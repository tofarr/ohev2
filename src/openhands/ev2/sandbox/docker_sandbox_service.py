"""Docker implementation of the sandbox control plane.

This module is intentionally isolated from :mod:`sandbox_service` so the
Docker SDK is only imported when a Docker-backed service is actually selected
(other implementations will live in their own modules). ``DockerSandboxService``
backs template CRUD with the Docker *Image* API and sandbox CRUD with the
*Container* API:

* a template's ``id`` is the Docker image name, and the lifecycle metadata
  (``idle_pause_seconds``, ``paused_delete_seconds``, ``max_age_seconds``) are
  read from image labels;
* a sandbox's ``id`` is the Docker container name, and any container whose
  image matches a known template is a valid sandbox. ``desired_status`` maps
  to ``active`` (unpause/start) and ``inactive`` (pause).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, cast

import docker  # type: ignore[import-untyped]  # docker SDK ships no type stubs
import httpx
from docker.errors import ImageNotFound, NotFound  # type: ignore[import-untyped]
from pydantic import Field

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox, DockerSandboxSnapshot
from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxTemplate,
    ExposedPort,
    ExposedUrl,
    Sandbox,
    SandboxSnapshot,
    SandboxStatus,
    SandboxTemplate,
    SnapshotMode,
    VolumeMount,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxCreate,
    SandboxSnapshotCreate,
    SandboxTemplateCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotUnsupportedError,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
)
from openhands.ev2.util import snapshot_store

logger = logging.getLogger(__name__)

# Default working directory mounted into every Docker sandbox container. Both
# Docker and Kubernetes providers converge on this path so a snapshot taken
# from one provider restores cleanly into the other.
_DEFAULT_WORKING_DIR = "/home/openhands"

# Docker image labels carrying the lifespan metadata.
_TAG_IDLE_PAUSE_SECONDS = "io.openhands.sandbox.idle_pause_seconds"
_TAG_PAUSED_DELETE_SECONDS = "io.openhands.sandbox.paused_delete_seconds"
_TAG_MAX_AGE_SECONDS = "io.openhands.sandbox.max_age_seconds"

# Names of the default exposed ports surfaced on every Docker sandbox.
AGENT_SERVER = "agent_server"
VSCODE = "vscode"

# Default exposed ports declared on every Docker template / sandbox. Each
# container port is matched to a free host port at runtime.
DEFAULT_EXPOSED_PORTS: tuple[ExposedPort, ...] = (
    ExposedPort(
        name=AGENT_SERVER,
        description="The port on which the agent server runs within the container",
        container_port=8000,
    ),
    ExposedPort(
        name=VSCODE,
        description="The port on which the VSCode server runs within the container",
        container_port=8001,
    ),
)

# Docker image label recording the sandbox id a container belongs to. Set on
# container creation so a container can be matched back to its sandbox even
# after a restart.
_TAG_SANDBOX_ID = "io.openhands.sandbox.sandbox_id"
# Label recording the template id (image name) the container was built from.
_TAG_SANDBOX_TEMPLATE_ID = "io.openhands.sandbox.sandbox_template_id"
# Label recording the wall-clock time a sandbox was paused by the lifecycle
# sweep, so ``paused_delete_seconds`` can be enforced across restarts. Cleared
# whenever the sandbox is resumed.
_TAG_PAUSED_AT = "io.openhands.sandbox.paused_at"


class DockerSandboxService(SandboxService):
    """Docker-backed sandbox control plane.

    Template state is the Docker image inventory: ``id`` is the image name and
    the lifespan metadata are image labels. ``max_memory`` is read from the
    image's host config.

    Sandbox state is the Docker container inventory: a container whose image
    matches one of ``image_name_patterns`` is a valid sandbox. ``desired_status``
    maps to ``active`` (unpause/start) and ``inactive`` (pause or stop, per
    ``deactivate_mode``).

    When ``workspace_dir`` is set, each sandbox is created with a bind mount
    of ``<workspace_dir>/<sandbox_id>`` onto the container working directory,
    giving the sandbox a persistent workspace analogous to a Kubernetes PVC.
    When ``workspace_dir`` is ``None`` the sandbox has no persistent workspace
    (its container writable layer is ephemeral) — the "no PVC" case.

    Snapshots are gzip tarballs of the workspace directory, stored in
    ``snapshot_dir`` and restored into a new sandbox's workspace before the
    container starts. This mirrors the Kubernetes VolumeSnapshot model and
    lets snapshots round-trip between providers.

    ``image_name_patterns`` restricts which images are treated as templates;
    only images whose repository/tag matches one of the glob patterns (``*``
    wildcard) are surfaced. This defaults to the Agent Canvas image prefix.
    """

    image_name_patterns: list[str] = Field(
        default_factory=lambda: ["ghcr.io/openhands/agent-server:*"],
        description="Glob patterns matching image names to treat as sandbox templates.",
    )
    exposed_ports: list[ExposedPort] = Field(
        default_factory=lambda: list(DEFAULT_EXPOSED_PORTS),
        description="Exposed ports declared on every Docker sandbox by default.",
    )
    extra_hosts: dict[str, str] = Field(
        default_factory=lambda: {"host.docker.internal": "host-gateway"},
        description=(
            "Extra hostname mappings to add to agent-server containers. "
            "This allows containers to resolve hostnames like host.docker.internal "
            "for LAN deployments and MCP connections. "
            'Format: {"hostname": "ip_or_gateway"}'
        ),
    )
    use_host_network: bool = Field(
        default=False,
        description=(
            "Whether to use host networking mode for agent-server containers. "
            "When enabled, containers share the host network namespace, "
            "making all container ports directly accessible on the host. "
            "This is useful for reverse proxy setups where dynamic port mapping "
            "is problematic."
        ),
    )
    kvm_enabled: bool = Field(
        default=False,
        description=(
            "Whether to pass through /dev/kvm to sandbox containers for hardware "
            "virtualization support. When enabled, sandboxes can run KVM-accelerated "
            "virtual machines instead of using slower emulation. Requires the host "
            "to have KVM available (/dev/kvm must exist and be accessible). "
        ),
    )
    workspace_dir: str | None = Field(
        default=None,
        description=(
            "Host directory under which per-sandbox workspace bind mounts are "
            "created (``<workspace_dir>/<sandbox_id>``). When null the sandbox "
            "has no persistent workspace — its container writable layer is "
            "ephemeral (the 'no PVC' case). When set, the directory is created "
            "with parents if missing on sandbox creation."
        ),
    )
    snapshot_dir: str = Field(
        default_factory=lambda: str(Path.home() / ".openhands" / "enterprise" / "snapshots"),
        description=(
            "Host directory storing snapshot tarballs "
            "(``<snapshot_dir>/<snapshot_id>.tar.gz``). Created with parents if "
            "missing. Must be accessible to both this process (for gzip/gunzip) "
            "and, when streaming, for reading."
        ),
    )
    deactivate_mode: Literal["pause", "stop"] = Field(
        default="pause",
        description=(
            "How a sandbox is deactivated. ``pause`` uses the Docker cgroup "
            "freezer (``docker pause``) — memory and filesystem are frozen in "
            "place. ``stop`` uses ``docker stop`` then ``docker start`` on "
            "resume — processes are torn down (memory lost) but the writable "
            "layer / bind mount persists, giving a fresh restart analogous to "
            "scaling a Kubernetes Deployment to zero."
        ),
    )
    snapshot_mode: SnapshotMode = Field(
        default=SnapshotMode.MANUAL,
        description=(
            "Snapshot strategy advertised by every Docker sandbox/template. "
            "Docker supports manual workspace snapshots (gzip tarball of the "
            "workspace directory) by default; set to ``unsupported`` to disable."
        ),
    )
    sandbox_lifecycle_interval: float = Field(
        default=60.0,
        ge=0,
        description=(
            "Seconds between background sweeps that enforce the template "
            "lifespan knobs (``idle_pause_seconds``, ``paused_delete_seconds``, "
            "``max_age_seconds``) on every sandbox. When 0 the in-process loop "
            "is disabled and the sweep must be driven by an external scheduler "
            "calling ``DockerSandboxService.sweep_lifecycle``; see README "
            "'Sandbox lifecycle'."
        ),
    )
    agent_server_probe_timeout: float = Field(
        default=2.0,
        ge=0,
        description=(
            "Per-sandbox HTTP timeout (seconds) for probing the agent server "
            "root endpoint to derive ``last_accessed_at`` from its reported "
            "``idle_time``."
        ),
    )

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._client: Any = None
        self._http: httpx.AsyncClient | None = None
        self._lifecycle_task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> DockerSandboxService:
        self._start_lifecycle_loop()
        return self

    async def aclose(self) -> None:
        task = self._lifecycle_task
        self._lifecycle_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if self._http is not None:
            await self._http.aclose()
            self._http = None
        self._client = None

    @property
    def _images(self) -> Any:
        # Lazily connect so the server can boot without a running Docker
        # daemon; the first sandbox operation surfaces any connection error.
        if self._client is None:
            self._client = docker.from_env()
        return self._client.images

    @property
    def _containers(self) -> Any:
        if self._client is None:
            self._client = docker.from_env()
        return self._client.containers

    # ------------------------------------------------------------------ #
    # Provider hooks — templates.
    # ------------------------------------------------------------------ #
    async def _list_templates(self) -> list[SandboxTemplate]:
        return cast("list[SandboxTemplate]", await asyncio.to_thread(self._sync_list_templates))

    async def _get_template(self, template_id: str) -> SandboxTemplate:
        return await asyncio.to_thread(self._sync_get_template, template_id)

    def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
        return _docker_template_from_payload(payload, self.exposed_ports, self.snapshot_mode)

    async def _create_template(self, template: SandboxTemplate) -> DockerSandboxTemplate:
        docker_template = cast(DockerSandboxTemplate, template)
        await asyncio.to_thread(self._sync_create_template, docker_template.id)
        return docker_template

    async def _delete_template(self, template_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_template, template_id)

    # ------------------------------------------------------------------ #
    # Provider hooks — sandboxes.
    # ------------------------------------------------------------------ #
    async def _list_sandboxes(self) -> list[Sandbox]:
        sandboxes = cast("list[DockerSandbox]", await asyncio.to_thread(self._sync_list_sandboxes))
        await asyncio.gather(*(self._enrich_last_accessed_at(sb) for sb in sandboxes))
        return cast("list[Sandbox]", sandboxes)

    async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        sandbox = cast(DockerSandbox, await asyncio.to_thread(self._sync_get_sandbox, sandbox_id))
        await self._enrich_last_accessed_at(sandbox)
        return cast(Sandbox, sandbox)

    def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
        # ``id`` is assigned by the provider during ``_create_sandbox``; the
        # pre-persistence model carries only the template id for scope checks.
        return DockerSandbox(
            sandbox_template_id=payload.sandbox_template_id,
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
            snapshot_mode=self.snapshot_mode,
            session_api_key=None,
            exposed_urls=[],
            status_detail=None,
            volume_mounts=[],
        )

    async def _create_sandbox(self, sandbox: Sandbox, *, snapshot_id: str | None = None) -> Sandbox:
        docker_sandbox = cast(DockerSandbox, sandbox)
        if snapshot_id is not None and self.snapshot_mode is SnapshotMode.UNSUPPORTED:
            raise SandboxSnapshotUnsupportedError("snapshots are not supported")
        container_name = await asyncio.to_thread(
            self._sync_create_sandbox, docker_sandbox, snapshot_id
        )
        return await self._get_sandbox(container_name)

    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
        await asyncio.to_thread(self._sync_update_sandbox, sandbox_id, payload.desired_status)
        return await self._get_sandbox(sandbox_id)

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_sandbox, sandbox_id)

    # ------------------------------------------------------------------ #
    # last_accessed_at derivation + lifecycle sweep.
    # ------------------------------------------------------------------ #
    def _http_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self.agent_server_probe_timeout)
        return self._http

    def _agent_server_url(self, sandbox: DockerSandbox) -> str | None:
        """Return the agent server root URL for *sandbox*, or ``None``.

        Only an ``active`` sandbox exposes a reachable agent server; sandboxes
        in any other state have no URL to probe.
        """
        if sandbox.status is not SandboxStatus.ACTIVE or not sandbox.exposed_urls:
            return None
        for url in sandbox.exposed_urls:
            if url.name == AGENT_SERVER:
                return url.url.rstrip("/")
        return None

    async def _resolve_last_accessed_at(self, sandbox: DockerSandbox) -> datetime | None:
        """Probe the agent server root to derive ``last_accessed_at``.

        The agent server exposes ``{"idle_time": <seconds>}`` at ``/``; the
        last-accessed time is ``now - idle_time``. Returns ``None`` when the
        sandbox has no agent server URL, the probe fails, or the payload omits
        a usable ``idle_time``.
        """
        root = self._agent_server_url(sandbox)
        if root is None:
            return None
        try:
            response = await self._http_client().get(f"{root}/")
        except httpx.HTTPError:
            return None
        if response.status_code != 200:
            return None
        try:
            payload = response.json()
        except ValueError:
            return None
        idle = payload.get("idle_time") if isinstance(payload, dict) else None
        if not isinstance(idle, (int, float)) or idle < 0:
            return None
        return datetime.now(UTC) - timedelta(seconds=float(idle))

    async def _enrich_last_accessed_at(self, sandbox: DockerSandbox) -> None:
        """Fill ``last_accessed_at`` from the agent server probe, best-effort."""
        accessed = await self._resolve_last_accessed_at(sandbox)
        sandbox.last_accessed_at = accessed

    def _start_lifecycle_loop(self) -> None:
        """Start the background lifecycle sweep if configured (``interval > 0``)."""
        if self.sandbox_lifecycle_interval <= 0 or self._lifecycle_task is not None:
            return
        self._lifecycle_task = asyncio.create_task(self._lifecycle_loop(), name="sandbox-lifecycle")

    async def _lifecycle_loop(self) -> None:
        """Run :meth:`sweep_lifecycle` every interval until cancelled."""
        while True:
            await asyncio.sleep(self.sandbox_lifecycle_interval)
            try:
                summary = await self.sweep_lifecycle()
            except Exception:
                logger.exception("sandbox lifecycle sweep failed; will retry next interval")
            else:
                if summary:
                    logger.info("sandbox lifecycle: %s", summary)

    async def sweep_lifecycle(self) -> str | None:
        """Enforce template lifespan knobs across every sandbox.

        For each sandbox the template's ``idle_pause_seconds``,
        ``paused_delete_seconds`` and ``max_age_seconds`` are consulted (a
        ``None`` knob is not enforced). Actions, in priority order:

        * ``max_age_seconds`` — delete a sandbox whose ``created_at`` is older.
        * ``idle_pause_seconds`` — pause an ``active`` sandbox whose agent
          server reports idle time beyond the threshold.
        * ``paused_delete_seconds`` — delete an ``inactive`` sandbox paused
          longer than the threshold (the pause time is read from the
          ``io.openhands.sandbox.paused_at`` container label).

        Returns a one-line summary of actions taken, or ``None`` when idle.
        """
        sandboxes = cast("list[DockerSandbox]", await self._list_sandboxes())
        paused = 0
        deleted = 0
        for sandbox in sandboxes:
            template = await self._safe_template(sandbox.sandbox_template_id)
            if template is None:
                continue
            action = await self._lifecycle_action(sandbox, template)
            if action == "deleted":
                deleted += 1
            elif action == "paused":
                paused += 1
        parts: list[str] = []
        if paused:
            parts.append(f"paused {paused} idle sandbox(es)")
        if deleted:
            parts.append(f"deleted {deleted} sandbox(es)")
        return "; ".join(parts) if parts else None

    async def _safe_template(self, template_id: str) -> DockerSandboxTemplate | None:
        try:
            return cast(DockerSandboxTemplate, await self._get_template(template_id))
        except SandboxTemplateNotFoundError:
            return None

    async def _lifecycle_action(
        self, sandbox: DockerSandbox, template: SandboxTemplate
    ) -> str | None:
        """Apply the highest-priority lifespan action to *sandbox*."""
        now = datetime.now(UTC)
        if template.max_age_seconds is not None and (now - sandbox.created_at) > timedelta(
            seconds=template.max_age_seconds
        ):
            await self._delete_sandbox(sandbox.id)
            return "deleted"
        if sandbox.status is SandboxStatus.ACTIVE and template.idle_pause_seconds is not None:
            idle_seconds = self._idle_seconds(sandbox)
            if idle_seconds is not None and idle_seconds > template.idle_pause_seconds:
                await self._update_sandbox(
                    sandbox.id, SandboxUpdate(desired_status=SandboxStatus.INACTIVE)
                )
                return "paused"
        if sandbox.status is SandboxStatus.INACTIVE and template.paused_delete_seconds is not None:
            paused_at = await asyncio.to_thread(self._sync_paused_at, sandbox.id)
            if paused_at is not None and (now - paused_at) > timedelta(
                seconds=template.paused_delete_seconds
            ):
                await self._delete_sandbox(sandbox.id)
                return "deleted"
        return None

    @staticmethod
    def _idle_seconds(sandbox: DockerSandbox) -> float | None:
        if sandbox.last_accessed_at is None:
            return None
        return (datetime.now(UTC) - sandbox.last_accessed_at).total_seconds()

    def _sync_paused_at(self, sandbox_id: str) -> datetime | None:
        """Return the ``paused_at`` label timestamp for a sandbox, or ``None``."""
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            return None
        labels = (container.attrs.get("Config") or {}).get("Labels") or {}
        raw = labels.get(_TAG_PAUSED_AT)
        if not raw:
            return None
        return _parse_created(raw)

    # ------------------------------------------------------------------ #
    # Provider hooks - snapshots.
    # A Docker snapshot is a gzip tarball of the sandbox workspace bind-mount
    # directory, stored in ``snapshot_dir`` as ``<snapshot_id>.tar.gz``. The
    # sandbox must be paused (or stopped) before snapshotting so the workspace
    # is quiescent. Importing a snapshot from an uploaded file writes the raw
    # bytes into the snapshot store. Download streams the tarball. Restore
    # happens at sandbox creation time (see ``_sync_create_sandbox``).
    # ------------------------------------------------------------------ #
    async def _list_snapshots(self) -> list[SandboxSnapshot]:
        return cast("list[SandboxSnapshot]", await asyncio.to_thread(self._sync_list_snapshots))

    async def _get_snapshot(self, snapshot_id: str) -> SandboxSnapshot:
        return await asyncio.to_thread(self._sync_get_snapshot, snapshot_id)

    async def _snapshot_from_sandbox(
        self,
        payload: SandboxSnapshotCreate,
        sandbox: Sandbox,
    ) -> SandboxSnapshot:
        # Pre-persistence model; the id is assigned during _create_snapshot
        # when the provider generates the snapshot id.
        return DockerSandboxSnapshot(
            sandbox_id=sandbox.id,
            archive_path=str(snapshot_store.snapshot_path(self.snapshot_dir, "")),
        )

    async def _snapshot_from_file(
        self,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        # Pre-persistence model; the id is assigned during _create_snapshot
        # when the provider generates the snapshot id.
        return DockerSandboxSnapshot(
            sandbox_id=None,
            archive_path=str(snapshot_store.snapshot_path(self.snapshot_dir, "")),
        )

    async def _create_snapshot(
        self,
        snapshot: SandboxSnapshot,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        docker_snapshot = cast(DockerSandboxSnapshot, snapshot)
        snapshot_id = _generate_snapshot_id()
        docker_snapshot.id = snapshot_id
        docker_snapshot.archive_path = str(
            snapshot_store.snapshot_path(self.snapshot_dir, snapshot_id)
        )
        if payload.sandbox_id is not None:
            await asyncio.to_thread(self._sync_tar_snapshot, docker_snapshot, payload.sandbox_id)
        else:
            assert payload.file_data is not None
            await asyncio.to_thread(self._sync_import_snapshot, docker_snapshot, payload.file_data)
        return await self._get_snapshot(snapshot_id)

    async def _delete_snapshot(self, snapshot_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_snapshot, snapshot_id)

    async def stream_snapshot(self, snapshot_id: str) -> Any:
        """Stream the snapshot tarball (gzip) for download."""
        return snapshot_store.stream_snapshot(self.snapshot_dir, snapshot_id)

    # ------------------------------------------------------------------ #
    # Synchronous Docker Image API calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_list_templates(self) -> list[DockerSandboxTemplate]:
        templates: list[DockerSandboxTemplate] = []
        for image in self._images.list():
            template = self._template_from_image(image)
            if template is not None:
                templates.append(template)
        return templates

    def _template_from_image(self, image: Any) -> DockerSandboxTemplate | None:
        """Convert a Docker image to a template, or ``None`` if it is not one.

        Untagged intermediates are skipped.
        """
        try:
            template = _template_from_image_attrs(
                image.attrs, self.exposed_ports, self.snapshot_mode
            )
        except SandboxTemplateNotFoundError:
            return None
        return template if self._matches_image_name_patterns(template.id) else None

    def _sync_get_template(self, template_id: str) -> DockerSandboxTemplate:
        try:
            image = self._images.get(template_id)
        except ImageNotFound:
            raise SandboxTemplateNotFoundError(template_id) from None
        template = _template_from_image_attrs(image.attrs, self.exposed_ports, self.snapshot_mode)
        if not self._matches_image_name_patterns(template.id):
            raise SandboxTemplateNotFoundError(template_id)
        return template

    def _matches_image_name_patterns(self, image_name: str) -> bool:
        return any(_wildcard_match(pattern, image_name) for pattern in self.image_name_patterns)

    def _sync_create_template(self, template_id: str) -> None:
        images = self._images
        try:
            images.get(template_id)
        except ImageNotFound:
            images.pull(repository=template_id)
            return
        raise SandboxTemplateConflictError(template_id)

    def _sync_delete_template(self, template_id: str) -> None:
        try:
            self._images.remove(image=template_id)
        except ImageNotFound:
            raise SandboxTemplateNotFoundError(template_id) from None

    # ------------------------------------------------------------------ #
    # Synchronous Docker Container API calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_list_sandboxes(self) -> list[DockerSandbox]:
        sandboxes: list[DockerSandbox] = []
        for container in self._containers.list(all=True):
            sandbox = _sandbox_from_container_attrs(
                container,
                self.exposed_ports,
                self.image_name_patterns,
                self.snapshot_mode,
            )
            if sandbox is not None:
                sandboxes.append(sandbox)
        return sandboxes

    def _sync_get_sandbox(self, sandbox_id: str) -> DockerSandbox:
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(sandbox_id) from None
        sandbox = _sandbox_from_container_attrs(
            container,
            self.exposed_ports,
            self.image_name_patterns,
            self.snapshot_mode,
        )
        if sandbox is None:
            raise SandboxNotFoundError(sandbox_id)
        return sandbox

    def _sync_create_sandbox(self, sandbox: DockerSandbox, snapshot_id: str | None = None) -> str:
        # A sandbox is a container based on the image named by sandbox_template_id.
        # The sandbox id is generated up front so the workspace bind-mount source
        # directory can be created (and a snapshot restored into it) before the
        # container starts — the restore must happen against a quiescent host
        # directory, not a running container's filesystem.
        containers = self._containers
        sandbox_id = _generate_sandbox_id()
        ports: dict[str, Any] = {}
        for port in self.exposed_ports:
            ports[f"{port.container_port}/tcp"] = None
        binds: list[str] = []
        working_dir = _DEFAULT_WORKING_DIR
        if self.workspace_dir is not None:
            host_workspace = Path(self.workspace_dir) / sandbox_id
            host_workspace.mkdir(parents=True, exist_ok=True)
            if snapshot_id is not None:
                snapshot_store.restore_snapshot(self.snapshot_dir, snapshot_id, host_workspace)
            binds.append(f"{host_workspace}:{working_dir}")
        container = containers.run(
            image=sandbox.sandbox_template_id,
            name=sandbox_id,
            detach=True,
            ports=ports or None,
            labels={
                _TAG_SANDBOX_TEMPLATE_ID: sandbox.sandbox_template_id,
            },
            init=True,
            volumes=binds or None,
            working_dir=working_dir,
            extra_hosts=self.extra_hosts
            if self.extra_hosts and not self.use_host_network
            else None,
            devices=["/dev/kvm:/dev/kvm:rwm"] if self.kvm_enabled else None,
            environment={
                # This is a temporary measure. The agent server does not start with --host 0.0.0.0
                # by default unless a session api key is set.
                "SESSION_API_KEY": "changeme"
            },
        )
        # Stamp the sandbox-id label post-creation so the container can be
        # matched back to its sandbox after a restart.
        with contextlib.suppress(Exception):
            container.attrs["Config"]["Labels"][_TAG_SANDBOX_ID] = sandbox_id
        return sandbox_id

    def _sync_update_sandbox(self, sandbox_id: str, desired: SandboxStatus) -> None:
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(sandbox_id) from None
        state = _container_state(container)
        if desired is SandboxStatus.ACTIVE:
            self._activate_container(container, state)
        elif desired is SandboxStatus.INACTIVE:
            self._deactivate_container(container, state)

    def _activate_container(self, container: Any, state: str) -> None:
        if state == "paused":
            container.unpause()
        elif state in ("exited", "created"):
            container.start()
        # Clear the paused-at label so a subsequent idle pause re-stamps it.
        with contextlib.suppress(Exception):
            container.attrs["Config"]["Labels"].pop(_TAG_PAUSED_AT, None)

    def _deactivate_container(self, container: Any, state: str) -> None:
        """Deactivate per ``deactivate_mode``: pause (freeze) or stop (teardown)."""
        if state != "running":
            return
        if self.deactivate_mode == "stop":
            container.stop()
        else:
            container.pause()
        # Record when the sandbox was paused for paused_delete enforcement.
        with contextlib.suppress(Exception):
            container.attrs["Config"]["Labels"][_TAG_PAUSED_AT] = _iso_utc_now()

    def _sync_delete_sandbox(self, sandbox_id: str) -> None:
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(sandbox_id) from None
        # force=True removes a running/paused/exited container without a stop.
        container.remove(force=True)
        # Best-effort cleanup of the per-sandbox workspace bind-mount directory.
        if self.workspace_dir is not None:
            with contextlib.suppress(OSError):
                Path(self.workspace_dir, sandbox_id).rmdir()

    # ------------------------------------------------------------------ #
    # Synchronous snapshot store calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_list_snapshots(self) -> list[DockerSandboxSnapshot]:
        snapshots: list[DockerSandboxSnapshot] = []
        for snap_id in snapshot_store.list_snapshot_ids(self.snapshot_dir):
            snapshot = self._snapshot_from_store(snap_id)
            if snapshot is not None:
                snapshots.append(snapshot)
        return snapshots

    def _sync_get_snapshot(self, snapshot_id: str) -> DockerSandboxSnapshot:
        snapshot = self._snapshot_from_store(snapshot_id)
        if snapshot is None:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        return snapshot

    def _snapshot_from_store(self, snapshot_id: str) -> DockerSandboxSnapshot | None:
        """Build a snapshot model from a stored tarball, or ``None`` if absent."""
        if not snapshot_store.snapshot_exists(self.snapshot_dir, snapshot_id):
            return None
        created = snapshot_store.snapshot_created_at(self.snapshot_dir, snapshot_id)
        size = snapshot_store.snapshot_size(self.snapshot_dir, snapshot_id)
        return DockerSandboxSnapshot(
            id=snapshot_id,
            created_at=created or datetime.now(UTC),
            archive_path=str(snapshot_store.snapshot_path(self.snapshot_dir, snapshot_id)),
            size_bytes=size,
            sandbox_id=None,  # source-sandbox is not recoverable from the tarball alone
        )

    def _sync_tar_snapshot(self, snapshot: DockerSandboxSnapshot, sandbox_id: str) -> None:
        if snapshot_store.snapshot_exists(self.snapshot_dir, snapshot.id):
            raise SandboxSnapshotConflictError(snapshot.id)
        workspace = self._workspace_path_for_sandbox(sandbox_id)
        if workspace is None:
            raise SandboxNotFoundError(sandbox_id)
        snapshot_store.create_snapshot(self.snapshot_dir, snapshot.id, workspace)

    def _sync_import_snapshot(self, snapshot: DockerSandboxSnapshot, file_data: bytes) -> None:
        try:
            snapshot_store.import_snapshot(self.snapshot_dir, snapshot.id, file_data)
        except FileExistsError as exc:
            raise SandboxSnapshotConflictError(snapshot.id) from exc

    def _sync_delete_snapshot(self, snapshot_id: str) -> None:
        if not snapshot_store.snapshot_exists(self.snapshot_dir, snapshot_id):
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        snapshot_store.delete_snapshot(self.snapshot_dir, snapshot_id)

    def _workspace_path_for_sandbox(self, sandbox_id: str) -> Path | None:
        """Return the host workspace dir for *sandbox_id*, or ``None``.

        When ``workspace_dir`` is unset the sandbox has no persistent workspace
        to snapshot, so snapshotting is unsupported for that sandbox.
        """
        if self.workspace_dir is None:
            return None
        workspace = Path(self.workspace_dir) / sandbox_id
        if not workspace.is_dir():
            raise SandboxNotFoundError(sandbox_id) from None
        return workspace


def _container_state(container: Any) -> str:
    """Return the lower-cased Docker container status string."""
    with contextlib.suppress(Exception):
        container.reload()
    attrs = getattr(container, "attrs", {}) or {}
    state = attrs.get("State") or {}
    return str(state.get("Status") or "unknown")


def _template_from_image_attrs(
    attrs: dict[str, Any],
    exposed_ports: list[ExposedPort],
    snapshot_mode: SnapshotMode = SnapshotMode.MANUAL,
) -> DockerSandboxTemplate:
    """Build a :class:`DockerSandboxTemplate` from a Docker image's ``attrs``.

    Uses the first repository tag as the template id; an untagged image is not
    a usable template.
    """
    tags = [tag for tag in (attrs.get("RepoTags") or []) if tag != "<none>:<none>"]
    if not tags:
        raise SandboxTemplateNotFoundError("image is untagged")
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    host_config = attrs.get("HostConfig") or {}
    memory = host_config.get("Memory")
    return DockerSandboxTemplate(
        id=tags[0],
        command=config.get("Cmd"),
        created_at=_parse_created(attrs.get("Created")),
        initial_env=_parse_env(config.get("Env")),
        working_dir=config.get("WorkingDir") or _DEFAULT_WORKING_DIR,
        idle_pause_seconds=_label_int(labels, _TAG_IDLE_PAUSE_SECONDS),
        paused_delete_seconds=_label_int(labels, _TAG_PAUSED_DELETE_SECONDS),
        max_age_seconds=_label_int(labels, _TAG_MAX_AGE_SECONDS),
        max_memory=int(memory) if memory else None,
        exposed_ports=list(exposed_ports),
        snapshot_mode=snapshot_mode,
    )


def _docker_template_from_payload(
    payload: SandboxTemplateCreate,
    exposed_ports: list[ExposedPort],
    snapshot_mode: SnapshotMode = SnapshotMode.MANUAL,
) -> DockerSandboxTemplate:
    """Build a Docker template from a create payload (no persistence)."""
    ports = (
        [ExposedPort(**p) if isinstance(p, dict) else p for p in payload.exposed_ports]
        if payload.exposed_ports
        else list(exposed_ports)
    )
    return DockerSandboxTemplate(
        id=payload.id,
        command=payload.command,
        initial_env=payload.initial_env,
        working_dir=payload.working_dir,
        idle_pause_seconds=payload.idle_pause_seconds,
        paused_delete_seconds=payload.paused_delete_seconds,
        max_age_seconds=payload.max_age_seconds,
        max_memory=payload.max_memory,
        exposed_ports=ports,
        snapshot_mode=payload.snapshot_mode if payload.snapshot_mode is not None else snapshot_mode,
    )


def _sandbox_from_container_attrs(
    container: Any,
    exposed_ports: list[ExposedPort],
    image_name_patterns: list[str] | None = None,
    snapshot_mode: SnapshotMode = SnapshotMode.MANUAL,
) -> DockerSandbox | None:
    """Build a :class:`DockerSandbox` from a Docker container, or ``None``.

    Returns ``None`` when the container's image does not correspond to a
    sandbox template (no sandbox-id label and an image outside the configured
    patterns). A sandbox-id label short-circuits the image check so labeled
    containers are always recognized as sandboxes.
    """
    try:
        attrs = container.attrs
    except Exception:  # container may have been removed
        return None
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    image = config.get("Image") or ""
    sandbox_id = _resolve_sandbox_id(labels, attrs, image, image_name_patterns)
    if sandbox_id is None:
        return None
    template_id = labels.get(_TAG_SANDBOX_TEMPLATE_ID) or image
    state = attrs.get("State") or {}
    status_str = str(state.get("Status") or "unknown")
    host_config = attrs.get("HostConfig") or {}
    network_settings = attrs.get("NetworkSettings") or {}
    ports_binding = network_settings.get("Ports") or {}
    return DockerSandbox(
        id=sandbox_id,
        sandbox_template_id=template_id,
        status=_docker_status_to_sandbox_status(status_str),
        desired_status=_desired_from_labels(labels, status_str),
        snapshot_mode=snapshot_mode,
        session_api_key=None,
        exposed_urls=_exposed_urls_from_ports(exposed_ports, ports_binding),
        created_at=_parse_created(attrs.get("Created")),
        status_detail=state.get("Error") or None,
        volume_mounts=_volume_mounts_from_binds(host_config.get("Binds") or []),
    )


def _resolve_sandbox_id(
    labels: dict[str, Any],
    attrs: dict[str, Any],
    image: str,
    image_name_patterns: list[str] | None,
) -> str | None:
    """Return the sandbox id for a container, or ``None`` if it is not a sandbox.

    A labeled sandbox short-circuits the image check; otherwise the image must
    match one of *image_name_patterns*, in which case the container name is used.
    """
    sandbox_id = labels.get(_TAG_SANDBOX_ID)
    if sandbox_id:
        return str(sandbox_id)
    if not image or not image_name_patterns:
        return None
    if not any(_wildcard_match(pattern, image) for pattern in image_name_patterns):
        return None
    name = attrs.get("Name", "").lstrip("/")
    return name or None


def _docker_status_to_sandbox_status(status: str) -> SandboxStatus:
    """Map a Docker container status string to a :class:`SandboxStatus`."""
    if status == "running":
        return SandboxStatus.ACTIVE
    if status == "paused":
        return SandboxStatus.INACTIVE
    if status in ("exited", "dead"):
        return SandboxStatus.INACTIVE
    if status in ("created", "restarting"):
        return SandboxStatus.ACTIVATING
    return SandboxStatus.ERROR


def _desired_from_labels(labels: dict[str, Any], fallback_status: str) -> SandboxStatus:
    """Resolve the desired status, falling back to the observed status."""
    return _docker_status_to_sandbox_status(fallback_status)


def _exposed_urls_from_ports(
    exposed_ports: list[ExposedPort],
    ports_binding: dict[str, Any],
) -> list[ExposedUrl]:
    """Build :class:`ExposedUrl` entries from Docker's port bindings."""
    urls: list[ExposedUrl] = []
    for port in exposed_ports:
        binding = ports_binding.get(f"{port.container_port}/tcp")
        if not binding:
            continue
        host_port = binding[0].get("HostPort") if isinstance(binding, list) else None
        if not host_port:
            continue
        urls.append(
            ExposedUrl(
                name=port.name,
                url=f"http://localhost:{host_port}",
                port=int(host_port),
            )
        )
    return urls


def _volume_mounts_from_binds(binds: list[str]) -> list[VolumeMount]:
    """Parse Docker ``HostConfig.Binds`` entries into :class:`VolumeMount`."""
    mounts: list[VolumeMount] = []
    for entry in binds:
        parts = entry.split(":")
        if len(parts) < 2:
            continue
        host_path = parts[0]
        container_path = parts[1]
        mode = parts[2] if len(parts) > 2 else "rw"
        mounts.append(VolumeMount(host_path=host_path, container_path=container_path, mode=mode))
    return mounts


def _wildcard_match(pattern: str, target: str) -> bool:
    """Match *target* against *pattern*, where ``*`` is a glob wildcard.

    ``*`` matches any run of characters (including ``/``), so
    ``ghcr.io/openhands/*`` matches any image under that prefix. A pattern
    without wildcards must match exactly.
    """
    if "*" not in pattern:
        return pattern == target
    parts = pattern.split("*")
    escaped = ".*".join(re.escape(part) for part in parts)
    return re.fullmatch(escaped, target) is not None


def _parse_env(env: list[str] | None) -> dict[str, str]:
    """Parse a Docker ``Config.Env`` list into a name/value mapping."""
    if not env:
        return {}
    result: dict[str, str] = {}
    for entry in env:
        if "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        result[key] = value
    return result


def _label_int(labels: dict[str, Any], name: str) -> int | None:
    """Parse an integer label, returning ``None`` when absent or invalid."""
    raw = labels.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_created(created: object) -> datetime:
    """Parse a Docker ``Created`` timestamp into an aware UTC datetime."""
    if isinstance(created, str):
        try:
            parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    return datetime.now(UTC)


def _iso_utc_now() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(UTC).isoformat()


def _generate_snapshot_id() -> str:
    """Generate a unique snapshot id (used as the tarball filename stem)."""
    return uuid.uuid4().hex


def _generate_sandbox_id() -> str:
    """Generate a unique, human-friendly sandbox (container) name.

    Docker container names must match ``/?[a-zA-Z0-9][a-zA-Z0-9_.-]+``. We
    mint a short lowercase alphanumeric id prefixed with ``sandbox-`` so the
    per-sandbox workspace directory (``<workspace_dir>/<sandbox_id>``) has a
    predictable, collision-resistant name known before the container starts.
    """
    return f"sandbox-{secrets.token_hex(8)}"
