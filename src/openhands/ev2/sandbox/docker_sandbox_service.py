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
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, NamedTuple, cast
from urllib.parse import urlparse

import docker  # type: ignore[import-untyped]  # docker SDK ships no type stubs
import httpx
from docker.errors import ImageNotFound, NotFound  # type: ignore[import-untyped]
from pydantic import Field

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox.sandbox_models import (
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SnapshotMode,
    VolumeMount,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotUnsupportedError,
)
from openhands.ev2.sandbox.sandbox_template_models import ExposedPort
from openhands.ev2.util import snapshot_store
from openhands.ev2.util.random_id import generate_random_id
from openhands.ev2.util.search_filter import ALL, SearchFilter

logger = logging.getLogger(__name__)

# Default working directory mounted into every Docker sandbox container. Both
# Docker and Kubernetes providers converge on this path so a snapshot taken
# from one provider restores cleanly into the other.
_DEFAULT_WORKING_DIR = "/home/openhands"


def _webhook_base_url(base_url: str, sandbox_config_id: str) -> str:
    """Webhook callback URL as reachable from inside a container.

    The public ``base_url`` host is not resolvable from inside a container, so
    only the scheme and port are kept and the host becomes
    ``host.docker.internal`` (mapped by ``extra_hosts``).
    """
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "http"
    port = f":{parsed.port}" if parsed.port is not None else ""
    return f"{scheme}://host.docker.internal{port}/webhooks/{sandbox_config_id}"


def _sandbox_environment(base_url: str | None, sandbox_config_id: str | None) -> dict[str, str]:
    """Container environment for a new sandbox.

    The agent server does not start with --host 0.0.0.0 by default unless a
    session api key is set, so one is minted per sandbox. When ``base_url`` is
    set, the webhook callback and CORS environment are injected so the agent
    server reports conversation/event updates to this app and accepts browser
    requests from it; the webhook URL carries the sandbox config id in its
    path.
    """
    environment = {"SESSION_API_KEY": generate_random_id()}
    if base_url is not None:
        environment["OH_ALLOW_CORS_ORIGINS_0"] = base_url
        if sandbox_config_id is not None:
            environment["OH_WEBHOOKS_0_BASE_URL"] = _webhook_base_url(base_url, sandbox_config_id)
    return environment


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

# Docker image labels. ``_TAG_SANDBOX_TEMPLATE_ID`` is the only label used;
# it is set at container creation (immutable — that's fine for read-only
# selection by the warm pool). Container labels are otherwise immutable after
# creation, so the sandbox id and config id are encoded in the container
# *name* (the OHE_ convention) rather than in labels.
_TAG_SANDBOX_TEMPLATE_ID = "io.openhands.sandbox.sandbox_template_id"
# Label recording the wall-clock time a sandbox was paused by the lifecycle
# sweep, so ``paused_delete_seconds`` can be enforced across restarts. Cleared
# whenever the sandbox is resumed.
_TAG_PAUSED_AT = "io.openhands.sandbox.paused_at"

# Container-name prefix marking a container as owned by the sandbox service.
# Names follow the convention:
#   Warm:    OHE_<sandbox_id>            (1 payload segment; no config yet)
#   Claimed: OHE_<sandbox_id>_<config_id> (2 payload segments)
# Both ids are UUIDs (dashes, no underscores), so splitting on ``_`` is
# unambiguous. Any container whose name does not start with OHE_ is foreign and
# is left entirely alone (not listed, claimed, swept, or deleted).
_OHE_PREFIX = "OHE_"


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
        self._pull_tasks: set[asyncio.Task[None]] = set()
        self._warm_claim_lock = asyncio.Lock()

    async def __aenter__(self) -> DockerSandboxService:
        await self.refresh_templates()
        self._start_lifecycle_loop()
        return self

    async def aclose(self) -> None:
        task = self._lifecycle_task
        self._lifecycle_task = None
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        for pull_task in list(self._pull_tasks):
            pull_task.cancel()
        for pull_task in list(self._pull_tasks):
            with contextlib.suppress(asyncio.CancelledError):
                await pull_task
        self._pull_tasks.clear()
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
    # Template refresh — kick off background image pulls so every template
    # image referenced by a durable :class:`SandboxTemplate` is available
    # locally before a sandbox is created from it. Pulling is best-effort:
    # failures are logged and never raised to the caller, since a missing
    # image at refresh time is surfaced (with a clear error) at create time.
    # ------------------------------------------------------------------ #
    async def refresh_templates(self, image_tags: Iterable[str] = ()) -> None:
        """Ensure every template image in *image_tags* is pulled locally.

        Spawns a background :class:`asyncio.Task` per image that is not already
        present locally; tasks self-remove from ``_pull_tasks`` on completion.
        Idempotent — an image already local and an in-flight pull for the same
        tag are skipped.
        """
        for tag in image_tags:
            tag = tag.strip()
            if not tag:
                continue
            if self._has_pending_pull(tag):
                continue
            task = asyncio.create_task(self._pull_image_task(tag), name=f"docker-pull:{tag}")
            self._pull_tasks.add(task)
            task.add_done_callback(self._pull_tasks.discard)

    def _has_pending_pull(self, tag: str) -> bool:
        """True iff a background pull is already in flight for *tag*."""
        return any(
            task.get_name() == f"docker-pull:{tag}" and not task.done() for task in self._pull_tasks
        )

    async def _pull_image_task(self, tag: str) -> None:
        """Pull *tag* in a worker thread when it is not already local.

        Skips the (potentially slow) registry pull when the image is present,
        so repeated refresh calls are cheap. Errors are logged, not raised.
        """
        try:
            await asyncio.to_thread(self._images.get, tag)
            return  # already present locally
        except ImageNotFound:
            pass
        except Exception:
            logger.debug("docker image lookup failed for %s; will attempt pull", tag, exc_info=True)
        try:
            await asyncio.to_thread(self._images.pull, tag)
            logger.info("docker pulled sandbox template image %s", tag)
        except Exception:
            logger.warning("docker pull failed for sandbox template image %s", tag, exc_info=True)

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
        # pre-persistence model carries only the template id and config id for
        # scope checks.
        return DockerSandbox(
            sandbox_template_id=payload.sandbox_template_id,
            sandbox_config_id=payload.sandbox_config_id,
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
    # Warm sandbox pool hooks (overridden from the ABC).
    # ------------------------------------------------------------------ #
    async def _claim_warm_sandbox(self, template_id: str, *, config_id: str) -> Sandbox | None:
        """Claim a warm container by renaming it (daemon-serialized CAS)."""
        async with self._warm_claim_lock:
            return await asyncio.to_thread(self._sync_claim_warm_sandbox, template_id, config_id)

    async def _count_warm(self, template_id: str) -> int:
        return cast(int, await asyncio.to_thread(self._sync_count_warm, template_id))

    async def _create_warm(self, template_id: str) -> None:
        await asyncio.to_thread(self._sync_create_warm, template_id)

    async def _delete_warm(self, template_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_warm, template_id)

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
            knobs = await self._safe_template(sandbox.sandbox_template_id)
            if knobs is None:
                continue
            action = await self._lifecycle_action(sandbox, knobs)
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

    async def _safe_template(self, template_id: str) -> _LifespanKnobs | None:
        try:
            image = await asyncio.to_thread(self._images.get, template_id)
        except ImageNotFound:
            return None
        return _lifespan_knobs_from_image(image.attrs)

    async def _lifecycle_action(self, sandbox: DockerSandbox, knobs: _LifespanKnobs) -> str | None:
        """Apply the highest-priority lifespan action to *sandbox*."""
        now = datetime.now(UTC)
        if knobs.max_age_seconds is not None and (now - sandbox.created_at) > timedelta(
            seconds=knobs.max_age_seconds
        ):
            await self._delete_sandbox(sandbox.id)
            return "deleted"
        if sandbox.status is SandboxStatus.ACTIVE and knobs.idle_pause_seconds is not None:
            idle_seconds = self._idle_seconds(sandbox)
            if idle_seconds is not None and idle_seconds > knobs.idle_pause_seconds:
                await self._update_sandbox(
                    sandbox.id, SandboxUpdate(desired_status=SandboxStatus.INACTIVE)
                )
                return "paused"
        if sandbox.status is SandboxStatus.INACTIVE and knobs.paused_delete_seconds is not None:
            paused_at = await asyncio.to_thread(self._sync_paused_at, sandbox.id)
            if paused_at is not None and (now - paused_at) > timedelta(
                seconds=knobs.paused_delete_seconds
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
    # Snapshot artifact hooks. A Docker snapshot is a gzip tarball of the
    # sandbox workspace bind-mount directory, stored in ``snapshot_dir`` as
    # ``<snapshot_id>.tar.gz``. The sandbox must be paused (or stopped) before
    # snapshotting so the workspace is quiescent. Importing a snapshot from an
    # uploaded file writes the raw bytes into the snapshot store. Download
    # streams the tarball. Restore happens at sandbox creation time (see
    # ``_sync_create_sandbox``). These operate on snapshot ids; the DB index
    # row is owned by ``SandboxSnapshotService``.
    # ------------------------------------------------------------------ #
    async def stream_snapshot(self, snapshot_id: str) -> Any:
        """Stream the snapshot tarball (gzip) for download."""
        return snapshot_store.stream_snapshot(self.snapshot_dir, snapshot_id)

    async def capture_snapshot(
        self,
        snapshot_id: uuid.UUID,
        sandbox_id: str,
        *,
        sandbox_perm_filter: SearchFilter[Any] = ALL,
    ) -> int | None:
        """Capture a workspace tarball from a live sandbox.

        *snapshot_id* is the DB row id and doubles as the tarball filename
        stem (``<snapshot_dir>/<snapshot_id>.tar.gz``). Returns the tarball
        size in bytes. Raises :class:`SandboxNotFoundError` when the sandbox's
        workspace does not exist.
        """
        artifact_id = str(snapshot_id)
        await asyncio.to_thread(self._sync_tar_snapshot, artifact_id, sandbox_id)
        return snapshot_store.snapshot_size(self.snapshot_dir, artifact_id)

    async def import_snapshot_file(
        self,
        snapshot_id: uuid.UUID,
        file_data: bytes | None,
        *,
        schema_type: str | None = None,
    ) -> int | None:
        """Store an uploaded tarball and return its size in bytes."""
        assert file_data is not None
        artifact_id = str(snapshot_id)
        await asyncio.to_thread(self._sync_import_snapshot, artifact_id, file_data)
        return snapshot_store.snapshot_size(self.snapshot_dir, artifact_id)

    async def delete_snapshot_artifact(self, snapshot_id: str) -> None:
        """Delete the stored tarball for a snapshot."""
        await asyncio.to_thread(self._sync_delete_snapshot, snapshot_id)

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
        container_name = _ohe_name(sandbox_id, sandbox.sandbox_config_id)
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
        containers.run(
            image=sandbox.sandbox_template_id,
            name=container_name,
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
            environment=_sandbox_environment(self.base_url, sandbox.sandbox_config_id),
        )
        return container_name

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

    def _deactivate_container(self, container: Any, state: str) -> None:
        """Deactivate per ``deactivate_mode``: pause (freeze) or stop (teardown)."""
        if state != "running":
            return
        if self.deactivate_mode == "stop":
            container.stop()
        else:
            container.pause()
        # NOTE: Docker container labels are immutable after creation, so we
        # cannot stamp a ``paused_at`` label here. The ``_sync_paused_at``
        # reader therefore returns ``None`` for Docker, which means
        # ``paused_delete_seconds`` is not enforced until a mutable-label
        # backend (K8s annotations) or a Docker API enhancement is available.

    def _sync_delete_sandbox(self, sandbox_id: str) -> None:
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(sandbox_id) from None
        # force=True removes a running/paused/exited container without a stop.
        container.remove(force=True)
        # Best-effort cleanup of the per-sandbox workspace bind-mount directory.
        # The workspace dir is keyed by the bare sandbox id (UUID), not the
        # full container name (which includes the OHE_ prefix + config id).
        if self.workspace_dir is not None:
            sid = _strip_ohe_prefix(sandbox_id)
            with contextlib.suppress(OSError):
                Path(self.workspace_dir, sid).rmdir()

    # ------------------------------------------------------------------ #
    # Synchronous warm-pool operations (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_create_warm(self, template_id: str) -> None:
        """Create a paused warm container named ``OHE_<sandbox_id>``."""
        sandbox_id = _generate_sandbox_id()
        container_name = _ohe_name(sandbox_id)
        ports: dict[str, Any] = {}
        for port in self.exposed_ports:
            ports[f"{port.container_port}/tcp"] = None
        binds: list[str] = []
        working_dir = _DEFAULT_WORKING_DIR
        if self.workspace_dir is not None:
            host_workspace = Path(self.workspace_dir) / sandbox_id
            host_workspace.mkdir(parents=True, exist_ok=True)
            binds.append(f"{host_workspace}:{working_dir}")
        container = self._containers.run(
            image=template_id,
            name=container_name,
            detach=True,
            ports=ports or None,
            labels={_TAG_SANDBOX_TEMPLATE_ID: template_id},
            init=True,
            volumes=binds or None,
            working_dir=working_dir,
            extra_hosts=self.extra_hosts
            if self.extra_hosts and not self.use_host_network
            else None,
            devices=["/dev/kvm:/dev/kvm:rwm"] if self.kvm_enabled else None,
            # Warm containers are unclaimed: no webhook callback yet (the config
            # id is assigned at claim time), CORS only.
            environment=_sandbox_environment(self.base_url, None),
        )
        container.pause()

    def _sync_claim_warm_sandbox(self, template_id: str, config_id: str) -> DockerSandbox | None:
        """Claim the oldest warm container by renaming it (daemon CAS)."""
        candidates = self._warm_containers(template_id)
        for container in candidates:
            name = _container_name(container)
            parsed = _parse_ohe_name(name)
            if parsed is None or parsed[1] is not None:
                continue  # foreign or already claimed
            sandbox_id = parsed[0]
            new_name = _ohe_name(sandbox_id, config_id)
            try:
                container.rename(new_name)
            except Exception:
                # Lost the race (NotFound/Conflict) — try the next candidate.
                continue
            container.unpause()
            return _sandbox_from_container_attrs(
                container, self.exposed_ports, self.image_name_patterns, self.snapshot_mode
            )
        return None

    def _sync_count_warm(self, template_id: str) -> int:
        """Count warm (unclaimed) containers for *template_id*."""
        count = 0
        for container in self._warm_containers(template_id):
            name = _container_name(container)
            parsed = _parse_ohe_name(name)
            if parsed is not None and parsed[1] is None:
                count += 1
        return count

    def _sync_delete_warm(self, template_id: str) -> None:
        """Remove one warm (unclaimed) container for *template_id*."""
        for container in self._warm_containers(template_id):
            name = _container_name(container)
            parsed = _parse_ohe_name(name)
            if parsed is None or parsed[1] is not None:
                continue
            sandbox_id = parsed[0]
            container.remove(force=True)
            if self.workspace_dir is not None:
                with contextlib.suppress(OSError):
                    Path(self.workspace_dir, sandbox_id).rmdir()
            return

    def _warm_containers(self, template_id: str) -> list[Any]:
        """List paused containers matching *template_id* (warm candidates)."""
        containers = self._containers.list(
            all=True,
            filters={"label": f"{_TAG_SANDBOX_TEMPLATE_ID}={template_id}"},
        )
        # Sort by created time so the oldest is claimed first.
        containers.sort(key=lambda c: _parse_created(_container_attr(c, "Created", "")))
        return list(containers)

    # ------------------------------------------------------------------ #
    # Synchronous snapshot store calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_tar_snapshot(self, snapshot_id: str, sandbox_id: str) -> None:
        if snapshot_store.snapshot_exists(self.snapshot_dir, snapshot_id):
            raise SandboxSnapshotConflictError(snapshot_id)
        workspace = self._workspace_path_for_sandbox(sandbox_id)
        if workspace is None:
            raise SandboxNotFoundError(sandbox_id)
        snapshot_store.create_snapshot(self.snapshot_dir, snapshot_id, workspace)

    def _sync_import_snapshot(self, snapshot_id: str, file_data: bytes) -> None:
        try:
            snapshot_store.import_snapshot(self.snapshot_dir, snapshot_id, file_data)
        except FileExistsError as exc:
            raise SandboxSnapshotConflictError(snapshot_id) from exc

    def _sync_delete_snapshot(self, snapshot_id: str) -> None:
        if not snapshot_store.snapshot_exists(self.snapshot_dir, snapshot_id):
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        snapshot_store.delete_snapshot(self.snapshot_dir, snapshot_id)

    def _workspace_path_for_sandbox(self, sandbox_id: str) -> Path | None:
        """Return the host workspace dir for *sandbox_id*, or ``None``.

        When ``workspace_dir`` is unset the sandbox has no persistent workspace
        to snapshot, so snapshotting is unsupported for that sandbox. The
        workspace is keyed by the bare sandbox UUID (stripped of the ``OHE_``
        prefix and config id suffix encoded in the container name).
        """
        if self.workspace_dir is None:
            return None
        sid = _strip_ohe_prefix(sandbox_id)
        workspace = Path(self.workspace_dir) / sid
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


class _LifespanKnobs(NamedTuple):
    """Lifespan knobs read from a template image's labels (provider inventory).

    The DB ``SandboxTemplate`` is the source of truth for template metadata,
    but the provider-level lifecycle sweep still reads these knobs from the
    Docker image labels of the image a sandbox was started from.
    """

    idle_pause_seconds: int | None
    paused_delete_seconds: int | None
    max_age_seconds: int | None


def _lifespan_knobs_from_image(attrs: dict[str, Any]) -> _LifespanKnobs:
    """Extract lifespan knobs from a Docker image's label metadata."""
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    return _LifespanKnobs(
        idle_pause_seconds=_label_int(labels, _TAG_IDLE_PAUSE_SECONDS),
        paused_delete_seconds=_label_int(labels, _TAG_PAUSED_DELETE_SECONDS),
        max_age_seconds=_label_int(labels, _TAG_MAX_AGE_SECONDS),
    )


def _sandbox_from_container_attrs(
    container: Any,
    exposed_ports: list[ExposedPort],
    image_name_patterns: list[str] | None = None,
    snapshot_mode: SnapshotMode = SnapshotMode.MANUAL,
) -> DockerSandbox | None:
    """Build a :class:`DockerSandbox` from a Docker container, or ``None``.

    Returns ``None`` when the container is not a claimed sandbox — i.e. its
    name does not start with ``OHE_`` (foreign, left alone) or has only one
    payload segment (warm, excluded from the public surface). Only claimed
    names (``OHE_<sid>_<cid>``) are surfaced.
    """
    try:
        attrs = container.attrs
    except Exception:  # container may have been removed
        return None
    name = attrs.get("Name", "").lstrip("/")
    parsed = _parse_ohe_name(name)
    if parsed is None:
        return None  # foreign container — not ours
    sandbox_id, config_id = parsed
    if config_id is None:
        return None  # warm container — excluded from the public surface
    # The container name IS the sandbox id (used in _containers.get(name)).
    sandbox_id = name
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    template_id = labels.get(_TAG_SANDBOX_TEMPLATE_ID) or config.get("Image") or ""
    state = attrs.get("State") or {}
    status_str = str(state.get("Status") or "unknown")
    host_config = attrs.get("HostConfig") or {}
    network_settings = attrs.get("NetworkSettings") or {}
    ports_binding = network_settings.get("Ports") or {}
    session_api_key = (
        _session_api_key_from_env(config.get("Env") or []) if status_str == "running" else None
    )
    return DockerSandbox(
        id=sandbox_id,
        sandbox_template_id=template_id,
        sandbox_config_id=config_id,
        status=_docker_status_to_sandbox_status(status_str),
        desired_status=_desired_from_labels(labels, status_str),
        snapshot_mode=snapshot_mode,
        session_api_key=session_api_key,
        exposed_urls=_exposed_urls_from_ports(exposed_ports, ports_binding),
        created_at=_parse_created(attrs.get("Created")),
        status_detail=state.get("Error") or None,
        volume_mounts=_volume_mounts_from_binds(host_config.get("Binds") or []),
    )


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


def _label_int(labels: dict[str, Any], name: str) -> int | None:
    """Parse an integer label, returning ``None`` when absent or invalid."""
    raw = labels.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _session_api_key_from_env(env: list[str]) -> str | None:
    """Extract ``SESSION_API_KEY`` from a Docker container ``Config.Env`` list."""
    for entry in env:
        if entry.startswith("SESSION_API_KEY="):
            value = entry[len("SESSION_API_KEY=") :]
            return value or None
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


def _generate_sandbox_id() -> str:
    """Generate a unique sandbox id (22-char lowercase alphanumeric).

    The id is encoded in the container name (``OHE_<sid>`` or
    ``OHE_<sid>_<cid>``) and used as the workspace bind-mount directory key.
    The id is ``[a-z0-9]`` only, so it contains neither the ``_`` separator used
    by the ``OHE_`` name grammar nor the ``-`` used by derived K8s names, and
    the Docker name splits unambiguously on ``_``.
    """
    return generate_random_id()


def _ohe_name(sandbox_id: str, config_id: str | None = None) -> str:
    """Build the Docker container name for a sandbox.

    Without *config_id*: ``OHE_<sandbox_id>`` (warm).
    With *config_id*: ``OHE_<sandbox_id>_<config_id>`` (claimed).
    """
    if config_id is None:
        return f"{_OHE_PREFIX}{sandbox_id}"
    return f"{_OHE_PREFIX}{sandbox_id}_{config_id}"


def _parse_ohe_name(name: str) -> tuple[str, str | None] | None:
    """Parse an ``OHE_``-prefixed container name.

    Returns ``(sandbox_id, None)`` for warm, ``(sandbox_id, config_id)`` for
    claimed, or ``None`` when *name* is foreign (no ``OHE_`` prefix).
    """
    if not name.startswith(_OHE_PREFIX):
        return None
    payload = name[len(_OHE_PREFIX) :]
    parts = payload.split("_", 1)
    if len(parts) == 1:
        return parts[0], None  # warm
    return parts[0], parts[1]  # claimed


def _strip_ohe_prefix(name: str) -> str:
    """Return the bare sandbox id from a container name or OHE_-prefixed id."""
    parsed = _parse_ohe_name(name)
    if parsed is None:
        return name  # not an OHE_ name — return as-is
    return parsed[0]


def _container_name(container: Any) -> str:
    """Return the Docker container name (without leading ``/``)."""
    try:
        attrs = container.attrs
    except Exception:
        return ""
    return str(attrs.get("Name", "").lstrip("/"))


def _container_attr(container: Any, path: str, default: Any = None) -> Any:
    """Read a dotted attr path from a Docker container's attrs, best-effort."""
    try:
        attrs = container.attrs
    except Exception:
        return default
    obj: Any = attrs
    for part in path.split("."):
        if not isinstance(obj, dict):
            return default
        obj = obj.get(part, default)
    return obj
