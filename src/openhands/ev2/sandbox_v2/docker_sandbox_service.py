"""Docker implementation of the sandbox_v2 control plane.

This module is intentionally isolated from :mod:`sandbox_v2_service` so the
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
import re
from datetime import UTC, datetime
from typing import Any, cast

import docker  # type: ignore[import-untyped]  # docker SDK ships no type stubs
from docker.errors import ImageNotFound, NotFound  # type: ignore[import-untyped]
from pydantic import Field

from openhands.ev2.sandbox_v2.docker_sandbox_models import DockerSandbox, DockerSandboxSnapshot
from openhands.ev2.sandbox_v2.sandbox_v2_models import (
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
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxCreate,
    SandboxSnapshotCreate,
    SandboxTemplateCreate,
    SandboxUpdate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_service import (
    SandboxConflictError,
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
)

# Docker image labels carrying the lifespan metadata.
_TAG_IDLE_PAUSE_SECONDS = "io.openhands.sandbox_v2.idle_pause_seconds"
_TAG_PAUSED_DELETE_SECONDS = "io.openhands.sandbox_v2.paused_delete_seconds"
_TAG_MAX_AGE_SECONDS = "io.openhands.sandbox_v2.max_age_seconds"

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
_TAG_SANDBOX_ID = "io.openhands.sandbox_v2.sandbox_id"
# Label recording the template id (image name) the container was built from.
_TAG_SANDBOX_SPEC_ID = "io.openhands.sandbox_v2.sandbox_spec_id"
# Label recording that an image is a sandbox snapshot (rather than a template).
_TAG_SNAPSHOT_ID = "io.openhands.sandbox_v2.snapshot_id"
# Label recording the source sandbox a snapshot image was committed from.
_TAG_SNAPSHOT_SANDBOX_ID = "io.openhands.sandbox_v2.snapshot_sandbox_id"
# Label recording the created-at timestamp for a snapshot image.
_TAG_SNAPSHOT_CREATED_AT = "io.openhands.sandbox_v2.snapshot_created_at"
# Docker image tag prefix for committed sandbox snapshot images.
_SNAPSHOT_IMAGE_PREFIX = "openhands-sandbox-snapshot"


class DockerSandboxService(SandboxService):
    """Docker-backed sandbox control plane.

    Template state is the Docker image inventory: ``id`` is the image name and
    the lifespan metadata are image labels. ``max_memory`` is read from the
    image's host config.

    Sandbox state is the Docker container inventory: a container whose image
    matches one of ``image_name_patterns`` is a valid sandbox. ``desired_status``
    maps to ``active`` (unpause/start) and ``inactive`` (pause).

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
    snapshot_mode: SnapshotMode = Field(
        default=SnapshotMode.MANUAL,
        description=(
            "Snapshot strategy advertised by every Docker sandbox/template. "
            "Docker supports manual snapshots (``docker commit``) by default; "
            "set to ``unsupported`` to disable, or ``automatic`` if a background "
            "commit loop is configured externally."
        ),
    )

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        self._client: Any = None

    async def __aenter__(self) -> DockerSandboxService:
        return self

    async def aclose(self) -> None:
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
        return cast("list[Sandbox]", await asyncio.to_thread(self._sync_list_sandboxes))

    async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        return await asyncio.to_thread(self._sync_get_sandbox, sandbox_id)

    def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
        return DockerSandbox(
            id=payload.id,
            sandbox_spec_id=payload.sandbox_spec_id,
            status=SandboxStatus.INACTIVE,
            desired_status=SandboxStatus.INACTIVE,
            snapshot_mode=self.snapshot_mode,
            session_api_key=None,
            exposed_urls=[],
            status_detail=None,
            volume_mounts=[],
        )

    async def _create_sandbox(self, sandbox: Sandbox) -> Sandbox:
        docker_sandbox = cast(DockerSandbox, sandbox)
        await asyncio.to_thread(self._sync_create_sandbox, docker_sandbox)
        return await self._get_sandbox(docker_sandbox.id)

    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
        await asyncio.to_thread(self._sync_update_sandbox, sandbox_id, payload.desired_status)
        return await self._get_sandbox(sandbox_id)

    async def _delete_sandbox(self, sandbox_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_sandbox, sandbox_id)

    # ------------------------------------------------------------------ #
    # Provider hooks - snapshots.
    # A Docker snapshot is an image produced by ``docker commit`` of a
    # sandbox container. Snapshot images are tagged
    # ``openhands-sandbox-snapshot:<snapshot_id>`` and carry labels that mark
    # them as snapshots (so they are excluded from the template inventory)
    # and record the source sandbox + created-at timestamp. Importing a
    # snapshot from an uploaded file uses ``docker load`` to ingest the
    # tarball, then re-tags the resulting image. Download is served by a
    # router endpoint that streams ``docker save`` of the snapshot image.
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
        # The committed image is not materialized until _create_snapshot; here
        # we only declare the image id and source sandbox the snapshot will use.
        image_id = _snapshot_image_tag(payload.id)
        return DockerSandboxSnapshot(
            id=payload.id,
            image_id=image_id,
            sandbox_id=sandbox.id,
        )

    async def _snapshot_from_file(
        self,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        # The image is not loaded until _create_snapshot; here we only declare
        # the image id the imported image will be tagged with.
        image_id = _snapshot_image_tag(payload.id)
        return DockerSandboxSnapshot(
            id=payload.id,
            image_id=image_id,
            sandbox_id=None,
        )

    async def _create_snapshot(
        self,
        snapshot: SandboxSnapshot,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        docker_snapshot = cast(DockerSandboxSnapshot, snapshot)
        if payload.sandbox_id is not None:
            await asyncio.to_thread(self._sync_commit_snapshot, docker_snapshot)
        else:
            assert payload.file_data is not None
            await asyncio.to_thread(self._sync_load_snapshot, docker_snapshot, payload.file_data)
        return await self._get_snapshot(docker_snapshot.id)

    async def _delete_snapshot(self, snapshot_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_snapshot, snapshot_id)

    async def stream_snapshot(self, snapshot_id: str) -> Any:
        """Stream a snapshot's image as a tar archive (``docker save``)."""
        image_tag = _snapshot_image_tag(snapshot_id)
        image = await asyncio.to_thread(self._images.get, image_tag)
        # The Docker SDK image.save() returns a generator of bytes suitable for
        # a StreamingResponse.
        return image.save(named=True)

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

        Snapshot images and untagged intermediates are skipped.
        """
        if _is_snapshot_image(image.attrs):
            return None
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
        if _is_snapshot_image(image.attrs):
            raise SandboxTemplateNotFoundError(template_id)
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

    def _sync_create_sandbox(self, sandbox: DockerSandbox) -> None:
        # A sandbox is a container based on the image named by sandbox_spec_id.
        containers = self._containers
        try:
            containers.get(sandbox.id)
        except NotFound:
            ports: dict[str, Any] = {}
            for port in self.exposed_ports:
                ports[f"{port.container_port}/tcp"] = None
            containers.run(
                image=sandbox.sandbox_spec_id,
                name=sandbox.id,
                detach=True,
                ports=ports or None,
                labels={
                    _TAG_SANDBOX_ID: sandbox.id,
                    _TAG_SANDBOX_SPEC_ID: sandbox.sandbox_spec_id,
                },
                init=True,
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
            return
        raise SandboxConflictError(sandbox.id)

    def _sync_update_sandbox(self, sandbox_id: str, desired: SandboxStatus) -> None:
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(sandbox_id) from None
        state = _container_state(container)
        if desired is SandboxStatus.ACTIVE:
            self._activate_container(container, state)
        elif desired is SandboxStatus.INACTIVE:
            self._pause_container(container, state)

    @staticmethod
    def _activate_container(container: Any, state: str) -> None:
        if state == "paused":
            container.unpause()
        elif state in ("exited", "created"):
            container.start()

    @staticmethod
    def _pause_container(container: Any, state: str) -> None:
        if state == "running":
            container.pause()

    def _sync_delete_sandbox(self, sandbox_id: str) -> None:
        try:
            container = self._containers.get(sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(sandbox_id) from None
        # force=True removes a running/paused container without a separate stop.
        container.remove(force=True)

    # ------------------------------------------------------------------ #
    # Synchronous Docker Image API calls - snapshots.
    # ------------------------------------------------------------------ #
    def _sync_list_snapshots(self) -> list[DockerSandboxSnapshot]:
        snapshots: list[DockerSandboxSnapshot] = []
        for image in self._images.list():
            attrs = image.attrs
            if not _is_snapshot_image(attrs):
                continue
            snapshot = _snapshot_from_image_attrs(attrs)
            if snapshot is not None:
                snapshots.append(snapshot)
        return snapshots

    def _sync_get_snapshot(self, snapshot_id: str) -> DockerSandboxSnapshot:
        image_name = _snapshot_image_tag(snapshot_id)
        try:
            image = self._images.get(image_name)
        except ImageNotFound:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None
        snapshot = _snapshot_from_image_attrs(image.attrs)
        if snapshot is None or snapshot.id != snapshot_id:
            raise SandboxSnapshotNotFoundError(snapshot_id)
        return snapshot

    def _sync_commit_snapshot(self, snapshot: DockerSandboxSnapshot) -> None:
        image_tag = _snapshot_image_tag(snapshot.id)
        try:
            self._images.get(image_tag)
        except ImageNotFound:
            pass
        else:
            raise SandboxSnapshotConflictError(snapshot.id)
        try:
            container = self._containers.get(snapshot.sandbox_id)
        except NotFound:
            raise SandboxNotFoundError(snapshot.sandbox_id or "") from None
        created_at = _iso_utc_now()
        container.commit(
            repository=_SNAPSHOT_IMAGE_PREFIX,
            tag=snapshot.id,
            labels={
                _TAG_SNAPSHOT_ID: snapshot.id,
                _TAG_SNAPSHOT_SANDBOX_ID: snapshot.sandbox_id or "",
                _TAG_SNAPSHOT_CREATED_AT: created_at,
            },
        )

    def _sync_load_snapshot(self, snapshot: DockerSandboxSnapshot, file_data: bytes) -> None:
        image_tag = _snapshot_image_tag(snapshot.id)
        try:
            self._images.get(image_tag)
        except ImageNotFound:
            pass
        else:
            raise SandboxSnapshotConflictError(snapshot.id)
        result = self._client.images.load(file_data)
        # ``load`` returns a list of loaded images; re-tag the first one so the
        # snapshot is addressable by its snapshot id.
        loaded = result[0] if isinstance(result, list) else result
        loaded.tag(_SNAPSHOT_IMAGE_PREFIX, tag=snapshot.id)
        # Record snapshot metadata via a label by re-committing the re-tagged image.
        created_at = _iso_utc_now()
        self._client.api.commit(
            image_tag,
            repository=_SNAPSHOT_IMAGE_PREFIX,
            tag=snapshot.id,
            conf={
                "Labels": {
                    _TAG_SNAPSHOT_ID: snapshot.id,
                    _TAG_SNAPSHOT_SANDBOX_ID: "",
                    _TAG_SNAPSHOT_CREATED_AT: created_at,
                }
            },
        )

    def _sync_delete_snapshot(self, snapshot_id: str) -> None:
        image_tag = _snapshot_image_tag(snapshot_id)
        try:
            self._images.remove(image=image_tag, force=True)
        except ImageNotFound:
            raise SandboxSnapshotNotFoundError(snapshot_id) from None


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
        working_dir=config.get("WorkingDir") or "/home/openhands/workspace",
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
    spec_id = labels.get(_TAG_SANDBOX_SPEC_ID) or image
    state = attrs.get("State") or {}
    status_str = str(state.get("Status") or "unknown")
    host_config = attrs.get("HostConfig") or {}
    network_settings = attrs.get("NetworkSettings") or {}
    ports_binding = network_settings.get("Ports") or {}
    return DockerSandbox(
        id=sandbox_id,
        sandbox_spec_id=spec_id,
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


def _snapshot_image_tag(snapshot_id: str) -> str:
    """Return the Docker image reference for a snapshot id."""
    return f"{_SNAPSHOT_IMAGE_PREFIX}:{snapshot_id}"


def _is_snapshot_image(attrs: dict[str, Any]) -> bool:
    """Return ``True`` when a Docker image's attrs carry the snapshot label."""
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    return bool(labels.get(_TAG_SNAPSHOT_ID))


def _snapshot_from_image_attrs(attrs: dict[str, Any]) -> DockerSandboxSnapshot | None:
    """Build a :class:`DockerSandboxSnapshot` from a Docker image's attrs.

    Returns ``None`` when the image is not labeled as a snapshot.
    """
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    snapshot_id = labels.get(_TAG_SNAPSHOT_ID)
    if not snapshot_id:
        return None
    sandbox_id = labels.get(_TAG_SNAPSHOT_SANDBOX_ID) or None
    tags = [tag for tag in (attrs.get("RepoTags") or []) if tag != "<none>:<none>"]
    image_id = tags[0] if tags else _snapshot_image_tag(str(snapshot_id))
    created_raw = labels.get(_TAG_SNAPSHOT_CREATED_AT)
    return DockerSandboxSnapshot(
        id=str(snapshot_id),
        created_at=_parse_created(created_raw)
        if created_raw
        else _parse_created(attrs.get("Created")),
        download_url=None,
        image_id=image_id,
        sandbox_id=sandbox_id if sandbox_id else None,
    )


__all__ = [
    "AGENT_SERVER",
    "DEFAULT_EXPOSED_PORTS",
    "VSCODE",
    "DockerSandboxService",
    "_docker_template_from_payload",
    "_exposed_urls_from_ports",
    "_is_snapshot_image",
    "_label_int",
    "_parse_created",
    "_parse_env",
    "_resolve_sandbox_id",
    "_sandbox_from_container_attrs",
    "_snapshot_from_image_attrs",
    "_snapshot_image_tag",
    "_template_from_image_attrs",
    "_volume_mounts_from_binds",
    "_wildcard_match",
]
