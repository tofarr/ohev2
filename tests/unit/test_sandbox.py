"""Tests for the Docker sandbox control plane.

Covers the pieces that do not require a live Docker daemon or database: the
sandbox model, the Docker container attribute mapping helpers, the snapshot
tarball store, the lifecycle sweep, the ``last_accessed_at`` derivation, the
service factory/config wiring, and the exception-to-status mapping. Templates,
configs, and snapshot index rows are DB-backed and covered by their own route
tests; this file exercises only the live-sandbox + snapshot-artifact surface
owned by :class:`DockerSandboxService`.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

import httpx
import pytest
import respx
from docker.errors import ImageNotFound, NotFound  # type: ignore[import-untyped]
from pydantic import ValidationError

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox.docker_sandbox_service import (
    DEFAULT_EXPOSED_PORTS,
    DockerSandboxService,
    _docker_status_to_sandbox_status,
    _exposed_urls_from_ports,
    _generate_sandbox_id,
    _generate_snapshot_id,
    _label_int,
    _lifespan_knobs_from_image,
    _parse_created,
    _resolve_sandbox_id,
    _sandbox_from_container_attrs,
    _volume_mounts_from_binds,
    _wildcard_match,
)
from openhands.ev2.sandbox.sandbox_models import (
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    VolumeMount,
)
from openhands.ev2.sandbox.sandbox_schemas import SandboxCreate, SandboxUpdate
from openhands.ev2.sandbox.sandbox_service import (
    SandboxNotFoundError,
    SandboxService,
    SandboxSnapshotConflictError,
    SandboxSnapshotNotFoundError,
    SandboxSnapshotUnsupportedError,
    resolve_sandbox_service_class,
)
from openhands.ev2.sandbox.sandbox_template_models import ExposedPort

# --------------------------------------------------------------------------- #
# Models.
# --------------------------------------------------------------------------- #


def test_sandbox_model_round_trip() -> None:
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img:latest",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        session_api_key="key",
        exposed_urls=[ExposedUrl(name="agent_server", url="http://localhost:8001", port=8001)],
        volume_mounts=[VolumeMount(host_path="/h", container_path="/c")],
    )
    restored = Sandbox.model_validate(sandbox.model_dump(mode="json"))
    assert isinstance(restored, DockerSandbox)
    assert restored.id == "sb-1"
    assert restored.sandbox_template_id == "img:latest"
    assert restored.status is SandboxStatus.ACTIVE
    assert restored.session_api_key == "key"
    assert restored.exposed_urls is not None
    assert restored.exposed_urls[0].name == "agent_server"
    assert restored.volume_mounts is not None
    assert restored.volume_mounts[0].host_path == "/h"


def test_sandbox_defaults() -> None:
    sandbox = DockerSandbox(
        sandbox_template_id="img",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    assert sandbox.id == ""
    assert sandbox.session_api_key is None
    assert sandbox.exposed_urls == []
    assert sandbox.volume_mounts == []
    assert sandbox.status_detail is None


def test_exposed_port_is_frozen() -> None:
    port = ExposedPort(name="x", description="d")
    with pytest.raises(ValidationError):
        port.container_port = 9


def test_default_exposed_ports_include_agent_server_and_vscode() -> None:
    names = {p.name for p in DEFAULT_EXPOSED_PORTS}
    assert "agent_server" in names
    assert "vscode" in names


def test_sandbox_create_and_update_payloads() -> None:
    create = SandboxCreate.model_validate({"sandbox_template_id": "img"})
    assert create.sandbox_template_id == "img"
    update = SandboxUpdate.model_validate({"desired_status": "active"})
    assert update.desired_status is SandboxStatus.ACTIVE


def test_sandbox_update_requires_desired_status() -> None:
    with pytest.raises(ValidationError):
        SandboxUpdate.model_validate({})


# --------------------------------------------------------------------------- #
# Docker attribute mapping helpers.
# --------------------------------------------------------------------------- #


_PORTS = list(DEFAULT_EXPOSED_PORTS)


def test_label_int_tolerates_garbage() -> None:
    labels: dict[str, object] = {"good": "7", "bad": "nope", "absent": None}
    assert _label_int(labels, "good") == 7
    assert _label_int(labels, "bad") is None
    assert _label_int(labels, "missing") is None


def test_parse_created_handles_z_and_naive() -> None:
    parsed = _parse_created("2024-01-02T03:04:05Z")
    assert parsed.tzinfo is not None
    assert parsed.year == 2024
    naive = _parse_created("2024-01-02T03:04:05")
    assert naive.tzinfo is not None
    assert naive.utcoffset() is not None


def test_parse_created_invalid_string_returns_now() -> None:
    now = datetime.now(UTC)
    parsed = _parse_created("not-a-date")
    assert parsed >= now - timedelta(seconds=5)


def test_parse_created_non_string_returns_now() -> None:
    parsed = _parse_created(12345)
    assert parsed.tzinfo is UTC


def test_parse_created_naive_datetime_gets_utc() -> None:
    parsed = _parse_created("2024-01-02T03:04:05")
    assert parsed.utcoffset() == timedelta(0)


def test_exposed_urls_from_ports() -> None:
    ports = list(DEFAULT_EXPOSED_PORTS)
    binding: dict[str, Any] = {"8000/tcp": [{"HostPort": "32771"}], "8001/tcp": None}
    urls = _exposed_urls_from_ports(ports, binding)
    assert [u.name for u in urls] == ["agent_server"]
    assert urls[0].port == 32771
    assert urls[0].url == "http://localhost:32771"


def test_exposed_urls_empty_when_no_binding() -> None:
    assert _exposed_urls_from_ports(list(DEFAULT_EXPOSED_PORTS), {}) == []


def test_exposed_urls_skips_binding_without_host_port() -> None:
    ports = list(DEFAULT_EXPOSED_PORTS)
    binding: dict[str, Any] = {"8000/tcp": [{}]}
    assert _exposed_urls_from_ports(ports, binding) == []


def test_volume_mounts_from_binds() -> None:
    binds = ["/host:/container", "/h2:/c2:ro", "bad"]
    mounts = _volume_mounts_from_binds(binds)
    assert len(mounts) == 2
    assert mounts[0].host_path == "/host"
    assert mounts[0].container_path == "/container"
    assert mounts[0].mode == "rw"
    assert mounts[1].mode == "ro"


def test_volume_mounts_empty() -> None:
    assert _volume_mounts_from_binds([]) == []


def test_wildcard_match() -> None:
    assert _wildcard_match("ghcr.io/openhands/agent-server", "ghcr.io/openhands/agent-server")
    assert _wildcard_match("ghcr.io/openhands/*", "ghcr.io/openhands/agent-server")
    assert not _wildcard_match("ghcr.io/openhands/agent-server", "ghcr.io/other/agent-canvas")
    # A bare pattern (no wildcard) requires an exact match, so a tagged
    # image is *not* matched by it — use ``:*`` to opt into tagged variants.
    assert not _wildcard_match(
        "ghcr.io/openhands/agent-server", "ghcr.io/openhands/agent-server:1.16.0"
    )
    assert _wildcard_match(
        "ghcr.io/openhands/agent-server:*", "ghcr.io/openhands/agent-server:1.16.0"
    )


def test_docker_status_to_sandbox_status_edge_cases() -> None:
    assert _docker_status_to_sandbox_status("running") is SandboxStatus.ACTIVE
    assert _docker_status_to_sandbox_status("paused") is SandboxStatus.INACTIVE
    assert _docker_status_to_sandbox_status("exited") is SandboxStatus.INACTIVE
    assert _docker_status_to_sandbox_status("created") is SandboxStatus.ACTIVATING
    assert _docker_status_to_sandbox_status("restarting") is SandboxStatus.ACTIVATING
    assert _docker_status_to_sandbox_status("weird") is SandboxStatus.ERROR


def test_generate_sandbox_id_is_unique() -> None:
    ids = {_generate_sandbox_id() for _ in range(100)}
    assert len(ids) == 100
    assert all(s.startswith("sandbox-") for s in ids)


def test_generate_snapshot_id_is_unique() -> None:
    ids = {_generate_snapshot_id() for _ in range(100)}
    assert len(ids) == 100


# --------------------------------------------------------------------------- #
# Container attribute mapping -> DockerSandbox.
# --------------------------------------------------------------------------- #


class _FakeContainer:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs

    def reload(self) -> None:
        pass


def _container_attrs(
    *,
    status: str = "running",
    sandbox_id: str | None = "sb-1",
    image: str = "ghcr.io/openhands/agent-server:latest",
    name: str = "sb-1",
    created: str = "2024-01-02T03:04:05Z",
    ports: dict[str, Any] | None = None,
    binds: list[str] | None = None,
    labels: dict[str, str] | None = None,
) -> dict[str, Any]:
    full_labels = {"io.openhands.sandbox.sandbox_id": sandbox_id} if sandbox_id else {}
    if labels:
        full_labels.update(labels)
    return {
        "Name": f"/{name}",
        "Created": created,
        "State": {"Status": status, "Error": None},
        "Config": {"Image": image, "Labels": full_labels},
        "HostConfig": {"Binds": binds or []},
        "NetworkSettings": {"Ports": ports or {}},
    }


def test_sandbox_from_container_attrs_running() -> None:
    container = _FakeContainer(
        _container_attrs(status="running", ports={"8000/tcp": [{"HostPort": "32771"}]})
    )
    sandbox = _sandbox_from_container_attrs(container, _PORTS)
    assert sandbox is not None
    assert sandbox.id == "sb-1"
    assert sandbox.status is SandboxStatus.ACTIVE
    assert sandbox.desired_status is SandboxStatus.ACTIVE
    assert sandbox.exposed_urls is not None
    assert [u.name for u in sandbox.exposed_urls] == ["agent_server"]


def test_sandbox_from_container_attrs_paused_is_inactive() -> None:
    container = _FakeContainer(_container_attrs(status="paused"))
    sandbox = _sandbox_from_container_attrs(container, _PORTS)
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.INACTIVE


def test_sandbox_from_container_attrs_exited_is_inactive() -> None:
    container = _FakeContainer(_container_attrs(status="exited"))
    sandbox = _sandbox_from_container_attrs(container, _PORTS)
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.INACTIVE


def test_sandbox_from_container_attrs_no_label_returns_none_via_pattern() -> None:
    # No sandbox-id label and an image that does not match the patterns -> None.
    container = _FakeContainer(
        _container_attrs(sandbox_id=None, image="ghcr.io/other/agent:latest", name="x")
    )
    sandbox = _sandbox_from_container_attrs(
        container, _PORTS, image_name_patterns=["ghcr.io/openhands/agent-server:*"]
    )
    assert sandbox is None


def test_sandbox_from_container_attrs_returns_none_on_exception() -> None:
    class _Broken:
        @property
        def attrs(self) -> dict[str, Any]:
            raise RuntimeError("container gone")

    assert _sandbox_from_container_attrs(_Broken(), _PORTS) is None


def test_resolve_sandbox_id_uses_name_when_image_matches_pattern() -> None:
    labels: dict[str, Any] = {}
    attrs = {"Name": "/named-sandbox"}
    sid = _resolve_sandbox_id(
        labels, attrs, "ghcr.io/openhands/agent-server:1.0", ["ghcr.io/openhands/*"]
    )
    assert sid == "named-sandbox"


def test_resolve_sandbox_id_returns_none_when_name_empty() -> None:
    labels: dict[str, Any] = {}
    attrs = {"Name": ""}
    sid = _resolve_sandbox_id(
        labels, attrs, "ghcr.io/openhands/agent-server:1.0", ["ghcr.io/openhands/*"]
    )
    assert sid is None


def test_lifespan_knobs_from_image() -> None:
    attrs = {
        "Config": {
            "Labels": {
                "io.openhands.sandbox.idle_pause_seconds": "120",
                "io.openhands.sandbox.paused_delete_seconds": "300",
                "io.openhands.sandbox.max_age_seconds": "3600",
            }
        }
    }
    knobs = _lifespan_knobs_from_image(attrs)
    assert knobs.idle_pause_seconds == 120
    assert knobs.paused_delete_seconds == 300
    assert knobs.max_age_seconds == 3600


def test_lifespan_knobs_from_image_missing() -> None:
    knobs = _lifespan_knobs_from_image({})
    assert knobs.idle_pause_seconds is None
    assert knobs.paused_delete_seconds is None
    assert knobs.max_age_seconds is None


# --------------------------------------------------------------------------- #
# Factory & config wiring.
# --------------------------------------------------------------------------- #


def test_resolve_docker_service_class() -> None:
    cls = resolve_sandbox_service_class(
        "openhands.ev2.sandbox.docker_sandbox_service.DockerSandboxService"
    )
    assert cls is DockerSandboxService


def test_resolve_rejects_non_service() -> None:
    with pytest.raises(TypeError):
        resolve_sandbox_service_class("openhands.ev2.sandbox.docker_sandbox_service._LifespanKnobs")


def test_resolve_rejects_missing_module() -> None:
    with pytest.raises(ValueError):
        resolve_sandbox_service_class("does.not.Exist")


def test_build_docker_service() -> None:
    from openhands.ev2.config import AppConfig

    config = AppConfig(
        idp={"url": "https://idp.example.com", "client_id": "c", "client_secret": "s"},  # type: ignore[arg-type]
        encryption_key={"id": "primary", "value": "test-secret-at-least-32-bytes-long!!"},  # type: ignore[arg-type]
    )
    service = config.get_sandbox_service()
    assert isinstance(service, DockerSandboxService)
    assert isinstance(service, SandboxService)


def test_config_default_sandbox_service(monkeypatch: pytest.MonkeyPatch) -> None:
    from openhands.ev2.config import get_config

    get_config.cache_clear()
    monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    config = get_config()
    assert "DockerSandboxService" in config.sandbox_service_class


def test_sandbox_service_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    from openhands.ev2.config import AppConfig

    monkeypatch.setenv("OHE_SANDBOX_IMAGE_NAME_PATTERNS_0", "ghcr.io/acme/agent-*")
    config = AppConfig(
        idp={"url": "https://idp.example.com", "client_id": "c", "client_secret": "s"},  # type: ignore[arg-type]
        encryption_key={"id": "primary", "value": "test-secret-at-least-32-bytes-long!!"},  # type: ignore[arg-type]
    )
    service = config.get_sandbox_service()
    assert isinstance(service, DockerSandboxService)
    assert service.image_name_patterns == ["ghcr.io/acme/agent-*"]


# --------------------------------------------------------------------------- #
# Router exception-to-status mapping.
# --------------------------------------------------------------------------- #


def test_sandbox_router_exception_to_status_mapping() -> None:
    from fastapi import status as http_status

    from openhands.ev2.sandbox.sandbox_router import _map_exception_to_status
    from openhands.ev2.sandbox.sandbox_service import (
        BatchPermissionDeniedError,
        SandboxConflictError,
        SandboxNotFoundError,
        SandboxPermissionScopeError,
    )

    assert _map_exception_to_status(SandboxNotFoundError("x")).status_code == 404
    assert _map_exception_to_status(SandboxConflictError("x")).status_code == 409
    assert _map_exception_to_status(SandboxPermissionScopeError("x")).status_code == 403
    assert _map_exception_to_status(BatchPermissionDeniedError("x")).status_code == 403
    assert (
        _map_exception_to_status(RuntimeError("boom")).status_code
        == http_status.HTTP_500_INTERNAL_SERVER_ERROR
    )


def test_snapshot_router_exception_to_status_mapping() -> None:
    from openhands.ev2.sandbox.sandbox_service import (
        SandboxSnapshotConflictError,
        SandboxSnapshotNotFoundError,
        SandboxSnapshotPermissionScopeError,
        SandboxSnapshotUnsupportedError,
    )
    from openhands.ev2.sandbox.sandbox_snapshot_router import _map_exception_to_status

    assert _map_exception_to_status(SandboxSnapshotNotFoundError("x")).status_code == 404
    assert _map_exception_to_status(SandboxSnapshotPermissionScopeError("x")).status_code == 403
    assert _map_exception_to_status(SandboxSnapshotConflictError("x")).status_code == 409
    assert _map_exception_to_status(SandboxSnapshotUnsupportedError("x")).status_code == 501


# --------------------------------------------------------------------------- #
# Snapshot tarball store (sync helpers + artifact hooks).
# --------------------------------------------------------------------------- #


def _service_with_workspace(tmp_path: Path) -> DockerSandboxService:
    service = DockerSandboxService(
        workspace_dir=str(tmp_path / "ws"), snapshot_dir=str(tmp_path / "snaps")
    )
    return service


def test_sync_tar_snapshot_creates_tarball(tmp_path: Path) -> None:
    service = _service_with_workspace(tmp_path)
    assert service.workspace_dir is not None
    sandbox_id = "sb-1"
    (Path(service.workspace_dir) / sandbox_id).mkdir(parents=True)
    (Path(service.workspace_dir) / sandbox_id / "file.txt").write_text("hello")
    service._sync_tar_snapshot("snap-1", sandbox_id)
    from openhands.ev2.util import snapshot_store

    assert snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_tar_snapshot_conflict_when_tarball_exists(tmp_path: Path) -> None:
    service = _service_with_workspace(tmp_path)
    assert service.workspace_dir is not None
    sandbox_id = "sb-1"
    (Path(service.workspace_dir) / sandbox_id).mkdir(parents=True)
    service._sync_tar_snapshot("snap-1", sandbox_id)
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_tar_snapshot("snap-1", sandbox_id)


def test_sync_tar_snapshot_raises_when_workspace_missing(tmp_path: Path) -> None:
    service = _service_with_workspace(tmp_path)
    # Workspace dir exists but the per-sandbox subdirectory does not.
    assert service.workspace_dir is not None
    Path(service.workspace_dir).mkdir(parents=True)
    with pytest.raises(SandboxNotFoundError):
        service._sync_tar_snapshot("snap-1", "sb-missing")


def test_sync_tar_snapshot_raises_when_no_workspace_dir(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    with pytest.raises(SandboxNotFoundError):
        service._sync_tar_snapshot("snap-1", "sb-1")


def test_sync_import_snapshot_writes_file(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    from openhands.ev2.util import snapshot_store

    assert snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_import_snapshot_conflict_when_exists(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_import_snapshot("snap-1", b"again")


def test_sync_delete_snapshot_removes_tarball(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    service._sync_delete_snapshot("snap-1")
    from openhands.ev2.util import snapshot_store

    assert not snapshot_store.snapshot_exists(service.snapshot_dir, "snap-1")


def test_sync_delete_snapshot_missing_raises_not_found(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_delete_snapshot("nope")


async def test_stream_snapshot_returns_bytes(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    service._sync_import_snapshot("snap-1", b"tarball-bytes")
    chunks = await service.stream_snapshot("snap-1")
    assert b"".join(chunks) == b"tarball-bytes"


async def test_service_capture_snapshot_from_sandbox(tmp_path: Path) -> None:
    service = _service_with_workspace(tmp_path)
    assert service.workspace_dir is not None
    sandbox_id = "sb-1"
    ws = Path(service.workspace_dir) / sandbox_id
    ws.mkdir(parents=True)
    (ws / "f.txt").write_text("data")
    snapshot_id, size = await service.capture_snapshot(sandbox_id)
    assert snapshot_id
    assert size is not None and size > 0


async def test_service_import_snapshot_from_file(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    snapshot_id, size = await service.import_snapshot_file(b"tarball-bytes")
    assert snapshot_id
    assert size is not None and size > 0


async def test_service_delete_snapshot(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    await service.import_snapshot_file(b"tarball-bytes")
    snapshot_id = (await service.import_snapshot_file(b"more"))[0]
    await service.delete_snapshot_artifact(snapshot_id)
    from openhands.ev2.util import snapshot_store

    assert not snapshot_store.snapshot_exists(service.snapshot_dir, snapshot_id)


async def test_service_delete_snapshot_not_found_raises(tmp_path: Path) -> None:
    service = DockerSandboxService(snapshot_dir=str(tmp_path / "snaps"))
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.delete_snapshot_artifact("nope")


def test_base_service_snapshot_hooks_raise_unsupported() -> None:
    # A SandboxService subclass that does not override the snapshot hooks
    # inherits the unsupported defaults from the base class.
    class _BareService(SandboxService):
        async def _list_sandboxes(self) -> list[Sandbox]:
            return []

        async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
            raise SandboxNotFoundError(sandbox_id)

        def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
            raise NotImplementedError

        async def _create_sandbox(
            self, sandbox: Sandbox, *, snapshot_id: str | None = None
        ) -> Sandbox:
            raise NotImplementedError

        async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
            raise NotImplementedError

        async def _delete_sandbox(self, sandbox_id: str) -> None:
            pass

    service = _BareService()
    with pytest.raises(SandboxSnapshotUnsupportedError):
        asyncio.run(service.stream_snapshot("snap-a"))


# --------------------------------------------------------------------------- #
# last_accessed_at derivation.
# --------------------------------------------------------------------------- #


def _active_sandbox_with_url(url: str = "http://localhost:32771") -> DockerSandbox:
    return DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        exposed_urls=[ExposedUrl(name="agent_server", url=url, port=32771)],
    )


@respx.mock
async def test_resolve_last_accessed_at_from_idle_time() -> None:
    service = DockerSandboxService()
    respx.get("http://localhost:32771/").mock(
        return_value=httpx.Response(200, json={"idle_time": 60})
    )
    accessed = await service._resolve_last_accessed_at(_active_sandbox_with_url())
    assert accessed is not None
    delta = datetime.now(UTC) - accessed
    assert 55 <= delta.total_seconds() <= 70


async def test_resolve_last_accessed_at_none_when_not_active() -> None:
    service = DockerSandboxService()
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
    assert await service._resolve_last_accessed_at(sandbox) is None


@respx.mock
async def test_resolve_last_accessed_at_none_on_http_error() -> None:
    service = DockerSandboxService()
    respx.get("http://localhost:32771/").mock(side_effect=httpx.ConnectError("boom"))
    assert await service._resolve_last_accessed_at(_active_sandbox_with_url()) is None


@respx.mock
async def test_resolve_last_accessed_at_none_when_idle_time_missing() -> None:
    service = DockerSandboxService()
    respx.get("http://localhost:32771/").mock(return_value=httpx.Response(200, json={"other": 1}))
    assert await service._resolve_last_accessed_at(_active_sandbox_with_url()) is None


@respx.mock
async def test_list_sandboxes_enriches_last_accessed_at() -> None:
    service = DockerSandboxService()
    respx.get("http://localhost:32771/").mock(
        return_value=httpx.Response(200, json={"idle_time": 5})
    )

    class _FakeContainers:
        def list(self, all: bool = False) -> list[Any]:  # noqa: A002
            return [
                _FakeContainer(
                    _container_attrs(status="running", ports={"8000/tcp": [{"HostPort": "32771"}]})
                )
            ]

    service._client = _FakeDockerClient(containers=_FakeContainers())
    sandboxes = await service._list_sandboxes()
    assert len(sandboxes) == 1
    assert sandboxes[0].last_accessed_at is not None


# --------------------------------------------------------------------------- #
# Lifecycle sweep.
# --------------------------------------------------------------------------- #


class _FakeImage:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs


class _FakeImages:
    def __init__(self, images: list[_FakeImage]) -> None:
        self._images = {image.attrs["RepoTags"][0]: image for image in images}

    def get(self, name: str) -> _FakeImage:
        try:
            return self._images[name]
        except KeyError:
            raise ImageNotFound(name) from None


class _FakeContainerCtrl:
    """A fake Docker container supporting pause/stop/remove + label mutation."""

    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs
        self.paused = False
        self.stopped = False
        self.removed = False

    def reload(self) -> None:
        pass

    def pause(self) -> None:
        self.paused = True
        self.attrs["State"]["Status"] = "paused"
        with contextlib.suppress(Exception):
            self.attrs["Config"]["Labels"]["io.openhands.sandbox.paused_at"] = datetime.now(
                UTC
            ).isoformat()

    def unpause(self) -> None:
        self.paused = False
        self.attrs["State"]["Status"] = "running"

    def stop(self) -> None:
        self.stopped = True
        self.attrs["State"]["Status"] = "exited"

    def start(self) -> None:
        self.stopped = False
        self.attrs["State"]["Status"] = "running"

    def remove(self, force: bool = False) -> None:
        self.removed = True


class _FakeContainers:
    def __init__(self, containers: list[_FakeContainerCtrl]) -> None:
        self._containers = {c.attrs["Name"].lstrip("/"): c for c in containers}

    def list(self, all: bool = False) -> list[_FakeContainerCtrl]:  # noqa: A002
        return list(self._containers.values())

    def get(self, sandbox_id: str) -> _FakeContainerCtrl:
        try:
            return self._containers[sandbox_id]
        except KeyError:
            raise NotFound(sandbox_id) from None


class _FakeDockerClient:
    def __init__(
        self,
        images: list[_FakeImage] | None = None,
        containers: Any = None,
    ) -> None:
        self.images = _FakeImages(images or [])
        self.containers = containers or _FakeContainers([])


def _image_attrs_with_knobs(
    repo_tag: str,
    *,
    idle_pause_seconds: int | None = None,
    paused_delete_seconds: int | None = None,
    max_age_seconds: int | None = None,
) -> dict[str, Any]:
    labels: dict[str, str] = {}
    if idle_pause_seconds is not None:
        labels["io.openhands.sandbox.idle_pause_seconds"] = str(idle_pause_seconds)
    if paused_delete_seconds is not None:
        labels["io.openhands.sandbox.paused_delete_seconds"] = str(paused_delete_seconds)
    if max_age_seconds is not None:
        labels["io.openhands.sandbox.max_age_seconds"] = str(max_age_seconds)
    return {
        "RepoTags": [repo_tag],
        "Created": "2024-01-02T03:04:05Z",
        "Config": {"Cmd": None, "Env": None, "WorkingDir": None, "Labels": labels},
        "HostConfig": {},
    }


@respx.mock
async def test_sweep_pauses_idle_active_sandbox() -> None:
    service = DockerSandboxService()
    respx.get("http://localhost:32771/").mock(
        return_value=httpx.Response(200, json={"idle_time": 999})
    )
    sandbox = _FakeContainerCtrl(
        _container_attrs(
            status="running",
            image="img:latest",
            ports={"8000/tcp": [{"HostPort": "32771"}]},
        )
    )
    # Make last_accessed_at old enough to exceed idle_pause_seconds.
    sandbox.attrs["Created"] = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    service._client = _FakeDockerClient(
        images=[_FakeImage(_image_attrs_with_knobs("img:latest", idle_pause_seconds=10))],
        containers=_FakeContainers([sandbox]),
    )
    summary = await service.sweep_lifecycle()
    assert sandbox.paused
    assert summary is not None and "paused" in summary


async def test_sweep_skips_active_sandbox_under_idle_threshold() -> None:
    service = DockerSandboxService()
    sandbox = _FakeContainerCtrl(_container_attrs(status="running", image="img:latest"))
    service._client = _FakeDockerClient(
        images=[_FakeImage(_image_attrs_with_knobs("img:latest", idle_pause_seconds=3600))],
        containers=_FakeContainers([sandbox]),
    )
    # No exposed URL -> last_accessed_at None -> idle_seconds None -> no pause.
    summary = await service.sweep_lifecycle()
    assert not sandbox.paused
    assert summary is None


async def test_sweep_deletes_paused_sandbox_past_paused_delete() -> None:
    service = DockerSandboxService()
    paused_at = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    sandbox = _FakeContainerCtrl(
        _container_attrs(
            status="paused",
            image="img:latest",
            labels={"io.openhands.sandbox.paused_at": paused_at},
        )
    )
    service._client = _FakeDockerClient(
        images=[_FakeImage(_image_attrs_with_knobs("img:latest", paused_delete_seconds=60))],
        containers=_FakeContainers([sandbox]),
    )
    summary = await service.sweep_lifecycle()
    assert sandbox.removed
    assert summary is not None and "deleted" in summary


async def test_sweep_deletes_sandbox_past_max_age() -> None:
    service = DockerSandboxService()
    sandbox = _FakeContainerCtrl(_container_attrs(status="running", image="img:latest"))
    sandbox.attrs["Created"] = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    service._client = _FakeDockerClient(
        images=[_FakeImage(_image_attrs_with_knobs("img:latest", max_age_seconds=60))],
        containers=_FakeContainers([sandbox]),
    )
    summary = await service.sweep_lifecycle()
    assert sandbox.removed
    assert summary is not None and "deleted" in summary


async def test_sweep_no_op_when_no_thresholds_set() -> None:
    service = DockerSandboxService()
    sandbox = _FakeContainerCtrl(_container_attrs(status="running", image="img:latest"))
    service._client = _FakeDockerClient(
        images=[_FakeImage(_image_attrs_with_knobs("img:latest"))],
        containers=_FakeContainers([sandbox]),
    )
    summary = await service.sweep_lifecycle()
    assert not sandbox.paused
    assert not sandbox.removed
    assert summary is None


# --------------------------------------------------------------------------- #
# Lifecycle task management.
# --------------------------------------------------------------------------- #


async def test_aenter_starts_lifecycle_task() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=0.1)
    service._client = _FakeDockerClient()
    async with service:
        assert service._lifecycle_task is not None
        task = service._lifecycle_task
    assert task.cancelled() or task.done()


async def test_aenter_skips_task_when_interval_zero() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=0)
    service._client = _FakeDockerClient()
    async with service:
        assert service._lifecycle_task is None


async def test_aclose_cancels_lifecycle_task() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=0.1)
    service._client = _FakeDockerClient()
    await service.__aenter__()
    task = service._lifecycle_task
    assert task is not None
    await service.__aexit__(None, None, None)
    assert task.cancelled() or task.done()


async def test_aclose_closes_http_client() -> None:
    service = DockerSandboxService()
    await service.__aenter__()
    # Force creation of the http client.
    client = service._http_client()
    assert service._http is client
    await service.__aexit__(None, None, None)
    assert client.is_closed


async def test_lifecycle_loop_runs_one_sweep_then_cancels() -> None:
    swept: list[bool] = []

    class _StubSweepService(DockerSandboxService):
        async def sweep_lifecycle(self) -> str | None:
            swept.append(True)
            return None

    service = _StubSweepService(sandbox_lifecycle_interval=0.01)
    service._client = _FakeDockerClient()
    await service.__aenter__()
    await asyncio.sleep(0.05)
    await service.__aexit__(None, None, None)
    assert swept


# --------------------------------------------------------------------------- #
# Deactivation mode (pause vs stop) stamps/clears the paused_at label.
# --------------------------------------------------------------------------- #


def test_deactivate_container_stamps_paused_at_label() -> None:
    service = DockerSandboxService(deactivate_mode="pause")
    container = _FakeContainerCtrl(_container_attrs(status="running", image="img:latest"))
    service._deactivate_container(container, "running")
    assert container.paused
    assert container.attrs["Config"]["Labels"].get("io.openhands.sandbox.paused_at") is not None


def test_deactivate_container_stamps_paused_at_label_in_stop_mode() -> None:
    service = DockerSandboxService(deactivate_mode="stop")
    container = _FakeContainerCtrl(_container_attrs(status="running", image="img:latest"))
    service._deactivate_container(container, "running")
    assert container.stopped
    assert container.attrs["Config"]["Labels"].get("io.openhands.sandbox.paused_at") is not None


def test_activate_container_clears_paused_at_label() -> None:
    service = DockerSandboxService()
    container = _FakeContainerCtrl(
        _container_attrs(
            status="paused",
            image="img:latest",
            labels={"io.openhands.sandbox.paused_at": "2024-01-02T03:04:05Z"},
        )
    )
    service._activate_container(container, "paused")
    assert "io.openhands.sandbox.paused_at" not in (container.attrs["Config"]["Labels"])


def test_container_state_handles_reload_exception() -> None:
    from openhands.ev2.sandbox.docker_sandbox_service import _container_state

    class _Broken:
        def reload(self) -> None:
            raise RuntimeError("reload failed")

        attrs: ClassVar[dict[str, Any]] = {"State": {"Status": "running"}}

    assert _container_state(_Broken()) == "running"


# --------------------------------------------------------------------------- #
# Sandbox CRUD via a fake Docker client with container/image ops.
# --------------------------------------------------------------------------- #


class _FakeImageWithOps:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs

    def save(self, named: bool = False) -> list[bytes]:
        return [b"fake-tarball"]

    def tag(self, repository: str, tag: str) -> bool:
        return True

    def remove(self, force: bool = False) -> None:
        pass


class _FakeImagesWithOps:
    def __init__(self, images: list[_FakeImageWithOps]) -> None:
        self._images: dict[str, _FakeImageWithOps] = {
            image.attrs["RepoTags"][0]: image for image in images
        }

    def list(self) -> list[_FakeImageWithOps]:
        return list(self._images.values())

    def get(self, name: str) -> _FakeImageWithOps:
        try:
            return self._images[name]
        except KeyError:
            raise ImageNotFound(name) from None

    def remove(self, image: str, force: bool = False) -> None:
        if image not in self._images:
            raise ImageNotFound(image) from None
        del self._images[image]

    def pull(self, repository: str) -> None:
        self._images[repository] = _FakeImageWithOps(
            {"RepoTags": [repository], "Created": "2024-01-02T03:04:05Z", "Config": {"Labels": {}}}
        )


class _FakeContainerWithOps:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs
        self._paused = False
        self._stopped = False
        self._started = False
        self._unpaused = False
        self._removed = False

    @property
    def name(self) -> str:
        return self.attrs["Name"].lstrip("/")

    def reload(self) -> None:
        return None

    def pause(self) -> None:
        self._paused = True
        self.attrs["State"]["Status"] = "paused"

    def stop(self) -> None:
        self._stopped = True
        self.attrs["State"]["Status"] = "exited"

    def unpause(self) -> None:
        self._unpaused = True
        self.attrs["State"]["Status"] = "running"

    def start(self) -> None:
        self._started = True
        self.attrs["State"]["Status"] = "running"

    def remove(self, force: bool = False) -> None:
        self._removed = True


class _FakeContainersWithOps:
    _generated_name_counter = 0

    def __init__(self, containers: list[_FakeContainerWithOps]) -> None:
        self._containers: dict[str, _FakeContainerWithOps] = {
            c.attrs["Name"].lstrip("/"): c for c in containers
        }

    def list(self, all: bool = False) -> list[_FakeContainerWithOps]:  # noqa: A002
        return list(self._containers.values())

    def get(self, name: str) -> _FakeContainerWithOps:
        try:
            return self._containers[name]
        except KeyError:
            raise NotFound(name) from None

    def run(
        self,
        image: str,
        name: str | None = None,
        detach: bool = False,
        ports: dict[str, Any] | None = None,
        labels: dict[str, str] | None = None,
        init: bool = False,
        volumes: list[str] | None = None,
        working_dir: str | None = None,
        extra_hosts: dict[str, str] | None = None,
        devices: list[str] | None = None,
        environment: dict[str, str] | None = None,
    ) -> _FakeContainerWithOps:
        if name is None:
            type(self)._generated_name_counter += 1
            name = f"fakename-{type(self)._generated_name_counter}"
        attrs = _container_attrs(name=name, image=image, sandbox_id=name)
        attrs["State"]["Status"] = "running"
        attrs["Config"]["Labels"] = labels or {}
        container = _FakeContainerWithOps(attrs)
        self._containers[name] = container
        return container


class _FakeSnapshotDockerClient:
    def __init__(
        self,
        images: list[_FakeImageWithOps],
        containers: list[_FakeContainerWithOps] | None = None,
    ) -> None:
        self.images = _FakeImagesWithOps(images)
        self.containers = _FakeContainersWithOps(containers or [])


def _make_snapshot_service(
    images: list[_FakeImageWithOps],
    containers: list[tuple[str, str]] | None = None,
) -> tuple[DockerSandboxService, _FakeSnapshotDockerClient]:
    client = _FakeSnapshotDockerClient(images)
    for cname, image in containers or []:
        attrs = _container_attrs(name=cname, image=image, sandbox_id=cname)
        attrs["Config"]["Labels"]["io.openhands.sandbox.sandbox_template_id"] = image
        attrs["HostConfig"]["Binds"] = ["/host:/container:rw"]
        attrs["NetworkSettings"]["Ports"] = {"8000/tcp": [{"HostPort": "32771"}]}
        container = _FakeContainerWithOps(attrs)
        client.containers._containers[cname] = container
    service = DockerSandboxService()
    service._client = client
    return service, client


async def test_async_list_sandboxes_returns_sandboxes() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a"), ("sb-2", "img-a")])
    sandboxes = await service._list_sandboxes()
    assert {sb.id for sb in sandboxes} == {"sb-1", "sb-2"}


async def test_async_get_sandbox_returns_sandbox() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    sandbox = await service._get_sandbox("sb-1")
    assert sandbox.id == "sb-1"


async def test_async_get_sandbox_not_found_raises() -> None:
    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxNotFoundError):
        await service._get_sandbox("nope")


async def test_async_create_sandbox_creates_container() -> None:
    service, client = _make_snapshot_service([], [])
    sandbox = service._sandbox_from_create(SandboxCreate(sandbox_template_id="img-a"))
    result = await service._create_sandbox(sandbox)
    assert result.id != ""
    assert result.sandbox_template_id == "img-a"
    assert result.id in client.containers._containers


async def test_async_update_sandbox_activates_paused() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "paused"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.ACTIVE))
    assert container._unpaused


async def test_async_update_sandbox_starts_exited() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "exited"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.ACTIVE))
    assert container._started


async def test_async_update_sandbox_pauses_running() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "running"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.INACTIVE))
    assert container._paused


async def test_async_update_sandbox_not_found_raises() -> None:
    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxNotFoundError):
        await service._update_sandbox("nope", SandboxUpdate(desired_status=SandboxStatus.ACTIVE))


async def test_async_delete_sandbox_removes_container() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    await service._delete_sandbox("sb-1")
    assert container._removed


async def test_async_delete_sandbox_not_found_raises() -> None:
    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxNotFoundError):
        await service._delete_sandbox("nope")


async def test_sandbox_service_context_manager() -> None:
    service = DockerSandboxService()
    entered = await service.__aenter__()
    assert entered is service
    await service.aclose()
    assert service._client is None


# --------------------------------------------------------------------------- #
# snapshot_store round-trip (restore path).
# --------------------------------------------------------------------------- #


def test_snapshot_restore_roundtrip(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    snapshot_dir = str(tmp_path / "snaps")
    source_ws = tmp_path / "src" / "sb-1"
    source_ws.mkdir(parents=True)
    (source_ws / "hello.txt").write_text("world")
    snapshot_store.create_snapshot(snapshot_dir, "snap-1", source_ws)
    dest_ws = tmp_path / "dest" / "sb-2"
    snapshot_store.restore_snapshot(snapshot_dir, "snap-1", dest_ws)
    assert (dest_ws / "hello.txt").read_text() == "world"


def test_snapshot_store_list_and_size(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    snapshot_dir = str(tmp_path / "snaps")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "f").write_text("x")
    snapshot_store.create_snapshot(snapshot_dir, "snap-1", ws)
    assert snapshot_store.list_snapshot_ids(snapshot_dir) == ["snap-1"]
    assert snapshot_store.snapshot_size(snapshot_dir, "snap-1") is not None
    assert snapshot_store.snapshot_created_at(snapshot_dir, "snap-1") is not None


def test_snapshot_store_list_empty_when_dir_missing(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    assert snapshot_store.list_snapshot_ids(str(tmp_path / "nope")) == []


def test_snapshot_store_size_and_created_at_missing_return_none(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    snapshot_dir = str(tmp_path / "snaps")
    assert snapshot_store.snapshot_size(snapshot_dir, "nope") is None
    assert snapshot_store.snapshot_created_at(snapshot_dir, "nope") is None


def test_snapshot_store_restore_missing_raises(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    with pytest.raises(FileNotFoundError):
        snapshot_store.restore_snapshot(str(tmp_path / "snaps"), "nope", tmp_path / "dest")


def test_snapshot_store_stream_roundtrip(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    snapshot_dir = str(tmp_path / "snaps")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "f.txt").write_text("data")
    snapshot_store.create_snapshot(snapshot_dir, "snap-1", ws)
    chunks = b"".join(snapshot_store.stream_snapshot(snapshot_dir, "snap-1"))
    assert chunks  # non-empty tarball bytes


def test_snapshot_store_stream_missing_raises(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    with pytest.raises(FileNotFoundError):
        list(snapshot_store.stream_snapshot(str(tmp_path / "snaps"), "nope"))


def test_snapshot_store_create_conflict_raises(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    snapshot_dir = str(tmp_path / "snaps")
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "f").write_text("x")
    snapshot_store.create_snapshot(snapshot_dir, "snap-1", ws)
    with pytest.raises(FileExistsError):
        snapshot_store.create_snapshot(snapshot_dir, "snap-1", ws)


async def test_docker_create_sandbox_restores_snapshot_into_workspace(tmp_path: Path) -> None:
    from openhands.ev2.util import snapshot_store

    service = DockerSandboxService(
        workspace_dir=str(tmp_path / "ws"), snapshot_dir=str(tmp_path / "snaps")
    )
    service._client = _FakeSnapshotDockerClient([])
    # Seed a real (valid gzip-tar) snapshot from a source workspace.
    src_ws = tmp_path / "src"
    src_ws.mkdir()
    (src_ws / "hello.txt").write_text("world")
    snapshot_store.create_snapshot(service.snapshot_dir, "snap-1", src_ws)
    sandbox = service._sandbox_from_create(SandboxCreate(sandbox_template_id="img-a"))
    result = await service._create_sandbox(sandbox, snapshot_id="snap-1")
    assert result.id != ""
    assert Path(service.workspace_dir, result.id).is_dir()  # type: ignore[arg-type]
    assert (Path(service.workspace_dir, result.id) / "hello.txt").read_text() == "world"  # type: ignore[arg-type]


async def test_docker_update_sandbox_stop_mode_stops_container(tmp_path: Path) -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    service.deactivate_mode = "stop"
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "running"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.INACTIVE))
    assert container._stopped


async def test_docker_delete_sandbox_cleans_workspace_dir(tmp_path: Path) -> None:
    service = DockerSandboxService(
        workspace_dir=str(tmp_path / "ws"), snapshot_dir=str(tmp_path / "snaps")
    )
    service._client = _FakeSnapshotDockerClient([])
    sb_dir = Path(service.workspace_dir, "sb-1")  # type: ignore[arg-type]
    sb_dir.mkdir(parents=True)
    # Seed a container so delete finds it.
    attrs = _container_attrs(name="sb-1", image="img-a", sandbox_id="sb-1")
    attrs["Config"]["Labels"]["io.openhands.sandbox.sandbox_template_id"] = "img-a"
    service._client.containers._containers["sb-1"] = _FakeContainerWithOps(attrs)
    await service._delete_sandbox("sb-1")
    assert not sb_dir.exists()
