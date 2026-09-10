"""Tests for the pluggable sandbox control plane.

Covers the pieces that do not require a live Docker daemon or database: the
template model/schemas, the Docker Image attribute mapping helpers, and the
service factory/config wiring.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any, ClassVar

import httpx
import pytest
import respx
from docker.errors import ImageNotFound  # type: ignore[import-untyped]
from pydantic import ValidationError

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox, DockerSandboxSnapshot
from openhands.ev2.sandbox.docker_sandbox_service import (
    DEFAULT_EXPOSED_PORTS,
    DockerSandboxService,
    _docker_template_from_payload,
    _exposed_urls_from_ports,
    _is_snapshot_image,
    _label_int,
    _parse_created,
    _parse_env,
    _sandbox_from_container_attrs,
    _snapshot_from_image_attrs,
    _snapshot_image_tag,
    _template_from_image_attrs,
    _volume_mounts_from_binds,
    _wildcard_match,
)
from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxTemplate,
    ExposedPort,
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SandboxTemplate,
    SnapshotMode,
    VolumeMount,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxCreate,
    SandboxRead,
    SandboxSearchFilter,
    SandboxSnapshotCreate,
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxService,
    resolve_sandbox_service_class,
)

# --------------------------------------------------------------------------- #
# Models.
# --------------------------------------------------------------------------- #


def test_docker_template_defaults() -> None:
    template = DockerSandboxTemplate(id="ghcr.io/org/agent-server:latest")
    assert template.command is None
    assert template.initial_env == {}
    assert template.working_dir == "/home/openhands/workspace"
    assert template.idle_pause_seconds is None
    assert template.paused_delete_seconds is None
    assert template.max_age_seconds is None
    assert template.max_memory is None
    assert template.exposed_ports == []
    assert template.kind == "DockerSandboxTemplate"


def test_docker_template_carries_exposed_ports() -> None:
    template = DockerSandboxTemplate(
        id="img",
        exposed_ports=[
            ExposedPort(name="agent_server", description="agent server", container_port=8000),
        ],
    )
    assert len(template.exposed_ports) == 1
    assert template.exposed_ports[0].name == "agent_server"


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
    assert restored.exposed_urls[0].name == "agent_server"
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
        port.container_port = 9  # type: ignore[misc]


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
        SandboxUpdate.model_validate({})  # type: ignore[arg-type]


def test_template_discriminated_union_round_trip() -> None:
    template = DockerSandboxTemplate(
        id="img",
        command=["bash", "-c", "true"],
        idle_pause_seconds=60,
        max_memory=1024,
    )
    restored = SandboxTemplate.model_validate(template.model_dump(mode="json"))
    assert isinstance(restored, DockerSandboxTemplate)
    assert restored.id == "img"
    assert restored.idle_pause_seconds == 60
    assert restored.max_memory == 1024


def test_template_requires_id() -> None:
    with pytest.raises(ValidationError):
        DockerSandboxTemplate()  # type: ignore[call-arg]


# --------------------------------------------------------------------------- #
# Schemas.
# --------------------------------------------------------------------------- #


def test_create_payload_defaults() -> None:
    payload = SandboxTemplateCreate.model_validate({"id": "img"})
    assert payload.command is None
    assert payload.initial_env == {}
    assert payload.working_dir == "/home/openhands/workspace"
    assert payload.max_memory is None
    assert payload.exposed_ports == []


def test_create_payload_rejects_non_positive_timeouts() -> None:
    with pytest.raises(ValidationError):
        SandboxTemplateCreate.model_validate({"id": "img", "idle_pause_seconds": 0})
    with pytest.raises(ValidationError):
        SandboxTemplateCreate.model_validate({"id": "img", "max_age_seconds": -1})


def test_read_model_from_template() -> None:
    template = DockerSandboxTemplate(id="img", idle_pause_seconds=30, max_memory=2048)
    read = SandboxTemplateRead.model_validate(template)
    assert read.id == "img"
    assert read.idle_pause_seconds == 30
    assert read.max_memory == 2048
    assert read.created_at == template.created_at
    assert read.exposed_ports == []


# --------------------------------------------------------------------------- #
# Docker Image attribute mapping.
# --------------------------------------------------------------------------- #


_PORTS = list(DEFAULT_EXPOSED_PORTS)


def test_template_from_image_attrs_basic() -> None:
    attrs = {
        "RepoTags": ["ghcr.io/org/agent-server:latest", "ghcr.io/org/agent-server:v1"],
        "Created": "2024-01-02T03:04:05.000000000Z",
        "Config": {
            "Cmd": ["bash", "-c", "sleep infinity"],
            "Env": ["A=1", "B=two"],
            "WorkingDir": "/workspace",
            "Labels": {
                "io.openhands.sandbox.idle_pause_seconds": "120",
                "io.openhands.sandbox.max_age_seconds": "3600",
            },
        },
        "HostConfig": {"Memory": 1073741824},
    }
    template = _template_from_image_attrs(attrs, _PORTS)
    assert isinstance(template, DockerSandboxTemplate)
    assert template.id == "ghcr.io/org/agent-server:latest"
    assert template.command == ["bash", "-c", "sleep infinity"]
    assert template.initial_env == {"A": "1", "B": "two"}
    assert template.working_dir == "/workspace"
    assert template.idle_pause_seconds == 120
    assert template.paused_delete_seconds is None
    assert template.max_age_seconds == 3600
    assert template.max_memory == 1073741824
    assert [p.name for p in template.exposed_ports] == ["agent_server", "vscode"]


def test_template_from_image_attrs_untagged_is_not_template() -> None:
    from openhands.ev2.sandbox.sandbox_service import (
        SandboxTemplateNotFoundError,
    )

    with pytest.raises(SandboxTemplateNotFoundError):
        _template_from_image_attrs({"RepoTags": ["<none>:<none>"]}, _PORTS)


def test_parse_env_skips_malformed() -> None:
    assert _parse_env(None) == {}
    assert _parse_env([]) == {}
    assert _parse_env(["NO_EQUALS", "A=1", "B="]) == {"A": "1", "B": ""}


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


def test_docker_template_from_payload() -> None:
    payload = SandboxTemplateCreate.model_validate(
        {
            "id": "img",
            "command": ["echo", "hi"],
            "initial_env": {"K": "v"},
            "working_dir": "/app",
            "idle_pause_seconds": 10,
            "max_memory": 512,
        }
    )
    template = _docker_template_from_payload(payload, _PORTS)
    assert isinstance(template, DockerSandboxTemplate)
    assert template.id == "img"
    assert template.command == ["echo", "hi"]
    assert template.initial_env == {"K": "v"}
    assert template.working_dir == "/app"
    assert template.idle_pause_seconds == 10
    assert template.max_memory == 512
    assert [p.name for p in template.exposed_ports] == ["agent_server", "vscode"]


def test_docker_template_from_payload_custom_ports() -> None:
    payload = SandboxTemplateCreate.model_validate(
        {
            "id": "img",
            "exposed_ports": [
                {"name": "custom", "description": "d", "container_port": 9000},
            ],
        }
    )
    template = _docker_template_from_payload(payload, list(DEFAULT_EXPOSED_PORTS))
    assert [p.name for p in template.exposed_ports] == ["custom"]


def test_exposed_urls_from_ports() -> None:
    ports = list(DEFAULT_EXPOSED_PORTS)
    binding = {"8000/tcp": [{"HostPort": "32771"}], "8001/tcp": None}
    urls = _exposed_urls_from_ports(ports, binding)
    assert [u.name for u in urls] == ["agent_server"]
    assert urls[0].port == 32771
    assert urls[0].url == "http://localhost:32771"


def test_exposed_urls_empty_when_no_binding() -> None:
    assert _exposed_urls_from_ports(list(DEFAULT_EXPOSED_PORTS), {}) == []


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


# --------------------------------------------------------------------------- #
# Docker synchronous CRUD (using a fake in-process image client).
# --------------------------------------------------------------------------- #


class _FakeImage:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs


class _FakeImages:
    def __init__(self, images: list[_FakeImage]) -> None:
        self._images = {image.attrs["RepoTags"][0]: image for image in images}

    def list(self) -> list[_FakeImage]:
        return list(self._images.values())

    def get(self, name: str) -> _FakeImage:
        try:
            return self._images[name]
        except KeyError:
            raise ImageNotFound(name) from None


class _FakeDockerClient:
    def __init__(self, images: list[_FakeImage]) -> None:
        self.images = _FakeImages(images)


def _image_attrs(repo_tag: str) -> dict[str, Any]:
    return {
        "RepoTags": [repo_tag],
        "Created": "2024-01-02T03:04:05Z",
        "Config": {"Cmd": None, "Env": None, "WorkingDir": None, "Labels": {}},
        "HostConfig": {},
    }


def test_sync_list_templates_filters_by_image_name_patterns() -> None:
    service = DockerSandboxService(
        image_name_patterns=["ghcr.io/openhands/*"],
    )
    service._client = _FakeDockerClient(
        [
            _FakeImage(_image_attrs("ghcr.io/openhands/agent-server:latest")),
            _FakeImage(_image_attrs("ghcr.io/other/agent:latest")),
        ]
    )
    templates = service._sync_list_templates()
    assert [t.id for t in templates] == ["ghcr.io/openhands/agent-server:latest"]


def test_sync_get_template_returns_matching_image() -> None:
    service = DockerSandboxService(
        image_name_patterns=["ghcr.io/openhands/*"],
    )
    service._client = _FakeDockerClient(
        [_FakeImage(_image_attrs("ghcr.io/openhands/agent-server:latest"))]
    )
    template = service._sync_get_template("ghcr.io/openhands/agent-server:latest")
    assert template.id == "ghcr.io/openhands/agent-server:latest"


def test_sync_get_template_rejects_non_matching_image() -> None:
    from openhands.ev2.sandbox.sandbox_service import (
        SandboxTemplateNotFoundError,
    )

    service = DockerSandboxService(
        image_name_patterns=["ghcr.io/openhands/*"],
    )
    service._client = _FakeDockerClient([_FakeImage(_image_attrs("ghcr.io/other/agent:latest"))])
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_get_template("ghcr.io/other/agent:latest")


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
        resolve_sandbox_service_class("openhands.ev2.sandbox.sandbox_service.SandboxTemplate")


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


def test_docker_service_image_name_matching() -> None:
    service = DockerSandboxService()
    # The default pattern is ``:*`` so tagged images match…
    assert service._matches_image_name_patterns("ghcr.io/openhands/agent-server:1.16.0")
    # …but a bare (tagless) image does not.
    assert not service._matches_image_name_patterns("ghcr.io/openhands/agent-server")
    assert not service._matches_image_name_patterns("ghcr.io/other/agent-canvas")


# --------------------------------------------------------------------------- #
# Router helpers (no Docker/DB required).
# --------------------------------------------------------------------------- #


def test_exception_to_status_mapping() -> None:
    from fastapi import status as http_status

    from openhands.ev2.sandbox.sandbox_service import (
        BatchPermissionDeniedError,
        SandboxTemplateConflictError,
        SandboxTemplateNotFoundError,
        SandboxTemplatePermissionScopeError,
    )
    from openhands.ev2.sandbox.sandbox_template_router import _map_exception_to_status

    assert _map_exception_to_status(SandboxTemplateNotFoundError("x")).status_code == 404
    assert _map_exception_to_status(SandboxTemplateConflictError("x")).status_code == 409
    assert _map_exception_to_status(SandboxTemplatePermissionScopeError("x")).status_code == 403
    assert _map_exception_to_status(BatchPermissionDeniedError("x")).status_code == 403
    assert (
        _map_exception_to_status(RuntimeError("boom")).status_code
        == http_status.HTTP_500_INTERNAL_SERVER_ERROR
    )


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


# --------------------------------------------------------------------------- #
# Docker container attribute mapping (sandbox projection).
# --------------------------------------------------------------------------- #


class _FakeContainer:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs

    def reload(self) -> None:
        return None


class _FakeContainers:
    def __init__(self, containers: list[_FakeContainer]) -> None:
        self._containers = {c.attrs["Name"].lstrip("/"): c for c in containers}

    def list(self, all: bool = False) -> list[_FakeContainer]:  # noqa: A002
        return list(self._containers.values())

    def get(self, name: str) -> _FakeContainer:
        try:
            return self._containers[name]
        except KeyError:
            from docker.errors import NotFound  # type: ignore[import-untyped]

            raise NotFound(name) from None


class _FakeContainerClient:
    def __init__(self, containers: list[_FakeContainer]) -> None:
        self.containers = _FakeContainers(containers)


def _container_attrs(name: str, *, image: str = "img", status: str = "running") -> dict[str, Any]:
    return {
        "Name": f"/{name}",
        "Created": "2024-01-02T03:04:05Z",
        "State": {"Status": status, "Error": None},
        "Config": {
            "Image": image,
            "Labels": {
                "io.openhands.sandbox.sandbox_id": name,
                "io.openhands.sandbox.sandbox_template_id": image,
            },
        },
        "HostConfig": {"Binds": ["/host:/container:rw"]},
        "NetworkSettings": {"Ports": {"8000/tcp": [{"HostPort": "32771"}]}},
    }


def test_sandbox_from_container_attrs_running() -> None:
    container = _FakeContainer(_container_attrs("sb-1", status="running"))
    sandbox = _sandbox_from_container_attrs(container, list(DEFAULT_EXPOSED_PORTS))
    assert isinstance(sandbox, DockerSandbox)
    assert sandbox.id == "sb-1"
    assert sandbox.sandbox_template_id == "img"
    assert sandbox.status is SandboxStatus.ACTIVE
    assert sandbox.desired_status is SandboxStatus.ACTIVE
    assert [u.name for u in (sandbox.exposed_urls or [])] == ["agent_server"]
    assert sandbox.volume_mounts[0].host_path == "/host"


def test_sandbox_from_container_attrs_paused_is_inactive() -> None:
    container = _FakeContainer(_container_attrs("sb-2", status="paused"))
    sandbox = _sandbox_from_container_attrs(container, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.INACTIVE


def test_sandbox_from_container_attrs_no_label_returns_none() -> None:
    attrs = _container_attrs("anon", status="running")
    attrs["Config"]["Labels"] = {}
    container = _FakeContainer(attrs)
    assert _sandbox_from_container_attrs(container, list(DEFAULT_EXPOSED_PORTS)) is None


def test_sandbox_from_container_attrs_exited_is_inactive() -> None:
    container = _FakeContainer(_container_attrs("sb-3", status="exited"))
    sandbox = _sandbox_from_container_attrs(container, list(DEFAULT_EXPOSED_PORTS))
    assert sandbox is not None
    assert sandbox.status is SandboxStatus.INACTIVE


def test_sync_list_sandboxes_projects_containers() -> None:
    service = DockerSandboxService()
    service._client = _FakeContainerClient(
        [
            _FakeContainer(_container_attrs("sb-1")),
            _FakeContainer(_container_attrs("sb-2", status="paused")),
        ]
    )
    sandboxes = service._sync_list_sandboxes()
    assert {sb.id for sb in sandboxes} == {"sb-1", "sb-2"}


def test_sync_get_sandbox_returns_container() -> None:
    service = DockerSandboxService()
    service._client = _FakeContainerClient([_FakeContainer(_container_attrs("sb-1"))])
    sandbox = service._sync_get_sandbox("sb-1")
    assert sandbox.id == "sb-1"


def test_sync_get_sandbox_missing_raises_not_found() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError

    service = DockerSandboxService()
    service._client = _FakeContainerClient([])
    with pytest.raises(SandboxNotFoundError):
        service._sync_get_sandbox("nope")


def test_sync_get_sandbox_unlabeled_raises_not_found() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError

    service = DockerSandboxService()
    attrs = _container_attrs("anon", status="running")
    attrs["Config"]["Labels"] = {}
    service._client = _FakeContainerClient([_FakeContainer(attrs)])
    with pytest.raises(SandboxNotFoundError):
        service._sync_get_sandbox("anon")


# --------------------------------------------------------------------------- #
# Snapshots.
# --------------------------------------------------------------------------- #


def test_snapshot_mode_default_is_manual() -> None:
    service = DockerSandboxService()
    assert service.snapshot_mode == SnapshotMode.MANUAL


def test_snapshot_mode_can_be_configured() -> None:
    service = DockerSandboxService(snapshot_mode=SnapshotMode.UNSUPPORTED)
    assert service.snapshot_mode == SnapshotMode.UNSUPPORTED


def test_sandbox_from_create_carries_snapshot_mode() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxCreate

    service = DockerSandboxService(snapshot_mode=SnapshotMode.AUTOMATIC)
    sandbox = service._sandbox_from_create(SandboxCreate(sandbox_template_id="img-a"))
    assert sandbox.snapshot_mode == SnapshotMode.AUTOMATIC


def test_snapshot_image_tag_builds_reference() -> None:
    assert _snapshot_image_tag("snap-1") == "openhands-sandbox-snapshot:snap-1"


def test_is_snapshot_image_detects_label() -> None:
    attrs = {"Config": {"Labels": {"io.openhands.sandbox.snapshot_id": "snap-a"}}}
    assert _is_snapshot_image(attrs) is True


def test_is_snapshot_image_false_without_label() -> None:
    attrs = {"Config": {"Labels": {}}}
    assert _is_snapshot_image(attrs) is False


def test_snapshot_from_image_attrs_basic() -> None:
    attrs = {
        "RepoTags": ["openhands-sandbox-snapshot:snap-a"],
        "Created": "2024-01-02T03:04:05.000000000Z",
        "Config": {
            "Labels": {
                "io.openhands.sandbox.snapshot_id": "snap-a",
                "io.openhands.sandbox.snapshot_sandbox_id": "sb-1",
                "io.openhands.sandbox.snapshot_created_at": "2024-01-02T03:04:05Z",
            }
        },
    }
    snapshot = _snapshot_from_image_attrs(attrs)
    assert snapshot is not None
    assert snapshot.id == "snap-a"
    assert snapshot.sandbox_id == "sb-1"
    assert snapshot.image_id == "openhands-sandbox-snapshot:snap-a"
    assert snapshot.created_at is not None
    assert snapshot.download_url is None


def test_snapshot_from_image_attrs_returns_none_without_label() -> None:
    attrs = {"Config": {"Labels": {}}}
    assert _snapshot_from_image_attrs(attrs) is None


def test_template_from_image_attrs_carries_snapshot_mode() -> None:
    attrs = {
        "RepoTags": ["img-a:latest"],
        "Config": {"Labels": {}, "WorkingDir": "/w"},
    }
    template = _template_from_image_attrs(attrs, _PORTS, SnapshotMode.AUTOMATIC)
    assert template.snapshot_mode == SnapshotMode.AUTOMATIC


def _snapshot_image_attrs(
    snapshot_id: str,
    *,
    sandbox_id: str | None = "sb-1",
    created_at: str = "2024-01-02T03:04:05Z",
) -> dict[str, Any]:
    """Build realistic Docker image attrs for a snapshot image."""
    labels: dict[str, str] = {
        "io.openhands.sandbox.snapshot_id": snapshot_id,
        "io.openhands.sandbox.snapshot_created_at": created_at,
    }
    if sandbox_id:
        labels["io.openhands.sandbox.snapshot_sandbox_id"] = sandbox_id
    return {
        "RepoTags": [f"openhands-sandbox-snapshot:{snapshot_id}"],
        "Created": created_at,
        "Config": {"Cmd": None, "Env": None, "WorkingDir": None, "Labels": labels},
        "HostConfig": {},
    }


def test_sync_list_templates_excludes_snapshot_images() -> None:
    service = DockerSandboxService(
        image_name_patterns=["ghcr.io/openhands/*", "openhands-sandbox-snapshot:*"],
    )
    service._client = _FakeDockerClient(
        [
            _FakeImage(_snapshot_image_attrs("snap-x")),
            _FakeImage(_image_attrs("ghcr.io/openhands/agent-canvas:latest")),
        ]
    )
    templates = service._sync_list_templates()
    assert [t.id for t in templates] == ["ghcr.io/openhands/agent-canvas:latest"]


def test_sync_list_snapshots_returns_only_snapshot_images() -> None:
    service = DockerSandboxService()
    service._client = _FakeDockerClient(
        [
            _FakeImage(_snapshot_image_attrs("snap-1", sandbox_id="sb-1")),
            _FakeImage(_image_attrs("img-a:latest")),
        ]
    )
    snapshots = service._sync_list_snapshots()
    assert [s.id for s in snapshots] == ["snap-1"]


def test_snapshot_from_image_attrs_falls_back_to_tag_without_repotags() -> None:
    attrs = {
        "RepoTags": None,
        "Created": "2024-01-02T03:04:05Z",
        "Config": {
            "Labels": {"io.openhands.sandbox.snapshot_id": "snap-a"},
        },
    }
    snapshot = _snapshot_from_image_attrs(attrs)
    assert snapshot is not None
    assert snapshot.id == "snap-a"
    assert snapshot.image_id == "openhands-sandbox-snapshot:snap-a"


def test_snapshot_from_image_attrs_uses_attrs_created_when_no_label() -> None:
    attrs = {
        "RepoTags": ["openhands-sandbox-snapshot:snap-a"],
        "Created": "2024-06-01T12:00:00Z",
        "Config": {
            "Labels": {"io.openhands.sandbox.snapshot_id": "snap-a"},
        },
    }
    snapshot = _snapshot_from_image_attrs(attrs)
    assert snapshot is not None
    assert snapshot.created_at is not None
    assert snapshot.created_at.year == 2024
    assert snapshot.created_at.month == 6


# --------------------------------------------------------------------------- #
# Docker snapshot CRUD (using enhanced fakes with commit/save/remove/load).
# --------------------------------------------------------------------------- #


class _FakeImageWithOps:
    """Fake Docker image supporting save(), tag(), and remove()."""

    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs
        self._saved = False
        self._tagged: list[tuple[str, str]] = []

    def save(self, named: bool = False) -> list[bytes]:
        self._saved = True
        return [b"fake-tarball"]

    def tag(self, repository: str, tag: str) -> bool:
        self._tagged.append((repository, tag))
        return True

    def remove(self, force: bool = False) -> None:
        pass


class _FakeImagesWithOps:
    """Fake Docker images client with get/list/remove/load/pull.

    Shares a backing dict with the container/api fakes so ``commit`` and
    ``load`` register images that ``get`` can subsequently find.
    """

    def __init__(self, images: list[_FakeImageWithOps]) -> None:
        self._images: dict[str, _FakeImageWithOps] = {}
        for image in images:
            tag = image.attrs["RepoTags"][0]
            self._images[tag] = image
        self._loaded_images: list[bytes] = []

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

    def load(self, data: bytes) -> list[_FakeImageWithOps]:
        self._loaded_images.append(data)
        fake = _FakeImageWithOps(
            {
                "RepoTags": ["loaded-temp:latest"],
                "Created": "2024-01-02T03:04:05Z",
                "Config": {"Labels": {}},
            }
        )
        self._images["loaded-temp:latest"] = fake
        return [fake]

    def pull(self, repository: str) -> None:
        fake = _FakeImageWithOps(
            {
                "RepoTags": [repository],
                "Created": "2024-01-02T03:04:05Z",
                "Config": {"Labels": {}},
            }
        )
        self._images[repository] = fake

    def _register(self, tag: str, attrs: dict[str, Any]) -> _FakeImageWithOps:
        """Register a newly committed/loaded image so ``get`` can find it."""
        image = _FakeImageWithOps(attrs)
        self._images[tag] = image
        return image


class _FakeContainerWithCommit:
    """Fake Docker container supporting commit(), reload(), pause/unpause/start/remove."""

    def __init__(
        self,
        attrs: dict[str, Any],
        images: _FakeImagesWithOps,
    ) -> None:
        self.attrs = attrs
        self._images = images
        self._committed: list[dict[str, Any]] = []
        self._paused = False
        self._started = False
        self._unpaused = False
        self._removed = False

    @property
    def name(self) -> str:
        return self.attrs["Name"].lstrip("/")

    def reload(self) -> None:
        return None

    def commit(
        self,
        repository: str,
        tag: str,
        labels: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Any:
        record = {"repository": repository, "tag": tag, "labels": labels or {}}
        self._committed.append(record)
        image_tag = f"{repository}:{tag}"
        all_labels = dict(self.attrs.get("Config", {}).get("Labels", {}))
        all_labels.update(labels or {})
        self._images._register(
            image_tag,
            {
                "RepoTags": [image_tag],
                "Created": "2024-01-02T03:04:05Z",
                "Config": {"Labels": all_labels},
            },
        )
        return {"Id": f"sha256:{tag}"}

    def pause(self) -> None:
        self._paused = True
        self.attrs["State"]["Status"] = "paused"

    def unpause(self) -> None:
        self._unpaused = True
        self.attrs["State"]["Status"] = "running"

    def start(self) -> None:
        self._started = True
        self.attrs["State"]["Status"] = "running"

    def remove(self, force: bool = False) -> None:
        self._removed = True


class _FakeContainersWithCommit:
    def __init__(self, containers: list[_FakeContainerWithCommit]) -> None:
        self._containers: dict[str, _FakeContainerWithCommit] = {
            c.attrs["Name"].lstrip("/"): c for c in containers
        }

    def list(self, all: bool = False) -> list[_FakeContainerWithCommit]:  # noqa: A002
        return list(self._containers.values())

    def get(self, name: str) -> _FakeContainerWithCommit:
        try:
            return self._containers[name]
        except KeyError:
            from docker.errors import NotFound  # type: ignore[import-untyped]

            raise NotFound(name) from None

    _generated_name_counter = 0

    def run(
        self,
        image: str,
        name: str | None = None,
        detach: bool = False,
        ports: dict[str, Any] | None = None,
        labels: dict[str, str] | None = None,
        init: bool = False,
        extra_hosts: dict[str, str] | None = None,
        devices: list[str] | None = None,
        environment: dict[str, str] | None = None,
    ) -> _FakeContainerWithCommit:
        # When ``name`` is not supplied (the production path), generate a
        # humorous two-word name mimicking Docker's name generator.
        if name is None:
            type(self)._generated_name_counter += 1
            name = f"fakename-{type(self)._generated_name_counter}"
        attrs = _container_attrs(name, image=image)
        attrs["State"]["Status"] = "running"
        attrs["Config"]["Labels"] = labels or {}
        container = _FakeContainerWithCommit(attrs, _FakeImagesWithOps([]))
        self._containers[name] = container
        return container


class _FakeApi:
    """Fake Docker low-level API with commit().

    Holds a reference to the shared images dict so ``commit`` can update the
    re-tagged image with snapshot labels.
    """

    def __init__(self, images: _FakeImagesWithOps) -> None:
        self._images = images
        self._commits: list[dict[str, Any]] = []

    def commit(
        self, image: str, repository: str, tag: str, conf: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        record = {"image": image, "repository": repository, "tag": tag, "conf": conf or {}}
        self._commits.append(record)
        image_tag = f"{repository}:{tag}"
        labels = (conf or {}).get("Labels", {})
        self._images._register(
            image_tag,
            {
                "RepoTags": [image_tag],
                "Created": "2024-01-02T03:04:05Z",
                "Config": {"Labels": dict(labels)},
            },
        )
        return {"Id": f"sha256:{tag}"}


class _FakeSnapshotDockerClient:
    """Fake Docker client supporting images, containers, and api.

    All three subsystems share the same images backing dict so that
    ``container.commit()``, ``images.load()``, and ``api.commit()``
    all register images that ``images.get()`` can find.
    """

    def __init__(
        self,
        images: list[_FakeImageWithOps],
        containers: list[_FakeContainerWithCommit] | None = None,
    ) -> None:
        self.images = _FakeImagesWithOps(images)
        self.containers = _FakeContainersWithCommit(containers or [])
        self.api = _FakeApi(self.images)


def _make_snapshot_service(
    images: list[_FakeImageWithOps],
    containers: list[tuple[str, str]] | None = None,
) -> tuple[DockerSandboxService, _FakeSnapshotDockerClient]:
    """Build a DockerSandboxService with a fake client and wired containers.

    *containers* is a list of ``(name, image)`` tuples; each container is
    wired to the shared images client so ``commit`` registers images.
    """
    client = _FakeSnapshotDockerClient(images)
    for name, image in containers or []:
        container = _FakeContainerWithCommit(_container_attrs(name, image=image), client.images)
        client.containers._containers[name] = container
    service = DockerSandboxService()
    service._client = client
    return service, client


def test_sync_get_snapshot_returns_snapshot() -> None:
    service, _ = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    snapshot = service._sync_get_snapshot("snap-1")
    assert snapshot.id == "snap-1"
    assert snapshot.image_id == "openhands-sandbox-snapshot:snap-1"


def test_sync_get_snapshot_missing_raises_not_found() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_get_snapshot("nope")


def test_sync_get_snapshot_raises_when_image_not_labeled() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("openhands-sandbox-snapshot:snap-x"))]
    )
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_get_snapshot("snap-x")


def test_sync_commit_snapshot_creates_image() -> None:
    service, client = _make_snapshot_service([], [("sb-1", "img-a")])
    snapshot = DockerSandboxSnapshot(
        id="snap-1", image_id="openhands-sandbox-snapshot:snap-1", sandbox_id="sb-1"
    )
    service._sync_commit_snapshot(snapshot)
    container = client.containers.get("sb-1")
    assert len(container._committed) == 1
    assert container._committed[0]["repository"] == "openhands-sandbox-snapshot"
    assert container._committed[0]["tag"] == "snap-1"
    # The committed image is registered so _get_snapshot can find it.
    image = client.images.get("openhands-sandbox-snapshot:snap-1")
    assert image.attrs["Config"]["Labels"]["io.openhands.sandbox.snapshot_id"] == "snap-1"


def test_sync_commit_snapshot_conflict_when_image_exists() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotConflictError

    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_snapshot_image_attrs("snap-1"))],
        [("sb-1", "img-a")],
    )
    snapshot = DockerSandboxSnapshot(
        id="snap-1", image_id="openhands-sandbox-snapshot:snap-1", sandbox_id="sb-1"
    )
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_commit_snapshot(snapshot)


def test_sync_commit_snapshot_raises_when_sandbox_missing() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError

    service, _ = _make_snapshot_service([])
    snapshot = DockerSandboxSnapshot(
        id="snap-1", image_id="openhands-sandbox-snapshot:snap-1", sandbox_id="sb-missing"
    )
    with pytest.raises(SandboxNotFoundError):
        service._sync_commit_snapshot(snapshot)


def test_sync_load_snapshot_imports_file() -> None:
    service, client = _make_snapshot_service([])
    snapshot = DockerSandboxSnapshot(
        id="snap-1", image_id="openhands-sandbox-snapshot:snap-1", sandbox_id=None
    )
    service._sync_load_snapshot(snapshot, b"tarball-bytes")
    assert client.images._loaded_images == [b"tarball-bytes"]
    assert len(client.api._commits) == 1
    assert client.api._commits[0]["repository"] == "openhands-sandbox-snapshot"
    assert client.api._commits[0]["tag"] == "snap-1"
    # The re-committed image is registered with snapshot labels.
    image = client.images.get("openhands-sandbox-snapshot:snap-1")
    assert image.attrs["Config"]["Labels"]["io.openhands.sandbox.snapshot_id"] == "snap-1"


def test_sync_load_snapshot_conflict_when_image_exists() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotConflictError

    service, _ = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    snapshot = DockerSandboxSnapshot(
        id="snap-1", image_id="openhands-sandbox-snapshot:snap-1", sandbox_id=None
    )
    with pytest.raises(SandboxSnapshotConflictError):
        service._sync_load_snapshot(snapshot, b"tarball-bytes")


def test_sync_delete_snapshot_removes_image() -> None:
    service, client = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    service._sync_delete_snapshot("snap-1")
    with pytest.raises(ImageNotFound):
        client.images.get("openhands-sandbox-snapshot:snap-1")


def test_sync_delete_snapshot_missing_raises_not_found() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxSnapshotNotFoundError):
        service._sync_delete_snapshot("nope")


@pytest.mark.asyncio
async def test_async_list_snapshots_returns_all() -> None:
    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2")),
            _FakeImageWithOps(_image_attrs("img-a:latest")),
        ]
    )
    snapshots = await service._list_snapshots()
    assert {s.id for s in snapshots} == {"snap-1", "snap-2"}


@pytest.mark.asyncio
async def test_async_get_snapshot_returns_snapshot() -> None:
    service, _ = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    snapshot = await service._get_snapshot("snap-1")
    assert snapshot.id == "snap-1"


@pytest.mark.asyncio
async def test_snapshot_from_sandbox_builds_model() -> None:
    from openhands.ev2.sandbox.sandbox_models import SandboxStatus

    service = DockerSandboxService()
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img-a",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        snapshot_mode=SnapshotMode.MANUAL,
        session_api_key=None,
        exposed_urls=[],
        status_detail=None,
        volume_mounts=[],
    )
    payload = SandboxSnapshotCreate(sandbox_id="sb-1")
    snapshot = await service._snapshot_from_sandbox(payload, sandbox)
    # Pre-persistence model: id and image_id are assigned during _create_snapshot.
    assert snapshot.id == ""
    assert snapshot.sandbox_id == "sb-1"
    assert snapshot.image_id == ""


@pytest.mark.asyncio
async def test_snapshot_from_file_builds_model() -> None:
    service = DockerSandboxService()
    payload = SandboxSnapshotCreate(file_data=b"tar", schema_type="docker-image-tar")
    snapshot = await service._snapshot_from_file(payload)
    assert snapshot.id == ""
    assert snapshot.sandbox_id is None
    assert snapshot.image_id == ""


@pytest.mark.asyncio
async def test_create_snapshot_from_sandbox_commits() -> None:
    from openhands.ev2.sandbox.sandbox_models import SandboxStatus

    service, client = _make_snapshot_service([], [("sb-1", "img-a")])
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img-a",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        snapshot_mode=SnapshotMode.MANUAL,
        session_api_key=None,
        exposed_urls=[],
        status_detail=None,
        volume_mounts=[],
    )
    payload = SandboxSnapshotCreate(sandbox_id="sb-1")
    snapshot_model = await service._snapshot_from_sandbox(payload, sandbox)
    result = await service._create_snapshot(snapshot_model, payload)
    assert result.id
    assert result.image_id == f"openhands-sandbox-snapshot:{result.id}"
    container = client.containers.get("sb-1")
    assert len(container._committed) == 1
    assert container._committed[0]["tag"] == result.id


@pytest.mark.asyncio
async def test_create_snapshot_from_file_loads() -> None:
    service, client = _make_snapshot_service([])
    payload = SandboxSnapshotCreate(file_data=b"tar", schema_type="docker-image-tar")
    snapshot_model = await service._snapshot_from_file(payload)
    result = await service._create_snapshot(snapshot_model, payload)
    assert result.id
    assert client.images._loaded_images == [b"tar"]


@pytest.mark.asyncio
async def test_delete_snapshot_removes_image() -> None:
    service, client = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    await service._delete_snapshot("snap-1")
    with pytest.raises(ImageNotFound):
        client.images.get("openhands-sandbox-snapshot:snap-1")


@pytest.mark.asyncio
async def test_stream_snapshot_returns_image_save() -> None:
    service, _ = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    fake_image = service._client.images.get("openhands-sandbox-snapshot:snap-1")
    chunks = await service.stream_snapshot("snap-1")
    assert list(chunks) == [b"fake-tarball"]
    assert fake_image._saved


@pytest.mark.asyncio
async def test_service_list_snapshots_filters_by_perm() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotSearchFilter

    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1", sandbox_id="sb-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2", sandbox_id="sb-2")),
        ]
    )
    perm = SandboxSnapshotSearchFilter(sandbox_id__eq="sb-1")
    snapshots = await service.list_snapshots(perm_filter=perm)
    assert [s.id for s in snapshots] == ["snap-1"]


@pytest.mark.asyncio
async def test_service_get_snapshot_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.get_snapshot("nope")


@pytest.mark.asyncio
async def test_service_create_snapshot_from_sandbox() -> None:

    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    payload = SandboxSnapshotCreate(sandbox_id="sb-1")
    snapshot = await service.create_snapshot(payload)
    assert snapshot.id
    assert snapshot.sandbox_id == "sb-1"


@pytest.mark.asyncio
async def test_service_create_snapshot_from_file() -> None:
    service, _ = _make_snapshot_service([])
    payload = SandboxSnapshotCreate(file_data=b"tar", schema_type="docker-image-tar")
    snapshot = await service.create_snapshot(payload)
    assert snapshot.id
    assert snapshot.sandbox_id is None


@pytest.mark.asyncio
async def test_service_delete_snapshot() -> None:
    service, client = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    await service.delete_snapshot("snap-1")
    with pytest.raises(ImageNotFound):
        client.images.get("openhands-sandbox-snapshot:snap-1")


@pytest.mark.asyncio
async def test_service_delete_snapshot_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxSnapshotNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxSnapshotNotFoundError):
        await service.delete_snapshot("nope")


# --------------------------------------------------------------------------- #
# Docker template & sandbox async CRUD (provider hooks).
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_async_list_templates_returns_templates() -> None:
    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("ghcr.io/openhands/agent-canvas:latest"))]
    )
    service.image_name_patterns = ["ghcr.io/openhands/*"]
    templates = await service._list_templates()
    assert [t.id for t in templates] == ["ghcr.io/openhands/agent-canvas:latest"]


@pytest.mark.asyncio
async def test_async_get_template_returns_template() -> None:
    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("ghcr.io/openhands/agent-canvas:latest"))]
    )
    service.image_name_patterns = ["ghcr.io/openhands/*"]
    template = await service._get_template("ghcr.io/openhands/agent-canvas:latest")
    assert template.id == "ghcr.io/openhands/agent-canvas:latest"


@pytest.mark.asyncio
async def test_async_create_template_pulls_image() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxTemplateCreate

    service = DockerSandboxService()
    service._client = _FakeSnapshotDockerClient([])
    payload = SandboxTemplateCreate(id="ghcr.io/openhands/agent-canvas:latest")
    template = service._template_from_create(payload)
    result = await service._create_template(template)
    assert result.id == "ghcr.io/openhands/agent-canvas:latest"


@pytest.mark.asyncio
async def test_async_create_template_conflict_when_exists() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxTemplateCreate
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateConflictError

    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("ghcr.io/openhands/agent-canvas:latest"))]
    )
    payload = SandboxTemplateCreate(id="ghcr.io/openhands/agent-canvas:latest")
    template = service._template_from_create(payload)
    with pytest.raises(SandboxTemplateConflictError):
        await service._create_template(template)


@pytest.mark.asyncio
async def test_async_delete_template_removes_image() -> None:
    service, client = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("ghcr.io/openhands/agent-canvas:latest"))]
    )
    await service._delete_template("ghcr.io/openhands/agent-canvas:latest")
    with pytest.raises(ImageNotFound):
        client.images.get("ghcr.io/openhands/agent-canvas:latest")


@pytest.mark.asyncio
async def test_async_delete_template_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxTemplateNotFoundError):
        await service._delete_template("nope")


@pytest.mark.asyncio
async def test_async_list_sandboxes_returns_sandboxes() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a"), ("sb-2", "img-a")])
    sandboxes = await service._list_sandboxes()
    assert {sb.id for sb in sandboxes} == {"sb-1", "sb-2"}


@pytest.mark.asyncio
async def test_async_get_sandbox_returns_sandbox() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    sandbox = await service._get_sandbox("sb-1")
    assert sandbox.id == "sb-1"


@pytest.mark.asyncio
async def test_async_get_sandbox_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxNotFoundError):
        await service._get_sandbox("nope")


@pytest.mark.asyncio
async def test_async_create_sandbox_creates_container() -> None:
    service, client = _make_snapshot_service([], [])
    sandbox = service._sandbox_from_create(SandboxCreate(sandbox_template_id="img-a"))
    result = await service._create_sandbox(sandbox)
    # The id is generated by the service (Docker container name), not caller-supplied.
    assert result.id != ""
    assert result.sandbox_template_id == "img-a"
    assert result.id in client.containers._containers


@pytest.mark.asyncio
async def test_async_update_sandbox_activates_paused() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "paused"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.ACTIVE))
    assert container._unpaused


@pytest.mark.asyncio
async def test_async_update_sandbox_starts_exited() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "exited"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.ACTIVE))
    assert container._started


@pytest.mark.asyncio
async def test_async_update_sandbox_pauses_running() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    container.attrs["State"]["Status"] = "running"
    await service._update_sandbox("sb-1", SandboxUpdate(desired_status=SandboxStatus.INACTIVE))
    assert container._paused


@pytest.mark.asyncio
async def test_async_update_sandbox_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxNotFoundError):
        await service._update_sandbox("nope", SandboxUpdate(desired_status=SandboxStatus.ACTIVE))


@pytest.mark.asyncio
async def test_async_delete_sandbox_removes_container() -> None:
    service, _ = _make_snapshot_service([], [("sb-1", "img-a")])
    container = service._client.containers.get("sb-1")
    await service._delete_sandbox("sb-1")
    assert container._removed


@pytest.mark.asyncio
async def test_async_delete_sandbox_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxNotFoundError):
        await service._delete_sandbox("nope")


@pytest.mark.asyncio
async def test_sandbox_service_context_manager() -> None:
    service = DockerSandboxService()
    entered = await service.__aenter__()
    assert entered is service
    await service.aclose()
    assert service._client is None


# --------------------------------------------------------------------------- #
# SandboxService snapshot search/count/batch/unsupported coverage.
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_service_search_snapshots_paginates() -> None:
    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-3")),
        ]
    )
    page, next_cursor = await service.search_snapshots(cursor=None, limit=2)
    assert [s.id for s in page] == ["snap-1", "snap-2"]
    assert next_cursor == "snap-2"
    page2, next_cursor2 = await service.search_snapshots(cursor=next_cursor, limit=2)
    assert [s.id for s in page2] == ["snap-3"]
    assert next_cursor2 is None


@pytest.mark.asyncio
async def test_service_search_snapshots_with_search_filter() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotSearchFilter

    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1", sandbox_id="sb-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2", sandbox_id="sb-2")),
        ]
    )
    sf = SandboxSnapshotSearchFilter(sandbox_id__eq="sb-1")
    page, _ = await service.search_snapshots(search_filter=sf)
    assert [s.id for s in page] == ["snap-1"]


@pytest.mark.asyncio
async def test_service_count_snapshots() -> None:
    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2")),
        ]
    )
    total = await service.count_snapshots()
    assert total == 2


@pytest.mark.asyncio
async def test_service_count_snapshots_with_filter() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotSearchFilter

    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1", sandbox_id="sb-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2", sandbox_id="sb-2")),
        ]
    )
    sf = SandboxSnapshotSearchFilter(sandbox_id__eq="sb-1")
    total = await service.count_snapshots(search_filter=sf)
    assert total == 1


@pytest.mark.asyncio
async def test_service_get_snapshots_batch() -> None:
    service, _ = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2")),
        ]
    )
    results = await service.get_snapshots(["snap-1", "nope", "snap-2"])
    assert results[0] is not None
    assert results[0].id == "snap-1"
    assert results[1] is None
    assert results[2] is not None
    assert results[2].id == "snap-2"


@pytest.mark.asyncio
async def test_service_apply_snapshot_batch_deletes() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotBatchDelete
    from openhands.ev2.security.security_models import Action
    from openhands.ev2.util.search_filter import AllSearchFilter

    service, client = _make_snapshot_service(
        [
            _FakeImageWithOps(_snapshot_image_attrs("snap-1")),
            _FakeImageWithOps(_snapshot_image_attrs("snap-2")),
        ]
    )
    ops = [SandboxSnapshotBatchDelete(id="snap-1"), SandboxSnapshotBatchDelete(id="snap-2")]
    perm_filters: dict[Any, Any] = {Action.DELETE: AllSearchFilter()}
    results = await service.apply_snapshot_batch(ops, perm_filters)
    assert results == [None, None]
    with pytest.raises(ImageNotFound):
        client.images.get("openhands-sandbox-snapshot:snap-1")
    with pytest.raises(ImageNotFound):
        client.images.get("openhands-sandbox-snapshot:snap-2")


@pytest.mark.asyncio
async def test_service_apply_snapshot_batch_denied_when_filter_none() -> None:
    from openhands.ev2.sandbox.sandbox_schemas import SandboxSnapshotBatchDelete
    from openhands.ev2.sandbox.sandbox_service import BatchPermissionDeniedError
    from openhands.ev2.security.security_models import Action

    service, _ = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    ops = [SandboxSnapshotBatchDelete(id="snap-1")]
    perm_filters: dict[Any, Any] = {Action.DELETE: None}
    with pytest.raises(BatchPermissionDeniedError):
        await service.apply_snapshot_batch(ops, perm_filters)


@pytest.mark.asyncio
async def test_base_service_snapshot_hooks_raise_unsupported() -> None:
    from openhands.ev2.sandbox.sandbox_service import (
        SandboxNotFoundError,
        SandboxService,
        SandboxSnapshotUnsupportedError,
        SandboxTemplateNotFoundError,
    )

    class _UnsupportedService(SandboxService):
        async def _list_templates(self) -> list[SandboxTemplate]:
            return []

        async def _get_template(self, template_id: str) -> SandboxTemplate:
            raise SandboxTemplateNotFoundError(template_id)

        def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
            raise NotImplementedError

        async def _create_template(self, template: SandboxTemplate) -> SandboxTemplate:
            raise NotImplementedError

        async def _delete_template(self, template_id: str) -> None:
            pass

        async def _list_sandboxes(self) -> list[Sandbox]:
            return []

        async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
            raise SandboxNotFoundError(sandbox_id)

        def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
            raise NotImplementedError

        async def _create_sandbox(self, sandbox: Sandbox) -> Sandbox:
            raise NotImplementedError

        async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
            raise NotImplementedError

        async def _delete_sandbox(self, sandbox_id: str) -> None:
            pass

    service = _UnsupportedService()
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service._list_snapshots()
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service._get_snapshot("x")
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service._snapshot_from_sandbox(
            SandboxSnapshotCreate(sandbox_id="sb"),
            None,  # type: ignore[arg-type]
        )
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service._snapshot_from_file(SandboxSnapshotCreate(file_data=b"", schema_type="t"))
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service._create_snapshot(None, None)  # type: ignore[arg-type]
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service._delete_snapshot("x")
    with pytest.raises(SandboxSnapshotUnsupportedError):
        await service.stream_snapshot("x")


def test_snapshot_router_exception_to_status_mapping() -> None:
    from fastapi import status as http_status

    from openhands.ev2.sandbox.sandbox_service import (
        SandboxSnapshotConflictError,
        SandboxSnapshotNotFoundError,
        SandboxSnapshotPermissionScopeError,
        SandboxSnapshotUnsupportedError,
    )
    from openhands.ev2.sandbox.sandbox_snapshot_router import _map_exception_to_status

    assert _map_exception_to_status(SandboxSnapshotNotFoundError("x")).status_code == 404
    assert _map_exception_to_status(SandboxSnapshotConflictError("x")).status_code == 409
    assert _map_exception_to_status(SandboxSnapshotPermissionScopeError("x")).status_code == 403
    assert (
        _map_exception_to_status(SandboxSnapshotUnsupportedError("x")).status_code
        == http_status.HTTP_501_NOT_IMPLEMENTED
    )
    assert (
        _map_exception_to_status(RuntimeError("boom")).status_code
        == http_status.HTTP_500_INTERNAL_SERVER_ERROR
    )


# --------------------------------------------------------------------------- #
# Edge-case coverage for helpers and sync template error paths.
# --------------------------------------------------------------------------- #


def test_parse_created_invalid_string_returns_now() -> None:
    result = _parse_created("not-a-date")
    assert result.tzinfo is not None


def test_parse_created_non_string_returns_now() -> None:
    result = _parse_created(12345)
    assert result.tzinfo is not None


def test_parse_created_naive_datetime_gets_utc() -> None:
    result = _parse_created("2024-06-01T12:00:00")
    assert result.tzinfo is not None
    assert result.year == 2024


def test_parse_env_skips_entries_without_equals() -> None:
    result = _parse_env(["FOO=bar", "BADENTRY", "BAZ=qux"])
    assert result == {"FOO": "bar", "BAZ": "qux"}


def test_sync_get_template_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_get_template("nope")


def test_sync_get_template_raises_for_snapshot_image() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateNotFoundError

    service, _ = _make_snapshot_service([_FakeImageWithOps(_snapshot_image_attrs("snap-1"))])
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_get_template("openhands-sandbox-snapshot:snap-1")


def test_sync_get_template_raises_when_pattern_mismatch() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateNotFoundError

    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("ghcr.io/openhands/agent-canvas:latest"))]
    )
    service.image_name_patterns = ["docker.io/library/*"]
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_get_template("ghcr.io/openhands/agent-canvas:latest")


def test_sync_create_template_pulls_new_image() -> None:
    service, client = _make_snapshot_service([])
    service._sync_create_template("ghcr.io/openhands/agent-canvas:latest")
    assert "ghcr.io/openhands/agent-canvas:latest" in client.images._images


def test_sync_create_template_conflict_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateConflictError

    service, _ = _make_snapshot_service(
        [_FakeImageWithOps(_image_attrs("ghcr.io/openhands/agent-canvas:latest"))]
    )
    with pytest.raises(SandboxTemplateConflictError):
        service._sync_create_template("ghcr.io/openhands/agent-canvas:latest")


def test_sync_delete_template_not_found_raises() -> None:
    from openhands.ev2.sandbox.sandbox_service import SandboxTemplateNotFoundError

    service, _ = _make_snapshot_service([])
    with pytest.raises(SandboxTemplateNotFoundError):
        service._sync_delete_template("nope")


def test_container_state_handles_reload_exception() -> None:
    from openhands.ev2.sandbox.docker_sandbox_service import _container_state

    class _BadContainer:
        attrs: ClassVar[dict[str, Any]] = {}

        def reload(self) -> None:
            raise RuntimeError("reload failed")

    state = _container_state(_BadContainer())
    assert state == "unknown"


def test_snapshot_create_validation_errors() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        SandboxSnapshotCreate(sandbox_id="sb", file_data=b"tar", schema_type="t")

    with pytest.raises(ValidationError, match="Either sandbox_id or a file"):
        SandboxSnapshotCreate()

    with pytest.raises(ValidationError, match="schema_type is required"):
        SandboxSnapshotCreate(file_data=b"tar")


def test_template_from_image_returns_none_for_untagged() -> None:
    service, _ = _make_snapshot_service([])
    image = _FakeImage({"RepoTags": [], "Config": {"Labels": {}}})
    assert service._template_from_image(image) is None


def test_sandbox_from_container_attrs_returns_none_on_exception() -> None:
    class _ExplodingContainer:
        @property
        def attrs(self) -> dict[str, Any]:
            raise RuntimeError("container removed")

    result = _sandbox_from_container_attrs(_ExplodingContainer(), list(DEFAULT_EXPOSED_PORTS))
    assert result is None


def test_resolve_sandbox_id_uses_name_when_image_matches_pattern() -> None:
    from openhands.ev2.sandbox.docker_sandbox_service import _resolve_sandbox_id

    attrs = {"Name": "/my-container", "Config": {"Labels": {}}}
    result = _resolve_sandbox_id(
        {}, attrs, "ghcr.io/openhands/agent-canvas:latest", ["ghcr.io/openhands/*"]
    )
    assert result == "my-container"


def test_resolve_sandbox_id_returns_none_when_name_empty() -> None:
    from openhands.ev2.sandbox.docker_sandbox_service import _resolve_sandbox_id

    attrs = {"Name": "", "Config": {"Labels": {}}}
    result = _resolve_sandbox_id(
        {}, attrs, "ghcr.io/openhands/agent-canvas:latest", ["ghcr.io/openhands/*"]
    )
    assert result is None


def test_docker_status_to_sandbox_status_edge_cases() -> None:
    from openhands.ev2.sandbox.docker_sandbox_service import _docker_status_to_sandbox_status

    assert _docker_status_to_sandbox_status("created") is SandboxStatus.ACTIVATING
    assert _docker_status_to_sandbox_status("restarting") is SandboxStatus.ACTIVATING
    assert _docker_status_to_sandbox_status("unknown") is SandboxStatus.ERROR


def test_exposed_urls_skips_binding_without_host_port() -> None:
    ports_binding: dict[str, Any] = {"8000/tcp": [{}]}
    result = _exposed_urls_from_ports(list(DEFAULT_EXPOSED_PORTS), ports_binding)
    assert result == []


# --------------------------------------------------------------------------- #
# last_accessed_at + lifecycle sweep.
# --------------------------------------------------------------------------- #


class _MutableContainer:
    """Fake Docker container that records pause/unpause/start/remove and labels."""

    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs
        self.events: list[str] = []

    @property
    def name(self) -> str:
        return self.attrs["Name"].lstrip("/")

    def reload(self) -> None:
        return None

    def pause(self) -> None:
        self.attrs["State"]["Status"] = "paused"
        self.events.append("pause")

    def unpause(self) -> None:
        self.attrs["State"]["Status"] = "running"
        self.events.append("unpause")

    def start(self) -> None:
        self.attrs["State"]["Status"] = "running"
        self.events.append("start")

    def remove(self, force: bool = False) -> None:
        self.events.append("remove")


class _MutableContainers:
    def __init__(self, containers: list[_MutableContainer]) -> None:
        self._containers = {c.name: c for c in containers}

    def list(self, all: bool = False) -> list[_MutableContainer]:  # noqa: A002
        return list(self._containers.values())

    def get(self, name: str) -> _MutableContainer:
        try:
            return self._containers[name]
        except KeyError:
            from docker.errors import NotFound  # type: ignore[import-untyped]

            raise NotFound(name) from None


class _FakeImageObj:
    def __init__(self, attrs: dict[str, Any]) -> None:
        self.attrs = attrs


class _FakeImages:
    def __init__(self, images: list[_FakeImageObj]) -> None:
        self._images = {image.attrs["RepoTags"][0]: image for image in images}

    def list(self) -> list[_FakeImageObj]:
        return list(self._images.values())

    def get(self, name: str) -> _FakeImageObj:
        try:
            return self._images[name]
        except KeyError:
            raise ImageNotFound(name) from None


class _LifecycleClient:
    """Fake Docker client with both ``containers`` and ``images``."""

    def __init__(self, containers: list[_MutableContainer], images: list[_FakeImageObj]) -> None:
        self.containers = _MutableContainers(containers)
        self.images = _FakeImages(images)


def _lifecycle_image_attrs(template_id: str, *, idle_pause: int | None = None) -> dict[str, Any]:
    labels: dict[str, str] = {}
    if idle_pause is not None:
        labels["io.openhands.sandbox.idle_pause_seconds"] = str(idle_pause)
    return {
        "RepoTags": [template_id],
        "Created": "2024-01-02T03:04:05Z",
        "Config": {"Cmd": None, "Env": None, "WorkingDir": None, "Labels": labels},
        "HostConfig": {},
    }


def _lifecycle_container_attrs(
    name: str,
    *,
    template_id: str = "img",
    status: str = "running",
    created: str | None = None,
    paused_at: str | None = None,
    host_port: int = 32771,
) -> dict[str, Any]:
    labels: dict[str, str] = {
        "io.openhands.sandbox.sandbox_id": name,
        "io.openhands.sandbox.sandbox_template_id": template_id,
    }
    if paused_at is not None:
        labels["io.openhands.sandbox.paused_at"] = paused_at
    return {
        "Name": f"/{name}",
        "Created": created or "2024-01-02T03:04:05Z",
        "State": {"Status": status, "Error": None},
        "Config": {"Image": template_id, "Labels": labels},
        "HostConfig": {"Binds": []},
        "NetworkSettings": {"Ports": {"8000/tcp": [{"HostPort": str(host_port)}]}},
    }


def _service_with(client: _LifecycleClient, **fields: Any) -> DockerSandboxService:
    service = DockerSandboxService(
        image_name_patterns=["*"],
        sandbox_lifecycle_interval=0,
        agent_server_probe_timeout=1.0,
        **fields,
    )
    service._client = client
    return service


def test_sandbox_model_last_accessed_at_defaults_none() -> None:
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
    )
    assert sandbox.last_accessed_at is None


def test_sandbox_read_carries_last_accessed_at() -> None:
    accessed = datetime(2024, 6, 5, 12, tzinfo=UTC)
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        last_accessed_at=accessed,
    )
    read = SandboxRead.model_validate(sandbox)
    assert read.last_accessed_at == accessed


def test_sandbox_search_filter_last_accessed_at_gte() -> None:
    cutoff = datetime(2024, 6, 5, 12, tzinfo=UTC)
    young = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        last_accessed_at=datetime(2024, 6, 6, tzinfo=UTC),
    )
    old = DockerSandbox(
        id="sb-2",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        last_accessed_at=datetime(2024, 6, 1, tzinfo=UTC),
    )
    flt = SandboxSearchFilter.model_validate({"last_accessed_at__gte": cutoff})
    assert flt.matches(young)
    assert not flt.matches(old)


@respx.mock
async def test_resolve_last_accessed_at_from_idle_time() -> None:
    service = _service_with(_LifecycleClient([], []))
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        exposed_urls=[ExposedUrl(name="agent_server", url="http://localhost:32771", port=32771)],
    )
    respx.get("http://localhost:32771/").mock(
        return_value=httpx.Response(200, json={"idle_time": 30})
    )
    accessed = await service._resolve_last_accessed_at(sandbox)
    assert accessed is not None
    elapsed = (datetime.now(UTC) - accessed).total_seconds()
    assert 29 <= elapsed <= 31


async def test_resolve_last_accessed_at_none_when_not_active() -> None:
    service = _service_with(_LifecycleClient([], []))
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
        exposed_urls=[ExposedUrl(name="agent_server", url="http://localhost:32771", port=32771)],
    )
    assert await service._resolve_last_accessed_at(sandbox) is None


@respx.mock
async def test_resolve_last_accessed_at_none_on_http_error() -> None:
    service = _service_with(_LifecycleClient([], []))
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        exposed_urls=[ExposedUrl(name="agent_server", url="http://localhost:32771", port=32771)],
    )
    respx.get("http://localhost:32771/").mock(side_effect=httpx.ConnectError("boom"))
    assert await service._resolve_last_accessed_at(sandbox) is None


@respx.mock
async def test_resolve_last_accessed_at_none_when_idle_time_missing() -> None:
    service = _service_with(_LifecycleClient([], []))
    sandbox = DockerSandbox(
        id="sb-1",
        sandbox_template_id="img",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        exposed_urls=[ExposedUrl(name="agent_server", url="http://localhost:32771", port=32771)],
    )
    respx.get("http://localhost:32771/").mock(return_value=httpx.Response(200, json={"other": 1}))
    assert await service._resolve_last_accessed_at(sandbox) is None


@respx.mock
async def test_list_sandboxes_enriches_last_accessed_at() -> None:
    container = _MutableContainer(_lifecycle_container_attrs("sb-1", status="running"))
    image = _FakeImageObj(_lifecycle_image_attrs("img"))
    service = _service_with(_LifecycleClient([container], [image]))
    respx.get("http://localhost:32771/").mock(
        return_value=httpx.Response(200, json={"idle_time": 5})
    )
    sandboxes = await service._list_sandboxes()
    assert len(sandboxes) == 1
    assert sandboxes[0].last_accessed_at is not None


async def test_sweep_pauses_idle_active_sandbox() -> None:
    container = _MutableContainer(_lifecycle_container_attrs("sb-1", status="running"))
    image = _FakeImageObj(_lifecycle_image_attrs("img", idle_pause=10))
    service = _service_with(_LifecycleClient([container], [image]))
    # Pre-seed last_accessed_at so the sandbox is well past idle_pause_seconds.
    sandbox = await service._get_sandbox("sb-1")
    sandbox.last_accessed_at = datetime.now(UTC) - timedelta(seconds=120)

    # _list_sandboxes re-probes; bypass the probe by stubbing it to keep the
    # stale value so the sweep sees the idle sandbox.
    async def _no_probe(sb: DockerSandbox) -> None:
        sb.last_accessed_at = datetime.now(UTC) - timedelta(seconds=120)

    service._enrich_last_accessed_at = _no_probe  # type: ignore[method-assign]
    summary = await service.sweep_lifecycle()
    assert summary is not None
    assert "paused 1" in summary
    assert container.events == ["pause"]
    # paused_at label is stamped.
    assert container.attrs["Config"]["Labels"]["io.openhands.sandbox.paused_at"]


async def test_sweep_skips_active_sandbox_under_idle_threshold() -> None:
    container = _MutableContainer(_lifecycle_container_attrs("sb-1", status="running"))
    image = _FakeImageObj(_lifecycle_image_attrs("img", idle_pause=600))
    service = _service_with(_LifecycleClient([container], [image]))

    async def _fresh(sb: DockerSandbox) -> None:
        sb.last_accessed_at = datetime.now(UTC)

    service._enrich_last_accessed_at = _fresh  # type: ignore[method-assign]
    summary = await service.sweep_lifecycle()
    assert summary is None
    assert container.events == []


async def test_sweep_deletes_paused_sandbox_past_paused_delete() -> None:
    paused_at = (datetime.now(UTC) - timedelta(seconds=600)).isoformat()
    container = _MutableContainer(
        _lifecycle_container_attrs("sb-1", status="paused", paused_at=paused_at)
    )
    image = _FakeImageObj(_lifecycle_image_attrs("img"))
    # paused_delete is a template label; add it.
    image.attrs["Config"]["Labels"]["io.openhands.sandbox.paused_delete_seconds"] = "60"
    service = _service_with(_LifecycleClient([container], [image]))
    summary = await service.sweep_lifecycle()
    assert summary is not None
    assert "deleted 1" in summary
    assert container.events == ["remove"]


async def test_sweep_deletes_sandbox_past_max_age() -> None:
    old_created = (datetime.now(UTC) - timedelta(seconds=3600)).isoformat()
    container = _MutableContainer(
        _lifecycle_container_attrs("sb-1", status="running", created=old_created)
    )
    image = _FakeImageObj(_lifecycle_image_attrs("img"))
    image.attrs["Config"]["Labels"]["io.openhands.sandbox.max_age_seconds"] = "60"
    service = _service_with(_LifecycleClient([container], [image]))
    summary = await service.sweep_lifecycle()
    assert summary is not None
    assert "deleted 1" in summary
    assert container.events == ["remove"]


async def test_sweep_no_op_when_no_thresholds_set() -> None:
    container = _MutableContainer(_lifecycle_container_attrs("sb-1", status="running"))
    image = _FakeImageObj(_lifecycle_image_attrs("img"))
    service = _service_with(_LifecycleClient([container], [image]))
    summary = await service.sweep_lifecycle()
    assert summary is None
    assert container.events == []


async def test_aenter_starts_lifecycle_task() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=1.0)
    service._client = _LifecycleClient([], [])
    async with service:
        assert service._lifecycle_task is not None
        assert not service._lifecycle_task.done()
    assert service._lifecycle_task is None


async def test_aenter_skips_task_when_interval_zero() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=0)
    async with service:
        assert service._lifecycle_task is None


async def test_aclose_cancels_lifecycle_task() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=1.0)
    await service.__aenter__()
    task = service._lifecycle_task
    assert task is not None
    await service.aclose()
    assert task.cancelled()
    assert service._lifecycle_task is None


async def test_aclose_closes_http_client() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=0)
    # Force the lazy http client to be created.
    service._http = httpx.AsyncClient(timeout=1.0)
    await service.aclose()
    assert service._http is None


async def test_lifecycle_loop_runs_one_sweep_then_cancels() -> None:
    service = DockerSandboxService(sandbox_lifecycle_interval=0.01)
    service._client = _LifecycleClient([], [])
    service._start_lifecycle_loop()
    task = service._lifecycle_task
    assert task is not None
    # Let at least one sleep+sweep cycle elapse, then cancel.
    await asyncio.sleep(0.05)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
    assert task.cancelled()


async def test_pause_container_stamps_paused_at_label() -> None:
    container = _MutableContainer(_lifecycle_container_attrs("sb-1", status="running"))
    service = _service_with(_LifecycleClient([container], []))
    service._pause_container(container, "running")
    assert container.attrs["State"]["Status"] == "paused"
    assert "io.openhands.sandbox.paused_at" in container.attrs["Config"]["Labels"]


async def test_activate_container_clears_paused_at_label() -> None:
    paused_at = (datetime.now(UTC) - timedelta(seconds=60)).isoformat()
    container = _MutableContainer(
        _lifecycle_container_attrs("sb-1", status="paused", paused_at=paused_at)
    )
    service = _service_with(_LifecycleClient([container], []))
    service._activate_container(container, "paused")
    assert container.attrs["State"]["Status"] == "running"
    assert "io.openhands.sandbox.paused_at" not in container.attrs["Config"]["Labels"]
