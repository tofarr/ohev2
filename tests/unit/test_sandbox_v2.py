"""Tests for the pluggable sandbox_v2 control plane.

Covers the pieces that do not require a live Docker daemon or database: the
template model/schemas, the Docker Image attribute mapping helpers, and the
service factory/config wiring.
"""

from __future__ import annotations

from typing import Any

import pytest
from docker.errors import ImageNotFound  # type: ignore[import-untyped]
from pydantic import ValidationError

from openhands.ev2.sandbox_v2.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox_v2.docker_sandbox_service import (
    DEFAULT_EXPOSED_PORTS,
    DockerSandboxService,
    _docker_template_from_payload,
    _exposed_urls_from_ports,
    _label_int,
    _parse_created,
    _parse_env,
    _sandbox_from_container_attrs,
    _template_from_image_attrs,
    _volume_mounts_from_binds,
    _wildcard_match,
)
from openhands.ev2.sandbox_v2.sandbox_v2_models import (
    DockerSandboxTemplate,
    ExposedPort,
    ExposedUrl,
    Sandbox,
    SandboxStatus,
    SandboxTemplate,
    VolumeMount,
)
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxCreate,
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxUpdate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_service import (
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
        sandbox_spec_id="img:latest",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
        session_api_key="key",
        exposed_urls=[ExposedUrl(name="agent_server", url="http://localhost:8001", port=8001)],
        volume_mounts=[VolumeMount(host_path="/h", container_path="/c")],
    )
    restored = Sandbox.model_validate(sandbox.model_dump(mode="json"))
    assert isinstance(restored, DockerSandbox)
    assert restored.id == "sb-1"
    assert restored.sandbox_spec_id == "img:latest"
    assert restored.status is SandboxStatus.ACTIVE
    assert restored.session_api_key == "key"
    assert restored.exposed_urls[0].name == "agent_server"
    assert restored.volume_mounts[0].host_path == "/h"


def test_sandbox_defaults() -> None:
    sandbox = DockerSandbox(
        id="sb",
        sandbox_spec_id="img",
        status=SandboxStatus.INACTIVE,
        desired_status=SandboxStatus.INACTIVE,
    )
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
    create = SandboxCreate.model_validate({"id": "sb", "sandbox_spec_id": "img"})
    assert create.id == "sb"
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
                "io.openhands.sandbox_v2.idle_pause_seconds": "120",
                "io.openhands.sandbox_v2.max_age_seconds": "3600",
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
    from openhands.ev2.sandbox_v2.sandbox_v2_service import (
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
    from openhands.ev2.sandbox_v2.sandbox_v2_service import (
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
        "openhands.ev2.sandbox_v2.docker_sandbox_service.DockerSandboxService"
    )
    assert cls is DockerSandboxService


def test_resolve_rejects_non_service() -> None:
    with pytest.raises(TypeError):
        resolve_sandbox_service_class("openhands.ev2.sandbox_v2.sandbox_v2_service.SandboxTemplate")


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

    from openhands.ev2.sandbox_v2.sandbox_template_router import _map_exception_to_status
    from openhands.ev2.sandbox_v2.sandbox_v2_service import (
        BatchPermissionDeniedError,
        SandboxTemplateConflictError,
        SandboxTemplateNotFoundError,
        SandboxTemplatePermissionScopeError,
    )

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

    from openhands.ev2.sandbox_v2.sandbox_router import _map_exception_to_status
    from openhands.ev2.sandbox_v2.sandbox_v2_service import (
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
                "io.openhands.sandbox_v2.sandbox_id": name,
                "io.openhands.sandbox_v2.sandbox_spec_id": image,
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
    assert sandbox.sandbox_spec_id == "img"
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
    from openhands.ev2.sandbox_v2.sandbox_v2_service import SandboxNotFoundError

    service = DockerSandboxService()
    service._client = _FakeContainerClient([])
    with pytest.raises(SandboxNotFoundError):
        service._sync_get_sandbox("nope")


def test_sync_get_sandbox_unlabeled_raises_not_found() -> None:
    from openhands.ev2.sandbox_v2.sandbox_v2_service import SandboxNotFoundError

    service = DockerSandboxService()
    attrs = _container_attrs("anon", status="running")
    attrs["Config"]["Labels"] = {}
    service._client = _FakeContainerClient([_FakeContainer(attrs)])
    with pytest.raises(SandboxNotFoundError):
        service._sync_get_sandbox("anon")
