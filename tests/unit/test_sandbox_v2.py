"""Tests for the pluggable sandbox_v2 control plane.

Covers the pieces that do not require a live Docker daemon or database: the
template model/schemas, the Docker Image attribute mapping helpers, and the
service factory/config wiring.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from openhands.ev2.sandbox_v2.docker_sandbox_service import (
    DockerSandboxService,
    _apply_template_update,
    _docker_template_from_payload,
    _label_int,
    _parse_created,
    _parse_env,
    _template_from_image_attrs,
)
from openhands.ev2.sandbox_v2.sandbox_v2_models import (
    DockerSandboxTemplate,
    SandboxTemplate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxTemplateUpdate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_service import (
    SandboxService,
    build_sandbox_service,
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
    assert template.kind == "DockerSandboxTemplate"


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


def test_create_payload_rejects_non_positive_timeouts() -> None:
    with pytest.raises(ValidationError):
        SandboxTemplateCreate.model_validate({"id": "img", "idle_pause_seconds": 0})
    with pytest.raises(ValidationError):
        SandboxTemplateCreate.model_validate({"id": "img", "max_age_seconds": -1})


def test_update_payload_all_fields_optional() -> None:
    payload = SandboxTemplateUpdate.model_validate({})
    assert payload.command is None
    assert payload.working_dir is None


def test_read_model_from_template() -> None:
    template = DockerSandboxTemplate(id="img", idle_pause_seconds=30, max_memory=2048)
    read = SandboxTemplateRead.model_validate(template)
    assert read.id == "img"
    assert read.idle_pause_seconds == 30
    assert read.max_memory == 2048
    assert read.created_at == template.created_at


# --------------------------------------------------------------------------- #
# Docker Image attribute mapping.
# --------------------------------------------------------------------------- #


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
    template = _template_from_image_attrs(attrs)
    assert isinstance(template, DockerSandboxTemplate)
    assert template.id == "ghcr.io/org/agent-server:latest"
    assert template.command == ["bash", "-c", "sleep infinity"]
    assert template.initial_env == {"A": "1", "B": "two"}
    assert template.working_dir == "/workspace"
    assert template.idle_pause_seconds == 120
    assert template.paused_delete_seconds is None
    assert template.max_age_seconds == 3600
    assert template.max_memory == 1073741824


def test_template_from_image_attrs_untagged_is_not_template() -> None:
    from openhands.ev2.sandbox_v2.sandbox_v2_service import (
        SandboxTemplateNotFoundError,
    )

    with pytest.raises(SandboxTemplateNotFoundError):
        _template_from_image_attrs({"RepoTags": ["<none>:<none>"]})


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
    template = _docker_template_from_payload(payload)
    assert isinstance(template, DockerSandboxTemplate)
    assert template.id == "img"
    assert template.command == ["echo", "hi"]
    assert template.initial_env == {"K": "v"}
    assert template.working_dir == "/app"
    assert template.idle_pause_seconds == 10
    assert template.max_memory == 512


def test_apply_template_update_partial() -> None:
    original = DockerSandboxTemplate(
        id="img",
        command=["a"],
        initial_env={"A": "1"},
        working_dir="/ws",
        idle_pause_seconds=10,
        paused_delete_seconds=20,
        max_age_seconds=30,
        max_memory=40,
    )
    updated = _apply_template_update(
        original,
        SandboxTemplateUpdate.model_validate({"idle_pause_seconds": 99}),
    )
    assert updated.id == "img"
    assert updated.command == ["a"]
    assert updated.initial_env == {"A": "1"}
    assert updated.working_dir == "/ws"
    assert updated.idle_pause_seconds == 99
    assert updated.paused_delete_seconds == 20
    assert updated.max_age_seconds == 30
    assert updated.max_memory == 40


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
    service = build_sandbox_service(
        "openhands.ev2.sandbox_v2.docker_sandbox_service.DockerSandboxService"
    )
    assert isinstance(service, DockerSandboxService)
    assert isinstance(service, SandboxService)


def test_config_default_sandbox_service(monkeypatch: pytest.MonkeyPatch) -> None:
    from openhands.ev2.config import get_config

    get_config.cache_clear()
    monkeypatch.setenv("OHE_ENCRYPTION_KEY_VALUE", "test-secret-at-least-32-bytes-long!!")
    config = get_config()
    assert "DockerSandboxService" in config.sandbox_service


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
