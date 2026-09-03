"""Tests for sandbox polymorphic model payloads."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxRuntimeState,
    DockerSandboxTemplateSpec,
    FuseySandboxSnapshotArtifact,
    FuseySandboxStorageSpec,
    OpenHandsAgentServerSpec,
    SandboxRuntimeState,
    SandboxServerSpec,
    SandboxSnapshotArtifact,
    SandboxStorageSpec,
    SandboxTemplate,
    SandboxTemplateSpec,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxTemplateCreate,
    SandboxTemplateUpdate,
)
from openhands.ev2.sandbox.sandbox_service import (
    SandboxTemplatePermissionScopeError,
    SandboxTemplateService,
)
from openhands.ev2.util.search_filter import NoneSearchFilter


def test_sandbox_template_spec_round_trip() -> None:
    spec = DockerSandboxTemplateSpec(image="ghcr.io/openhands/agent-server:latest")
    data = spec.model_dump(mode="json")

    restored = SandboxTemplateSpec.model_validate(data)

    assert isinstance(restored, DockerSandboxTemplateSpec)
    assert restored.kind == "DockerSandboxTemplateSpec"
    assert restored.provider_kind == "docker"


def test_server_and_storage_specs_round_trip() -> None:
    server = OpenHandsAgentServerSpec(internal_port=18000)
    storage = FuseySandboxStorageSpec(mount_path="/workspace")

    restored_server = SandboxServerSpec.model_validate(server.model_dump(mode="json"))
    restored_storage = SandboxStorageSpec.model_validate(storage.model_dump(mode="json"))

    assert isinstance(restored_server, OpenHandsAgentServerSpec)
    assert restored_server.kind == "OpenHandsAgentServerSpec"
    assert isinstance(restored_storage, FuseySandboxStorageSpec)
    assert restored_storage.kind == "FuseySandboxStorageSpec"


def test_runtime_and_snapshot_artifacts_round_trip() -> None:
    filesystem_id = uuid.uuid4()
    runtime = DockerSandboxRuntimeState(container_id="container-1")
    artifact = FuseySandboxSnapshotArtifact(
        filesystem_id=filesystem_id,
        generation="generation-1",
    )

    restored_runtime = SandboxRuntimeState.model_validate(runtime.model_dump(mode="json"))
    restored_artifact = SandboxSnapshotArtifact.model_validate(artifact.model_dump(mode="json"))

    assert isinstance(restored_runtime, DockerSandboxRuntimeState)
    assert restored_runtime.kind == "DockerSandboxRuntimeState"
    assert isinstance(restored_artifact, FuseySandboxSnapshotArtifact)
    assert restored_artifact.filesystem_id == filesystem_id


def test_template_create_rejects_non_docker_provider() -> None:
    with pytest.raises(ValidationError):
        SandboxTemplateCreate.model_validate(
            {
                "name": "bad",
                "provider_kind": "kubernetes",
                "template_spec": {
                    "kind": "DockerSandboxTemplateSpec",
                    "provider_kind": "docker",
                    "image": "img",
                },
                "storage_spec": {
                    "kind": "FuseySandboxStorageSpec",
                    "storage_kind": "fusey",
                    "mount_path": "/ws",
                },
            }
        )


def test_template_create_rejects_non_fusey_storage() -> None:
    with pytest.raises(ValidationError):
        SandboxTemplateCreate.model_validate(
            {
                "name": "bad",
                "provider_kind": "docker",
                "template_spec": {
                    "kind": "DockerSandboxTemplateSpec",
                    "provider_kind": "docker",
                    "image": "img",
                },
                "storage_spec": {
                    "kind": "OtherStorage",
                    "storage_kind": "other",
                },
            }
        )


def test_template_update_rejects_non_docker_spec() -> None:
    with pytest.raises(ValidationError):
        SandboxTemplateUpdate.model_validate(
            {"template_spec": {"kind": "OtherSpec", "provider_kind": "other"}}
        )


def test_template_update_rejects_non_fusey_storage() -> None:
    with pytest.raises(ValidationError):
        SandboxTemplateUpdate.model_validate(
            {"storage_spec": {"kind": "OtherStorage", "storage_kind": "other"}}
        )


async def test_template_create_permission_scope_error(session: AsyncSession) -> None:
    empty_filter = NoneSearchFilter[SandboxTemplate]()
    svc = SandboxTemplateService(session, empty_filter)
    with pytest.raises(SandboxTemplatePermissionScopeError):
        await svc.create(
            SandboxTemplateCreate(
                name="denied",
                template_spec=DockerSandboxTemplateSpec(image="img"),
                storage_spec=FuseySandboxStorageSpec(mount_path="/ws"),
            ),
            user_id=uuid.uuid4(),
        )
