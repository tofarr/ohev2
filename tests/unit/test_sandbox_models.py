"""Tests for sandbox polymorphic model payloads."""

from __future__ import annotations

import uuid

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
    SandboxTemplateSpec,
)


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
