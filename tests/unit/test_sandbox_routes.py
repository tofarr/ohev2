"""Route tests for sandbox templates, sandboxes, and snapshots."""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import (
    Sandbox,
    SandboxCompute,
    SandboxComputeStatus,
    SandboxFilesystem,
    SandboxFilesystemStatus,
    SandboxStatus,
)


def _template_payload(name: str = "docker-template") -> dict[str, object]:
    return {
        "name": name,
        "provider_kind": "docker",
        "description": "Template for Docker-backed Fusey sandboxes.",
        "idle_timeout_seconds": 60,
        "max_lifetime_seconds": None,
        "template_spec": {
            "kind": "DockerSandboxTemplateSpec",
            "provider_kind": "docker",
            "image": "ghcr.io/openhands/agent-server:latest",
            "ports": [{"name": "web", "port": 18000, "protocol": "http"}],
        },
        "server_spec": {
            "kind": "OpenHandsAgentServerSpec",
            "server_kind": "openhands_agent_server",
            "internal_port": 18000,
        },
        "storage_spec": {
            "kind": "FuseySandboxStorageSpec",
            "storage_kind": "fusey",
            "mount_path": "/workspace",
        },
    }


async def test_template_create_and_search(client: AsyncClient) -> None:
    created = await client.post("/sandbox-templates", json=_template_payload())
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["provider_kind"] == "docker"
    assert body["template_spec"]["kind"] == "DockerSandboxTemplateSpec"
    assert body["storage_spec"]["kind"] == "FuseySandboxStorageSpec"

    listed = await client.get("/sandbox-templates")
    assert listed.status_code == 200, listed.text
    assert [item["id"] for item in listed.json()["items"]] == [body["id"]]


async def test_sandbox_lifecycle_and_snapshot_routes(
    client: AsyncClient,
    session: AsyncSession,
) -> None:
    template_response = await client.post("/sandbox-templates", json=_template_payload())
    assert template_response.status_code == 201, template_response.text
    template_id = template_response.json()["id"]

    create_response = await client.post(
        "/sandboxes",
        json={
            "name": "dev-sandbox",
            "template_id": template_id,
            "idle_timeout_seconds": 30,
            "max_lifetime_seconds": None,
        },
    )
    assert create_response.status_code == 201, create_response.text
    sandbox = create_response.json()
    assert sandbox["status"] == "inactive"
    assert sandbox["current_snapshot_id"] is None

    filesystem = await session.get(SandboxFilesystem, sandbox["filesystem_id"])
    assert filesystem is not None
    assert filesystem.status == SandboxFilesystemStatus.READY
    assert filesystem.object_prefix.startswith("sandbox-filesystems/")

    activate_response = await client.post(f"/sandboxes/{sandbox['id']}/activate")
    assert activate_response.status_code == 200, activate_response.text
    active = activate_response.json()
    assert active["status"] == "active"

    db_sandbox = await session.get(Sandbox, sandbox["id"])
    assert db_sandbox is not None
    assert db_sandbox.status == SandboxStatus.ACTIVE
    assert db_sandbox.current_compute_id is not None
    compute = await session.get(SandboxCompute, db_sandbox.current_compute_id)
    assert compute is not None
    assert compute.status == SandboxComputeStatus.SERVING

    snapshot_response = await client.post(
        "/sandbox-snapshots",
        json={
            "name": "before-change",
            "source_sandbox_id": sandbox["id"],
            "generation": "generation-1",
        },
    )
    assert snapshot_response.status_code == 201, snapshot_response.text
    snapshot = snapshot_response.json()
    assert snapshot["generation"] == "generation-1"
    assert snapshot["snapshot_artifact"]["kind"] == "FuseySandboxSnapshotArtifact"

    await session.refresh(db_sandbox)
    assert str(db_sandbox.current_snapshot_id) == snapshot["id"]

    deactivate_response = await client.post(f"/sandboxes/{sandbox['id']}/deactivate")
    assert deactivate_response.status_code == 200, deactivate_response.text
    inactive = deactivate_response.json()
    assert inactive["status"] == "inactive"

    await session.refresh(db_sandbox)
    assert db_sandbox.current_compute_id is None

    await session.refresh(compute)
    assert compute.status == SandboxComputeStatus.RELEASED


async def test_activate_conflict_from_active_state(client: AsyncClient) -> None:
    template_response = await client.post("/sandbox-templates", json=_template_payload("conflict"))
    assert template_response.status_code == 201, template_response.text
    sandbox_response = await client.post(
        "/sandboxes",
        json={"name": "conflict-sandbox", "template_id": template_response.json()["id"]},
    )
    assert sandbox_response.status_code == 201, sandbox_response.text
    sandbox_id = sandbox_response.json()["id"]

    first = await client.post(f"/sandboxes/{sandbox_id}/activate")
    assert first.status_code == 200, first.text
    second = await client.post(f"/sandboxes/{sandbox_id}/activate")
    assert second.status_code == 409, second.text
