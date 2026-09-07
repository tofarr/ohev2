"""Unit tests for the sandbox grant services (template, resource, snapshot).

All three services share the same code shape; the template service is tested
exhaustively, while the resource and snapshot services get a representative
happy-path + error-path each to guard the FK / unique-constraint wiring.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.sandbox.role_sandbox_permission_schemas import (
    RoleSandboxPermissionBatchCreate,
    RoleSandboxPermissionSearchFilter,
    RoleSandboxPermissionUpdate,
)
from openhands.ev2.sandbox.role_sandbox_permission_service import (
    RoleSandboxPermissionConflictError,
    RoleSandboxPermissionNotFoundError,
    RoleSandboxPermissionOrphanError,
    RoleSandboxPermissionScopeError,
    RoleSandboxPermissionService,
)
from openhands.ev2.sandbox.role_sandbox_snapshot_permission_schemas import (
    RoleSandboxSnapshotPermissionBatchCreate,
    RoleSandboxSnapshotPermissionSearchFilter,
    RoleSandboxSnapshotPermissionUpdate,
)
from openhands.ev2.sandbox.role_sandbox_snapshot_permission_service import (
    RoleSandboxSnapshotPermissionConflictError,
    RoleSandboxSnapshotPermissionNotFoundError,
    RoleSandboxSnapshotPermissionOrphanError,
    RoleSandboxSnapshotPermissionScopeError,
    RoleSandboxSnapshotPermissionService,
)
from openhands.ev2.sandbox.role_sandbox_template_permission_schemas import (
    RoleSandboxTemplatePermissionBatchCreate,
    RoleSandboxTemplatePermissionSearchFilter,
    RoleSandboxTemplatePermissionUpdate,
)
from openhands.ev2.sandbox.role_sandbox_template_permission_service import (
    BatchPermissionDeniedError as TemplateBatchPermissionDeniedError,
)
from openhands.ev2.sandbox.role_sandbox_template_permission_service import (
    RoleSandboxTemplatePermissionConflictError,
    RoleSandboxTemplatePermissionNotFoundError,
    RoleSandboxTemplatePermissionOrphanError,
    RoleSandboxTemplatePermissionScopeError,
    RoleSandboxTemplatePermissionService,
)
from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxTemplateSpec,
    FuseySandboxStorageSpec,
    OpenHandsAgentServerSpec,
    Sandbox,
    SandboxFilesystem,
    SandboxFilesystemStatus,
    SandboxSnapshot,
    SandboxSnapshotStatus,
    SandboxStatus,
    SandboxTemplate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL, NONE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_template(session: AsyncSession, *, n: int = 0) -> SandboxTemplate:
    user = User(email=f"t{n}@e.com", username=f"tu{n}")
    session.add(user)
    await session.flush()
    tpl = SandboxTemplate(
        name=f"tpl-{n}-{uuid.uuid4().hex[:4]}",
        provider_kind="docker",
        template_spec=DockerSandboxTemplateSpec(image="img"),
        server_spec=OpenHandsAgentServerSpec(internal_port=18000),
        storage_spec=FuseySandboxStorageSpec(mount_path="/ws"),
        user_id=user.id,
    )
    session.add(tpl)
    await session.flush()
    return tpl


async def _seed_sandbox(session: AsyncSession, *, n: int = 0) -> Sandbox:
    tpl = await _seed_template(session, n=n)
    fs = SandboxFilesystem(
        storage_kind="fusey",
        object_prefix=f"obj-{n}-{uuid.uuid4().hex[:6]}",
        user_id=tpl.user_id,
        status=SandboxFilesystemStatus.READY,
    )
    session.add(fs)
    await session.flush()
    sb = Sandbox(
        name=f"sb-{n}-{uuid.uuid4().hex[:4]}",
        template_id=tpl.id,
        filesystem_id=fs.id,
        provider_kind="docker",
        user_id=tpl.user_id,
        status=SandboxStatus.INACTIVE,
    )
    session.add(sb)
    await session.flush()
    return sb


async def _seed_snapshot(session: AsyncSession, *, n: int = 0) -> SandboxSnapshot:
    sb = await _seed_sandbox(session, n=n)
    from openhands.ev2.sandbox.sandbox_models import (
        FuseySandboxSnapshotArtifact,
        SandboxStorageKind,
    )

    snap = SandboxSnapshot(
        name=f"snap-{n}-{uuid.uuid4().hex[:4]}",
        filesystem_id=sb.filesystem_id,
        storage_kind=SandboxStorageKind.FUSEY,
        generation=f"gen-{n}",
        snapshot_artifact=FuseySandboxSnapshotArtifact(
            filesystem_id=sb.filesystem_id, generation=f"gen-{n}"
        ),
        user_id=sb.user_id,
        status=SandboxSnapshotStatus.READY,
    )
    session.add(snap)
    await session.flush()
    return snap


async def _seed_role(session: AsyncSession, *, n: int = 0) -> Role:
    role = Role(name=f"role-{n}-{uuid.uuid4().hex[:4]}")
    session.add(role)
    await session.flush()
    return role


# ---------------------------------------------------------------------------
# Template permission service
# ---------------------------------------------------------------------------


class TestTemplateCreateGrant:
    async def test_create_defaults(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        assert isinstance(link.id, uuid.UUID)
        assert link.role_id == role.id
        assert link.sandbox_template_id == tpl.id
        assert link.read_enabled is False
        assert link.update_enabled is False
        assert link.delete_enabled is False

    async def test_create_with_flags(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(
            role_id=role.id,
            sandbox_template_id=tpl.id,
            read_enabled=True,
            delete_enabled=True,
        )
        assert link.read_enabled is True
        assert link.delete_enabled is True
        assert link.update_enabled is False

    async def test_create_duplicate_pair_conflicts(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        with pytest.raises(RoleSandboxTemplatePermissionConflictError):
            await svc.create(role_id=role.id, sandbox_template_id=tpl.id)

    async def test_create_orphan_role_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        tpl = await _seed_template(session)
        with pytest.raises(RoleSandboxTemplatePermissionOrphanError):
            await svc.create(role_id=uuid.uuid4(), sandbox_template_id=tpl.id)

    async def test_create_orphan_template_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        with pytest.raises(RoleSandboxTemplatePermissionOrphanError):
            await svc.create(role_id=role.id, sandbox_template_id=uuid.uuid4())


class TestTemplateUpdateGrant:
    async def test_update_toggles_flags(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        updated = await svc.update(
            link.id,
            RoleSandboxTemplatePermissionUpdate(read_enabled=True, update_enabled=True),
        )
        assert updated.read_enabled is True
        assert updated.update_enabled is True
        assert updated.delete_enabled is False

    async def test_update_missing_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.update(uuid.uuid4(), RoleSandboxTemplatePermissionUpdate(read_enabled=True))


class TestTemplateDeleteGrant:
    async def test_delete_removes(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        await svc.delete(link.id)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.get(link.id)

    async def test_delete_missing_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.delete(uuid.uuid4())


class TestTemplateSearchGrant:
    async def test_search_filters_by_role(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        await svc.create(role_id=role.id, sandbox_template_id=tpl.id, read_enabled=True)
        links, _ = await svc.search_role_sandbox_template_permissions(
            search_filter=RoleSandboxTemplatePermissionSearchFilter(role_id__eq=role.id)
        )
        assert len(links) == 1
        assert links[0].read_enabled is True

    async def test_count(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        assert await svc.count() >= 1


class TestTemplateGetMany:
    async def test_get_many_aligned_with_nulls(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        missing = uuid.uuid4()
        results = await svc.get_many([link.id, missing])
        assert results[0] is not None and results[0].id == link.id
        assert results[1] is None

    async def test_get_many_empty(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        assert await svc.get_many([]) == []


class TestTemplateScopeError:
    async def test_create_denied_by_scope(self, session: AsyncSession) -> None:
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        svc = RoleSandboxTemplatePermissionService(session, NONE)
        with pytest.raises(RoleSandboxTemplatePermissionScopeError):
            await svc.create(role_id=role.id, sandbox_template_id=tpl.id)


class TestTemplateBatch:
    async def test_batch_create_update_delete(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        role2 = await _seed_role(session, n=1)
        tpl2 = await _seed_template(session, n=1)
        await session.flush()
        results = await svc.apply_batch(
            [
                RoleSandboxTemplatePermissionBatchCreate(
                    data={
                        "role_id": role.id,
                        "sandbox_template_id": tpl.id,
                        "read_enabled": True,
                    }
                ),
                RoleSandboxTemplatePermissionBatchCreate(
                    data={"role_id": role2.id, "sandbox_template_id": tpl2.id}
                ),
            ],
            {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
        )
        assert len(results) == 2
        assert results[0].read_enabled is True
        assert results[1] is not None

    async def test_batch_denied_when_action_filter_none(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        with pytest.raises(TemplateBatchPermissionDeniedError):
            await svc.apply_batch(
                [
                    RoleSandboxTemplatePermissionBatchCreate(
                        data={"role_id": role.id, "sandbox_template_id": tpl.id}
                    ),
                ],
                {Action.CREATE: None, Action.UPDATE: None, Action.DELETE: None},
            )


# ---------------------------------------------------------------------------
# Sandbox (resource) permission service — representative tests
# ---------------------------------------------------------------------------


class TestSandboxGrantService:
    async def test_create_and_get(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        link = await svc.create(role_id=role.id, sandbox_id=sb.id, read_enabled=True)
        assert link.read_enabled is True
        got = await svc.get(link.id)
        assert got.id == link.id

    async def test_create_duplicate_conflicts(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        await svc.create(role_id=role.id, sandbox_id=sb.id)
        with pytest.raises(RoleSandboxPermissionConflictError):
            await svc.create(role_id=role.id, sandbox_id=sb.id)

    async def test_create_orphan_sandbox_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        with pytest.raises(RoleSandboxPermissionOrphanError):
            await svc.create(role_id=role.id, sandbox_id=uuid.uuid4())

    async def test_update_and_delete(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        link = await svc.create(role_id=role.id, sandbox_id=sb.id)
        updated = await svc.update(link.id, RoleSandboxPermissionUpdate(update_enabled=True))
        assert updated.update_enabled is True
        await svc.delete(link.id)
        with pytest.raises(RoleSandboxPermissionNotFoundError):
            await svc.get(link.id)

    async def test_search_and_count(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        await svc.create(role_id=role.id, sandbox_id=sb.id, read_enabled=True)
        links, _ = await svc.search_role_sandbox_permissions(
            search_filter=RoleSandboxPermissionSearchFilter(role_id__eq=role.id)
        )
        assert len(links) == 1
        assert await svc.count() >= 1

    async def test_get_many(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        link = await svc.create(role_id=role.id, sandbox_id=sb.id)
        results = await svc.get_many([link.id, uuid.uuid4()])
        assert results[0] is not None and results[0].id == link.id
        assert results[1] is None

    async def test_batch(self, session: AsyncSession) -> None:
        svc = RoleSandboxPermissionService(session)
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        results = await svc.apply_batch(
            [
                RoleSandboxPermissionBatchCreate(
                    data={"role_id": role.id, "sandbox_id": sb.id, "read_enabled": True}
                ),
            ],
            {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
        )
        assert len(results) == 1
        assert results[0].read_enabled is True

    async def test_scope_error(self, session: AsyncSession) -> None:
        role = await _seed_role(session)
        sb = await _seed_sandbox(session)
        svc = RoleSandboxPermissionService(session, NONE)
        with pytest.raises(RoleSandboxPermissionScopeError):
            await svc.create(role_id=role.id, sandbox_id=sb.id)


# ---------------------------------------------------------------------------
# Sandbox snapshot permission service — representative tests
# ---------------------------------------------------------------------------


class TestSnapshotGrantService:
    async def test_create_and_get(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        link = await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id, delete_enabled=True)
        assert link.delete_enabled is True
        got = await svc.get(link.id)
        assert got.id == link.id

    async def test_create_duplicate_conflicts(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id)
        with pytest.raises(RoleSandboxSnapshotPermissionConflictError):
            await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id)

    async def test_create_orphan_snapshot_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        with pytest.raises(RoleSandboxSnapshotPermissionOrphanError):
            await svc.create(role_id=role.id, sandbox_snapshot_id=uuid.uuid4())

    async def test_update_and_delete(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        link = await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id)
        updated = await svc.update(link.id, RoleSandboxSnapshotPermissionUpdate(read_enabled=True))
        assert updated.read_enabled is True
        await svc.delete(link.id)
        with pytest.raises(RoleSandboxSnapshotPermissionNotFoundError):
            await svc.get(link.id)

    async def test_search_and_count(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id, read_enabled=True)
        links, _ = await svc.search_role_sandbox_snapshot_permissions(
            search_filter=RoleSandboxSnapshotPermissionSearchFilter(role_id__eq=role.id)
        )
        assert len(links) == 1
        assert await svc.count() >= 1

    async def test_get_many(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        link = await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id)
        results = await svc.get_many([link.id, uuid.uuid4()])
        assert results[0] is not None and results[0].id == link.id
        assert results[1] is None

    async def test_batch(self, session: AsyncSession) -> None:
        svc = RoleSandboxSnapshotPermissionService(session)
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        results = await svc.apply_batch(
            [
                RoleSandboxSnapshotPermissionBatchCreate(
                    data={
                        "role_id": role.id,
                        "sandbox_snapshot_id": snap.id,
                        "delete_enabled": True,
                    }
                ),
            ],
            {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
        )
        assert len(results) == 1
        assert results[0].delete_enabled is True

    async def test_scope_error(self, session: AsyncSession) -> None:
        role = await _seed_role(session)
        snap = await _seed_snapshot(session)
        svc = RoleSandboxSnapshotPermissionService(session, NONE)
        with pytest.raises(RoleSandboxSnapshotPermissionScopeError):
            await svc.create(role_id=role.id, sandbox_snapshot_id=snap.id)
