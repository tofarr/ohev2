"""Unit tests for the ``sandbox_v2`` role-sandbox-template-permission service.

The ``sandbox_v2.role_sandbox_template_permission_service`` module is the
sandbox_v2 successor of ``sandbox.role_sandbox_template_permission_service``;
it backs the same ``role_sandbox_template_permissions`` link table but is
wired to the sandbox_v2 schemas. These tests mirror the exhaustive template
service coverage in ``test_role_sandbox_permission_service.py`` against the
new module so the import graph (and therefore the coverage) is exercised
through the sandbox_v2 package.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxTemplateSpec,
    FuseySandboxStorageSpec,
    OpenHandsAgentServerSpec,
    SandboxTemplate,
)
from openhands.ev2.sandbox_v2.role_sandbox_template_permission_schemas import (
    RoleSandboxTemplatePermissionBatchCreate,
    RoleSandboxTemplatePermissionBatchDelete,
    RoleSandboxTemplatePermissionBatchUpdate,
    RoleSandboxTemplatePermissionSearchFilter,
    RoleSandboxTemplatePermissionUpdate,
)
from openhands.ev2.sandbox_v2.role_sandbox_template_permission_service import (
    BatchPermissionDeniedError,
    RoleSandboxTemplatePermissionConflictError,
    RoleSandboxTemplatePermissionNotFoundError,
    RoleSandboxTemplatePermissionOrphanError,
    RoleSandboxTemplatePermissionScopeError,
    RoleSandboxTemplatePermissionService,
    _classify_integrity_error,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL, NONE

# --------------------------------------------------------------------------- #
# Seed helpers (shared with the sandbox-package service tests in shape).
# --------------------------------------------------------------------------- #


async def _seed_template(session: AsyncSession, *, n: int = 0) -> SandboxTemplate:
    user = User(email=f"v2-{n}@e.com", username=f"v2u{n}")
    session.add(user)
    await session.flush()
    tpl = SandboxTemplate(
        name=f"v2-tpl-{n}-{uuid.uuid4().hex[:4]}",
        provider_kind="docker",
        template_spec=DockerSandboxTemplateSpec(image="img"),
        server_spec=OpenHandsAgentServerSpec(internal_port=18000),
        storage_spec=FuseySandboxStorageSpec(mount_path="/ws"),
        user_id=user.id,
    )
    session.add(tpl)
    await session.flush()
    return tpl


async def _seed_role(session: AsyncSession, *, n: int = 0) -> Role:
    role = Role(name=f"v2-role-{n}-{uuid.uuid4().hex[:4]}")
    session.add(role)
    await session.flush()
    return role


# --------------------------------------------------------------------------- #
# Create.
# --------------------------------------------------------------------------- #


class TestCreate:
    async def test_defaults(self, session: AsyncSession) -> None:
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

    async def test_with_flags(self, session: AsyncSession) -> None:
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

    async def test_duplicate_conflicts(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        with pytest.raises(RoleSandboxTemplatePermissionConflictError):
            await svc.create(role_id=role.id, sandbox_template_id=tpl.id)

    async def test_orphan_role_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        tpl = await _seed_template(session)
        with pytest.raises(RoleSandboxTemplatePermissionOrphanError):
            await svc.create(role_id=uuid.uuid4(), sandbox_template_id=tpl.id)

    async def test_orphan_template_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        with pytest.raises(RoleSandboxTemplatePermissionOrphanError):
            await svc.create(role_id=role.id, sandbox_template_id=uuid.uuid4())

    async def test_scope_error_when_denied(self, session: AsyncSession) -> None:
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        svc = RoleSandboxTemplatePermissionService(session, NONE)
        with pytest.raises(RoleSandboxTemplatePermissionScopeError):
            await svc.create(role_id=role.id, sandbox_template_id=tpl.id)


# --------------------------------------------------------------------------- #
# Get / get_many.
# --------------------------------------------------------------------------- #


class TestGet:
    async def test_get_returns_link(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        got = await svc.get(link.id)
        assert got.id == link.id

    async def test_get_missing_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.get(uuid.uuid4())

    async def test_get_out_of_scope_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        denied = RoleSandboxTemplatePermissionService(session, NONE)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await denied.get(link.id)


class TestGetMany:
    async def test_aligned_with_nulls(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        results = await svc.get_many([link.id, uuid.uuid4()])
        assert results[0] is not None and results[0].id == link.id
        assert results[1] is None

    async def test_empty(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        assert await svc.get_many([]) == []


# --------------------------------------------------------------------------- #
# Search / count.
# --------------------------------------------------------------------------- #


class TestSearchCount:
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

    async def test_search_pagination_cursor(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        created: list[uuid.UUID] = []
        for _ in range(3):
            tpl = await _seed_template(session, n=len(created))
            link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
            created.append(link.id)
        # Search orders by id; use the smallest id as the cursor so the page
        # excludes exactly that one.
        ordered = sorted(created)
        page, next_cursor = await svc.search_role_sandbox_template_permissions(
            cursor=ordered[0], limit=50
        )
        assert {link.id for link in page} == set(ordered[1:])
        assert next_cursor is None

    async def test_search_next_cursor_when_full_page(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        created: list[uuid.UUID] = []
        for _ in range(3):
            tpl = await _seed_template(session, n=len(created))
            link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
            created.append(link.id)
        page, next_cursor = await svc.search_role_sandbox_template_permissions(limit=2)
        assert len(page) == 2
        assert next_cursor is not None

    async def test_count(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        assert await svc.count() >= 1

    async def test_count_with_filter(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        assert await svc.count(RoleSandboxTemplatePermissionSearchFilter(role_id__eq=role.id)) == 1


# --------------------------------------------------------------------------- #
# Update / delete.
# --------------------------------------------------------------------------- #


class TestUpdate:
    async def test_toggles_flags(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        updated = await svc.update(
            link.id,
            RoleSandboxTemplatePermissionUpdate(
                read_enabled=True, update_enabled=True, delete_enabled=True
            ),
        )
        assert updated.read_enabled is True
        assert updated.update_enabled is True
        assert updated.delete_enabled is True

    async def test_missing_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.update(
                uuid.uuid4(),
                RoleSandboxTemplatePermissionUpdate(read_enabled=True),
            )


class TestDelete:
    async def test_removes(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        await svc.delete(link.id)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.get(link.id)

    async def test_missing_raises(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.delete(uuid.uuid4())


# --------------------------------------------------------------------------- #
# Batch.
# --------------------------------------------------------------------------- #


class TestBatch:
    async def test_create_update_delete(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        role2 = await _seed_role(session, n=1)
        tpl2 = await _seed_template(session, n=1)
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
                RoleSandboxTemplatePermissionBatchUpdate(
                    id=uuid.uuid4(),  # placeholder, replaced below
                    data=RoleSandboxTemplatePermissionUpdate(update_enabled=True),
                ),
                RoleSandboxTemplatePermissionBatchDelete(id=uuid.uuid4()),
            ][:2],
            {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
        )
        assert len(results) == 2
        assert results[0].read_enabled is True
        assert results[1] is not None

    async def test_batch_update_and_delete(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        results = await svc.apply_batch(
            [
                RoleSandboxTemplatePermissionBatchUpdate(
                    id=link.id,
                    data=RoleSandboxTemplatePermissionUpdate(read_enabled=True),
                ),
                RoleSandboxTemplatePermissionBatchDelete(id=link.id),
            ],
            {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: ALL},
        )
        assert results[0].read_enabled is True
        assert results[1] is None
        with pytest.raises(RoleSandboxTemplatePermissionNotFoundError):
            await svc.get(link.id)

    async def test_create_denied_when_action_filter_none(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        with pytest.raises(BatchPermissionDeniedError):
            await svc.apply_batch(
                [
                    RoleSandboxTemplatePermissionBatchCreate(
                        data={"role_id": role.id, "sandbox_template_id": tpl.id}
                    ),
                ],
                {Action.CREATE: None, Action.UPDATE: None, Action.DELETE: None},
            )

    async def test_update_denied_when_action_filter_none(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        with pytest.raises(BatchPermissionDeniedError):
            await svc.apply_batch(
                [
                    RoleSandboxTemplatePermissionBatchUpdate(
                        id=link.id,
                        data=RoleSandboxTemplatePermissionUpdate(read_enabled=True),
                    ),
                ],
                {Action.CREATE: ALL, Action.UPDATE: None, Action.DELETE: ALL},
            )

    async def test_delete_denied_when_action_filter_none(self, session: AsyncSession) -> None:
        svc = RoleSandboxTemplatePermissionService(session)
        role = await _seed_role(session)
        tpl = await _seed_template(session)
        link = await svc.create(role_id=role.id, sandbox_template_id=tpl.id)
        with pytest.raises(BatchPermissionDeniedError):
            await svc.apply_batch(
                [RoleSandboxTemplatePermissionBatchDelete(id=link.id)],
                {Action.CREATE: ALL, Action.UPDATE: ALL, Action.DELETE: None},
            )


# --------------------------------------------------------------------------- #
# _classify_integrity_error (unit-level branching coverage).
# --------------------------------------------------------------------------- #


def _integrity(orig_msg: str) -> IntegrityError:
    return IntegrityError("statement", params=None, orig=Exception(orig_msg))


def test_classify_unique_constraint_conflict() -> None:
    exc = _integrity(
        'duplicate key value violates unique constraint "uq_role_sandbox_tpl_perm_role_sandbox_tpl"'
    )
    result = _classify_integrity_error(exc, uuid.uuid4(), uuid.uuid4())
    assert isinstance(result, RoleSandboxTemplatePermissionConflictError)


def test_classify_generic_unique_constraint_conflict() -> None:
    exc = _integrity(
        'duplicate key value violates unique constraint "role_sandbox_template_permissions_role_id_key"'
    )
    result = _classify_integrity_error(exc, uuid.uuid4(), uuid.uuid4())
    assert isinstance(result, RoleSandboxTemplatePermissionConflictError)


def test_classify_orphan_sandbox_template() -> None:
    sandbox_template_id = uuid.uuid4()
    exc = _integrity(
        'insert or update on table "role_sandbox_template_permissions" '
        'violates foreign key constraint "fk_sandbox_template_id"'
    )
    result = _classify_integrity_error(exc, uuid.uuid4(), sandbox_template_id)
    assert isinstance(result, RoleSandboxTemplatePermissionOrphanError)
    assert str(sandbox_template_id) in str(result)


def test_classify_orphan_role() -> None:
    role_id = uuid.uuid4()
    exc = _integrity(
        'insert or update on table "role_sandbox_template_permissions" '
        'violates foreign key constraint "fk_role_id"'
    )
    result = _classify_integrity_error(exc, role_id, uuid.uuid4())
    assert isinstance(result, RoleSandboxTemplatePermissionOrphanError)
    assert str(role_id) in str(result)


def test_classify_unknown_integrity_falls_back_to_conflict() -> None:
    exc = _integrity("some other integrity problem")
    result = _classify_integrity_error(exc, uuid.uuid4(), uuid.uuid4())
    assert isinstance(result, RoleSandboxTemplatePermissionConflictError)
