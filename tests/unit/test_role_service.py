"""Unit tests for the role service (DB-backed)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.role.role_schemas import (
    RoleBatchCreate,
    RoleBatchDelete,
    RoleBatchUpdate,
    RoleCreate,
    RoleSearchFilter,
    RoleUpdate,
)
from openhands.ev2.role.role_service import (
    BatchPermissionDeniedError,
    RoleNameConflictError,
    RoleNotFoundError,
    RolePermissionScopeError,
    RoleService,
)
from openhands.ev2.security.security_models import Action, Denied, Permitted, ReadOnly
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter

_ALL = AllSearchFilter[Role]()
_NONE = NoneSearchFilter[Role]()


@pytest.fixture
def service(session: AsyncSession) -> RoleService:
    return RoleService(session, _ALL)


class TestCreateRole:
    async def test_create_role(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="admin"))
        assert role.id is not None
        assert isinstance(role.id, uuid.UUID)
        assert role.name == "admin"
        assert role.created_at is not None
        assert role.updated_at is not None

    async def test_create_role_with_entity_permissions(self, service: RoleService) -> None:
        role = await service.create(
            RoleCreate(
                name="admin",
                user_permission=Permitted(),
                role_permission=ReadOnly(),
            )
        )
        assert isinstance(role.user_permission, Permitted)
        assert isinstance(role.role_permission, ReadOnly)

    async def test_create_role_with_legacy_permissions(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="viewer", user_permission=ReadOnly()))
        assert isinstance(role.user_permission, ReadOnly)
        assert role.role_permission is None

    async def test_create_duplicate_name_conflicts(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="dup"))
        with pytest.raises(RoleNameConflictError):
            await service.create(RoleCreate(name="dup"))

    async def test_create_invalid_name_rejected_at_schema(self) -> None:
        with pytest.raises(ValueError):
            RoleCreate(name="")

    async def test_create_defaults_to_unrestricted_scope(self, session: AsyncSession) -> None:
        # No perm_filter supplied: defaults to AllSearchFilter (unrestricted).
        svc = RoleService(session)
        role = await svc.create(RoleCreate(name="default"))
        assert role.name == "default"

    async def test_create_scoped_out_raises(self, session: AsyncSession) -> None:
        svc = RoleService(session, _NONE)
        with pytest.raises(RolePermissionScopeError):
            await svc.create(RoleCreate(name="denied"))


class TestGetRole:
    async def test_get_existing_role(self, service: RoleService) -> None:
        created = await service.create(RoleCreate(name="viewer"))
        fetched = await service.get(created.id)
        assert fetched.id == created.id
        assert fetched.name == "viewer"

    async def test_get_missing_role_raises(self, service: RoleService) -> None:
        with pytest.raises(RoleNotFoundError):
            await service.get(uuid.uuid4())


class TestSearchRoles:
    async def test_search_empty(self, service: RoleService) -> None:
        roles, next_cursor = await service.search_roles()
        assert roles == []
        assert next_cursor is None

    async def test_search_returns_roles(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="a"))
        await service.create(RoleCreate(name="b"))
        roles, next_cursor = await service.search_roles()
        assert len(roles) == 2
        assert next_cursor is None

    async def test_search_pagination_with_limit(self, service: RoleService) -> None:
        for i in range(5):
            await service.create(RoleCreate(name=f"r{i}"))
        roles, next_cursor = await service.search_roles(limit=2)
        assert len(roles) == 2
        assert next_cursor is not None

        roles2, next_cursor2 = await service.search_roles(cursor=next_cursor, limit=2)
        assert len(roles2) == 2
        assert next_cursor2 is not None

        roles3, next_cursor3 = await service.search_roles(cursor=next_cursor2, limit=2)
        assert len(roles3) == 1
        assert next_cursor3 is None

    async def test_search_sorted_by_id(self, service: RoleService) -> None:
        a = await service.create(RoleCreate(name="a"))
        b = await service.create(RoleCreate(name="b"))
        roles, _ = await service.search_roles()
        ids = [r.id for r in roles]
        assert set(ids) == {a.id, b.id}
        assert ids == sorted(ids)


class TestSearchRolesFilters:
    async def test_name_contains_case_insensitive(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="Admin"))
        await service.create(RoleCreate(name="viewer"))
        await service.create(RoleCreate(name="other"))
        roles, _ = await service.search_roles(
            search_filter=RoleSearchFilter(name__contains="ADMIN")
        )
        names = {r.name for r in roles}
        assert names == {"Admin"}

    async def test_name_eq_exact_match(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="admin"))
        await service.create(RoleCreate(name="viewer"))
        roles, _ = await service.search_roles(search_filter=RoleSearchFilter(name__eq="admin"))
        assert len(roles) == 1
        assert roles[0].name == "admin"

    async def test_created_at_gte(self, service: RoleService) -> None:
        old = await service.create(RoleCreate(name="old"))
        cutoff = old.created_at
        new = await service.create(RoleCreate(name="new"))
        roles, _ = await service.search_roles(
            search_filter=RoleSearchFilter(created_at__gte=cutoff)
        )
        ids = {r.id for r in roles}
        assert new.id in ids
        assert old.id in ids

    async def test_combined_filters(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="alice"))
        await service.create(RoleCreate(name="bob"))
        await service.create(RoleCreate(name="alice2"))
        roles, _ = await service.search_roles(
            search_filter=RoleSearchFilter(
                name__contains="alice",
                created_at__lt=datetime.now() + timedelta(days=1),
            ),
        )
        names = {r.name for r in roles}
        assert names == {"alice", "alice2"}


class TestUpdateRole:
    async def test_update_name(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="old"))
        updated = await service.update(role.id, RoleUpdate(name="new"))
        assert updated.name == "new"

    async def test_update_policies(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="r"))
        updated = await service.update(role.id, RoleUpdate(user_permission=Denied()))
        assert isinstance(updated.user_permission, Denied)

    async def test_update_user_permission(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="r"))
        updated = await service.update(role.id, RoleUpdate(user_permission=Permitted()))
        assert isinstance(updated.user_permission, Permitted)

    async def test_update_no_fields_keeps_name(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="keep"))
        updated = await service.update(role.id, RoleUpdate())
        assert updated.name == "keep"

    async def test_update_missing_role_raises(self, service: RoleService) -> None:
        with pytest.raises(RoleNotFoundError):
            await service.update(uuid.uuid4(), RoleUpdate(name="x"))

    async def test_update_to_existing_name_conflicts(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="taken"))
        role = await service.create(RoleCreate(name="other"))
        with pytest.raises(RoleNameConflictError):
            await service.update(role.id, RoleUpdate(name="taken"))


class TestDeleteRole:
    async def test_delete_role(self, service: RoleService) -> None:
        role = await service.create(RoleCreate(name="del"))
        await service.delete(role.id)
        with pytest.raises(RoleNotFoundError):
            await service.get(role.id)

    async def test_delete_missing_role_raises(self, service: RoleService) -> None:
        with pytest.raises(RoleNotFoundError):
            await service.delete(uuid.uuid4())


class TestCount:
    async def test_count_empty(self, service: RoleService) -> None:
        assert await service.count() == 0

    async def test_count_after_creates(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="a"))
        await service.create(RoleCreate(name="b"))
        assert await service.count() == 2

    async def test_count_with_filter(self, service: RoleService) -> None:
        await service.create(RoleCreate(name="admin"))
        await service.create(RoleCreate(name="viewer"))
        assert await service.count(search_filter=RoleSearchFilter(name__contains="admin")) == 1


class TestApplyBatch:
    """RoleService.apply_batch — per-op permission gating + atomic application."""

    async def test_batch_applies_mix_when_all_actions_permitted(
        self, session: AsyncSession
    ) -> None:
        svc = RoleService(session)
        existing = await RoleService(session, _ALL).create(RoleCreate(name="keep"))
        ops = [
            RoleBatchCreate(data=RoleCreate(name="new")),
            RoleBatchUpdate(id=existing.id, data=RoleUpdate(name="keepb")),
            RoleBatchDelete(id=existing.id),
        ]
        filters = {Action.CREATE: _ALL, Action.UPDATE: _ALL, Action.DELETE: _ALL}
        results = await svc.apply_batch(ops, filters)
        assert results[0] is not None and results[0].name == "new"
        # update then delete on same id: update returns the role, delete returns None
        assert results[1] is not None and results[1].name == "keepb"
        assert results[2] is None

    async def test_batch_raises_when_action_filter_is_none(self, session: AsyncSession) -> None:
        svc = RoleService(session)
        ops = [RoleBatchCreate(data=RoleCreate(name="denied"))]
        # CREATE filter is None -> denied
        filters = {Action.CREATE: None, Action.UPDATE: _ALL, Action.DELETE: _ALL}
        with pytest.raises(BatchPermissionDeniedError):
            await svc.apply_batch(ops, filters)

    async def test_batch_skips_unused_actions_without_raising(self, session: AsyncSession) -> None:
        # A create-only batch with update/delete filters set to None should succeed:
        # unused actions don't need grants (depends_permissions_or_none semantics).
        svc = RoleService(session)
        ops = [RoleBatchCreate(data=RoleCreate(name="only-create"))]
        filters = {Action.CREATE: _ALL, Action.UPDATE: None, Action.DELETE: None}
        results = await svc.apply_batch(ops, filters)
        assert results[0] is not None and results[0].name == "only-create"
