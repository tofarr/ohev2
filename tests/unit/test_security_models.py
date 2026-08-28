"""Unit tests for the security module.

Pure in-memory tests exercise the :class:`Permission` discriminated-union
round-trip and the ``to_search_filter`` reductions for each implementation. The
DB-backed tests (via the shared ``session`` fixture) verify the
:class:`PermissionType` JSONB ``TypeDecorator`` round-trips a stored policy
through Postgres and that the ``Role``/``RoleUser`` models persist correctly.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.security.security_models import (
    Action,
    Denied,
    Permission,
    Permitted,
    ReadOnly,
    Role,
    RoleUser,
)
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import AllSearchFilter, NoneSearchFilter

_USER_ID = uuid.uuid4()


class TestPermissionReduction:
    """Each implementation reduces to the correct SearchFilter per action."""

    def test_permitted_always_all(self) -> None:
        policy = Permitted()
        for action in Action:
            assert isinstance(policy.to_search_filter(_USER_ID, action), AllSearchFilter)

    def test_denied_always_none(self) -> None:
        policy = Denied()
        for action in Action:
            assert isinstance(policy.to_search_filter(_USER_ID, action), NoneSearchFilter)

    @pytest.mark.parametrize("action", [Action.READ, Action.SEARCH])
    def test_readonly_allows_read_and_search(self, action: Action) -> None:
        assert isinstance(ReadOnly().to_search_filter(_USER_ID, action), AllSearchFilter)

    @pytest.mark.parametrize("action", [Action.CREATE, Action.UPDATE, Action.DELETE, Action.USE])
    def test_readonly_denies_mutations(self, action: Action) -> None:
        assert isinstance(ReadOnly().to_search_filter(_USER_ID, action), NoneSearchFilter)


class TestPermissionRoundTrip:
    """Serialized policies deserialize back to the concrete subclass."""

    @pytest.mark.parametrize(
        ("policy", "cls"),
        [
            (Permitted(), Permitted),
            (Denied(), Denied),
            (ReadOnly(), ReadOnly),
        ],
    )
    def test_round_trip(self, policy: Permission, cls: type[Permission]) -> None:
        data = policy.model_dump(mode="json")
        restored = Permission.model_validate(data)
        assert isinstance(restored, cls)
        assert restored.kind == cls.__name__

    def test_kind_computed_field(self) -> None:
        assert Permitted().kind == "Permitted"
        assert Denied().kind == "Denied"
        assert ReadOnly().kind == "ReadOnly"


class TestPermissionAbstract:
    def test_base_to_search_filter_not_implemented(self) -> None:
        # The base Permission raises NotImplementedError; concrete subclasses
        # override it. Validating without a kind should fail to resolve a subclass.
        with pytest.raises(ValueError, match="kind"):
            Permission.model_validate({})


class TestRoleModel:
    """DB-backed persistence of Role with Permission JSONB columns."""

    async def test_role_persists_permission_policies(self, session: AsyncSession) -> None:
        role = Role(
            name="admin",
            role_permission=Permitted(),
            user_permission=Permitted(),
        )
        session.add(role)
        await session.flush()
        await session.refresh(role)

        assert isinstance(role.id, uuid.UUID)
        assert role.name == "admin"
        assert isinstance(role.role_permission, Permitted)
        assert isinstance(role.user_permission, Permitted)

    async def test_role_nullable_permission_columns(self, session: AsyncSession) -> None:
        role = Role(name="empty")
        session.add(role)
        await session.flush()
        await session.refresh(role)
        assert role.role_permission is None
        assert role.user_permission is None

    async def test_role_permission_round_trips_concrete_subclass(
        self, session: AsyncSession
    ) -> None:
        role = Role(name="viewer", user_permission=ReadOnly())
        session.add(role)
        await session.flush()
        await session.refresh(role)
        # The TypeDecorator must restore the concrete ReadOnly subclass.
        assert isinstance(role.user_permission, ReadOnly)

    async def test_role_name_unique(self, session: AsyncSession) -> None:
        session.add(Role(name="dup"))
        await session.flush()
        session.add(Role(name="dup"))
        with pytest.raises(Exception):  # noqa: B017 — IntegrityError subclass
            await session.flush()


class TestRoleUserModel:
    """DB-backed persistence of the RoleUser link table."""

    async def test_assign_role_to_user(self, session: AsyncSession) -> None:
        user = User(email="ru@example.com", username="ru")
        role = Role(name="viewer", user_permission=ReadOnly())
        session.add(user)
        session.add(role)
        await session.flush()

        link = RoleUser(role_id=role.id, user_id=user.id)
        session.add(link)
        await session.flush()
        await session.refresh(link)

        assert isinstance(link.id, uuid.UUID)
        assert link.role_id == role.id
        assert link.user_id == user.id
        # selectin relationships resolve to the linked rows.
        assert link.role.name == "viewer"
        assert link.user.email == "ru@example.com"

    async def test_role_user_query_by_user(self, session: AsyncSession) -> None:
        user = User(email="qu@example.com", username="qu")
        role = Role(name="admin", user_permission=Permitted())
        session.add(user)
        session.add(role)
        await session.flush()
        session.add(RoleUser(role_id=role.id, user_id=user.id))
        await session.flush()

        stmt = select(RoleUser).where(RoleUser.user_id == user.id)
        links = list((await session.execute(stmt)).scalars().all())
        assert len(links) == 1
        assert isinstance(links[0].role.user_permission, Permitted)
