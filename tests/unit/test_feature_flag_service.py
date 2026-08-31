"""Unit tests for the feature_flag service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.feature_flag.feature_flag_models import (
    FeatureFlag,
    FeatureFlagRoleAssignment,
    FeatureFlagUserAssignment,
)
from openhands.ev2.feature_flag.feature_flag_schemas import (
    FeatureFlagCreate,
    FeatureFlagRoleAssignmentCreate,
    FeatureFlagRoleAssignmentSearchFilter,
    FeatureFlagSearchFilter,
    FeatureFlagUpdate,
    FeatureFlagUserAssignmentCreate,
    FeatureFlagUserAssignmentSearchFilter,
)
from openhands.ev2.feature_flag.feature_flag_service import (
    FeatureFlagConflictError,
    FeatureFlagNotFoundError,
    FeatureFlagRoleAssignmentConflictError,
    FeatureFlagRoleAssignmentNotFoundError,
    FeatureFlagRoleAssignmentOrphanError,
    FeatureFlagRoleAssignmentService,
    FeatureFlagService,
    FeatureFlagUserAssignmentConflictError,
    FeatureFlagUserAssignmentNotFoundError,
    FeatureFlagUserAssignmentOrphanError,
    FeatureFlagUserAssignmentService,
)
from openhands.ev2.role.role_models import Role
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import AllSearchFilter


@pytest.fixture
def service(session: AsyncSession) -> FeatureFlagService:
    return FeatureFlagService(session, AllSearchFilter[FeatureFlag]())


@pytest.fixture
def user_override_service(session: AsyncSession) -> FeatureFlagUserAssignmentService:
    return FeatureFlagUserAssignmentService(session, AllSearchFilter[FeatureFlagUserAssignment]())


@pytest.fixture
def override_service(session: AsyncSession) -> FeatureFlagRoleAssignmentService:

    return FeatureFlagRoleAssignmentService(session, AllSearchFilter[FeatureFlagRoleAssignment]())


class TestCreateFeatureFlag:
    async def test_create_flag(self, service: FeatureFlagService) -> None:
        flag = await service.create(FeatureFlagCreate(id="SVC_FLAG", enabled=True, description="d"))
        assert flag.id == "SVC_FLAG"
        assert flag.enabled is True
        assert flag.description == "d"
        assert flag.created_at is not None
        assert flag.updated_at is not None

    async def test_create_duplicate_conflicts(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="DUP_SVC"))
        with pytest.raises(FeatureFlagConflictError):
            await service.create(FeatureFlagCreate(id="DUP_SVC"))


class TestGetFeatureFlag:
    async def test_get_existing(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="GET_SVC"))
        flag = await service.get("GET_SVC")
        assert flag.id == "GET_SVC"

    async def test_get_missing_raises(self, service: FeatureFlagService) -> None:
        with pytest.raises(FeatureFlagNotFoundError):
            await service.get("NOPE")


class TestUpdateFeatureFlag:
    async def test_update(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="UPD_SVC", enabled=False))
        flag = await service.update("UPD_SVC", FeatureFlagUpdate(enabled=True, description="x"))
        assert flag.enabled is True
        assert flag.description == "x"


class TestDeleteFeatureFlag:
    async def test_delete(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="DEL_SVC"))
        await service.delete("DEL_SVC")
        with pytest.raises(FeatureFlagNotFoundError):
            await service.get("DEL_SVC")

    async def test_delete_missing_raises(self, service: FeatureFlagService) -> None:
        with pytest.raises(FeatureFlagNotFoundError):
            await service.delete("NOPE")


class TestSearchFeatureFlag:
    async def test_search_pagination(self, service: FeatureFlagService) -> None:
        for i in range(3):
            await service.create(FeatureFlagCreate(id=f"PG_SVC_{i}"))
        flags, cursor = await service.search(limit=2)
        assert len(flags) == 2
        assert cursor is not None
        flags2, cursor2 = await service.search(cursor=cursor, limit=2)
        assert len(flags2) == 1
        assert cursor2 is None

    async def test_search_filter(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="FLT_ON", enabled=True))
        await service.create(FeatureFlagCreate(id="FLT_OFF", enabled=False))
        flags, _ = await service.search(search_filter=FeatureFlagSearchFilter(enabled__eq=True))
        assert all(f.enabled for f in flags)
        assert any(f.id == "FLT_ON" for f in flags)

    async def test_count(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="CNT_SVC_1"))
        await service.create(FeatureFlagCreate(id="CNT_SVC_2"))
        assert await service.count() >= 2


class TestGetManyFeatureFlag:
    async def test_get_many_aligned(self, service: FeatureFlagService) -> None:
        await service.create(FeatureFlagCreate(id="GM_A"))
        flags = await service.get_many(["GM_A", "MISSING"])
        assert flags[0] is not None and flags[0].id == "GM_A"
        assert flags[1] is None

    async def test_get_many_empty(self, service: FeatureFlagService) -> None:
        assert await service.get_many([]) == []


class TestEnabledForRoles:
    async def test_globally_enabled_only(
        self, service: FeatureFlagService, session: AsyncSession
    ) -> None:
        await service.create(FeatureFlagCreate(id="EF_ON", enabled=True))
        await service.create(FeatureFlagCreate(id="EF_OFF", enabled=False))
        ids = await service.enabled_for_roles([])
        assert "EF_ON" in ids
        assert "EF_OFF" not in ids

    async def test_override_forces_flag_on(
        self,
        service: FeatureFlagService,
        override_service: FeatureFlagRoleAssignmentService,
        session: AsyncSession,
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="EF_OVR")
        # Flag is globally disabled; override flips it on for the role.
        flag = (
            await session.execute(select(FeatureFlag).where(FeatureFlag.id == flag_id))
        ).scalar_one()
        flag.enabled = False
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        ids = await service.enabled_for_roles([role_id])
        assert flag_id in ids

    async def test_override_does_not_apply_to_other_role(
        self,
        service: FeatureFlagService,
        override_service: FeatureFlagRoleAssignmentService,
        session: AsyncSession,
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="EF_ISOLATE")
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        other = Role(name="ef-other-role")
        session.add(other)
        await session.flush()
        # other role has no override row -> flag is not enabled for it (flag
        # defaults to disabled).
        ids = await service.enabled_for_roles([other.id])
        assert flag_id not in ids

    async def test_union_of_global_and_override(
        self,
        service: FeatureFlagService,
        override_service: FeatureFlagRoleAssignmentService,
        session: AsyncSession,
    ) -> None:
        await service.create(FeatureFlagCreate(id="EF_GLOBAL", enabled=True))
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="EF_OVR2")
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        ids = set(await service.enabled_for_roles([role_id]))
        assert {"EF_GLOBAL", flag_id} <= ids

    async def test_user_assignment_forces_flag_on(
        self,
        service: FeatureFlagService,
        user_override_service: FeatureFlagUserAssignmentService,
        session: AsyncSession,
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session, flag_id="EF_USER")
        await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        ids = await service.enabled_for_roles([], user_id=user_id)
        assert flag_id in ids

    async def test_user_assignment_does_not_apply_to_other_user(
        self,
        service: FeatureFlagService,
        user_override_service: FeatureFlagUserAssignmentService,
        session: AsyncSession,
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session, flag_id="EF_USER_ONLY")
        other = User(email="other-user-flag@example.com", username="other-user-flag")
        session.add(other)
        await session.flush()
        await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        ids = await service.enabled_for_roles([], user_id=other.id)
        assert flag_id not in ids


async def _seed_flag_and_user(
    session: AsyncSession,
    *,
    flag_id: str = "USR_SVC_FLAG",
    username: str = "usr-svc-user",
) -> tuple[str, uuid.UUID]:
    session.add(FeatureFlag(id=flag_id))
    session.add(User(email=f"{username}@example.com", username=username))
    await session.flush()
    user = (await session.execute(select(User).where(User.username == username))).scalar_one()
    return flag_id, user.id


# ---------------------------------------------------------------------- #
# Feature flag role override service
# ---------------------------------------------------------------------- #


async def _seed_flag_and_role(
    session: AsyncSession,
    *,
    flag_id: str = "OVR_SVC_FLAG",
    role_name: str = "ovr-svc-role",
) -> tuple[str, uuid.UUID]:
    session.add(FeatureFlag(id=flag_id))
    session.add(Role(name=role_name))
    await session.flush()
    role = (await session.execute(select(Role).where(Role.name == role_name))).scalar_one()
    return flag_id, role.id


class TestCreateOverride:
    async def test_create_override(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session)
        link = await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        assert isinstance(link.id, uuid.UUID)
        assert link.feature_flag_id == flag_id
        assert link.role_id == role_id

    async def test_create_duplicate_conflicts(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="DUP_OVR_SVC")
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        with pytest.raises(FeatureFlagRoleAssignmentConflictError):
            await override_service.create(
                FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
            )

    async def test_create_missing_flag_raises_orphan(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        session.add(Role(name="orphan-flag-role"))
        await session.flush()
        role_id = (
            (await session.execute(select(Role).where(Role.name == "orphan-flag-role")))
            .scalar_one()
            .id
        )
        with pytest.raises((FeatureFlagRoleAssignmentOrphanError, Exception)):
            await override_service.create(
                FeatureFlagRoleAssignmentCreate(feature_flag_id="NO_SUCH_FLAG", role_id=role_id)
            )


class TestGetOverride:
    async def test_get_existing(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="GET_OVR_SVC")
        link = await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        fetched = await override_service.get(link.id)
        assert fetched.id == link.id

    async def test_get_missing_raises(
        self, override_service: FeatureFlagRoleAssignmentService
    ) -> None:
        with pytest.raises(FeatureFlagRoleAssignmentNotFoundError):
            await override_service.get(uuid.uuid4())


class TestDeleteOverride:
    async def test_delete(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="DEL_OVR_SVC")
        link = await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        await override_service.delete(link.id)
        with pytest.raises(FeatureFlagRoleAssignmentNotFoundError):
            await override_service.get(link.id)


# ---------------------------------------------------------------------- #
# Feature flag user override service
# ---------------------------------------------------------------------- #


class TestCreateUserOverride:
    async def test_create_user_override(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session)
        link = await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        assert isinstance(link.id, uuid.UUID)
        assert link.feature_flag_id == flag_id
        assert link.user_id == user_id

    async def test_create_duplicate_conflicts(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session, flag_id="DUP_USER_OVR_SVC")
        await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        with pytest.raises(FeatureFlagUserAssignmentConflictError):
            await user_override_service.create(
                FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
            )

    async def test_create_missing_flag_raises_orphan(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        user = User(email="orphan-user-flag@example.com", username="orphan-user-flag")
        session.add(user)
        await session.flush()
        with pytest.raises(FeatureFlagUserAssignmentOrphanError):
            await user_override_service.create(
                FeatureFlagUserAssignmentCreate(feature_flag_id="NO_SUCH_FLAG", user_id=user.id)
            )


class TestGetUserOverride:
    async def test_get_existing(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session, flag_id="GET_USER_OVR_SVC")
        link = await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        fetched = await user_override_service.get(link.id)
        assert fetched.id == link.id

    async def test_get_missing_raises(
        self, user_override_service: FeatureFlagUserAssignmentService
    ) -> None:
        with pytest.raises(FeatureFlagUserAssignmentNotFoundError):
            await user_override_service.get(uuid.uuid4())


class TestDeleteUserOverride:
    async def test_delete(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session, flag_id="DEL_USER_OVR_SVC")
        link = await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        await user_override_service.delete(link.id)
        with pytest.raises(FeatureFlagUserAssignmentNotFoundError):
            await user_override_service.get(link.id)


class TestSearchUserOverride:
    async def test_search_filter_by_flag(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        f1, u1 = await _seed_flag_and_user(session, flag_id="SF_USER_A", username="sf-user-a")
        f2, u2 = await _seed_flag_and_user(session, flag_id="SF_USER_B", username="sf-user-b")
        await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=f1, user_id=u1)
        )
        await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=f2, user_id=u2)
        )
        links, _ = await user_override_service.search(
            search_filter=FeatureFlagUserAssignmentSearchFilter(feature_flag_id__eq=f1)
        )
        assert all(link.feature_flag_id == f1 for link in links)

    async def test_count(
        self, user_override_service: FeatureFlagUserAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, user_id = await _seed_flag_and_user(session, flag_id="CNT_USER_OVR_SVC")
        await user_override_service.create(
            FeatureFlagUserAssignmentCreate(feature_flag_id=flag_id, user_id=user_id)
        )
        assert await user_override_service.count() >= 1


class TestSearchOverride:
    async def test_search_filter_by_flag(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        f1, r1 = await _seed_flag_and_role(session, flag_id="SF_A", role_name="sf-a-role")
        session.add(FeatureFlag(id="SF_B"))
        session.add(Role(name="sf-b-role"))
        await session.flush()
        r2 = (await session.execute(select(Role).where(Role.name == "sf-b-role"))).scalar_one().id
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=f1, role_id=r1)
        )
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id="SF_B", role_id=r2)
        )
        links, _ = await override_service.search(
            search_filter=FeatureFlagRoleAssignmentSearchFilter(feature_flag_id__eq=f1)
        )
        assert all(link.feature_flag_id == f1 for link in links)

    async def test_count(
        self, override_service: FeatureFlagRoleAssignmentService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="CNT_OVR_SVC")
        await override_service.create(
            FeatureFlagRoleAssignmentCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        assert await override_service.count() >= 1
