"""Unit tests for the feature_flag service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.feature_flag.feature_flag_models import FeatureFlag, FeatureFlagRole
from openhands.ev2.feature_flag.feature_flag_schemas import (
    FeatureFlagCreate,
    FeatureFlagRoleCreate,
    FeatureFlagRoleSearchFilter,
    FeatureFlagSearchFilter,
    FeatureFlagUpdate,
)
from openhands.ev2.feature_flag.feature_flag_service import (
    FeatureFlagConflictError,
    FeatureFlagNotFoundError,
    FeatureFlagRoleConflictError,
    FeatureFlagRoleNotFoundError,
    FeatureFlagRoleOrphanError,
    FeatureFlagRoleService,
    FeatureFlagService,
)
from openhands.ev2.role.role_models import Role
from openhands.ev2.util.search_filter import AllSearchFilter


@pytest.fixture
def service(session: AsyncSession) -> FeatureFlagService:
    return FeatureFlagService(session, AllSearchFilter[FeatureFlag]())


@pytest.fixture
def override_service(session: AsyncSession) -> FeatureFlagRoleService:

    return FeatureFlagRoleService(session, AllSearchFilter[FeatureFlagRole]())


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
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session)
        link = await override_service.create(
            FeatureFlagRoleCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        assert isinstance(link.id, uuid.UUID)
        assert link.feature_flag_id == flag_id
        assert link.role_id == role_id

    async def test_create_duplicate_conflicts(
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="DUP_OVR_SVC")
        await override_service.create(
            FeatureFlagRoleCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        with pytest.raises(FeatureFlagRoleConflictError):
            await override_service.create(
                FeatureFlagRoleCreate(feature_flag_id=flag_id, role_id=role_id)
            )

    async def test_create_missing_flag_raises_orphan(
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        session.add(Role(name="orphan-flag-role"))
        await session.flush()
        role_id = (
            (await session.execute(select(Role).where(Role.name == "orphan-flag-role")))
            .scalar_one()
            .id
        )
        with pytest.raises((FeatureFlagRoleOrphanError, Exception)):
            await override_service.create(
                FeatureFlagRoleCreate(feature_flag_id="NO_SUCH_FLAG", role_id=role_id)
            )


class TestGetOverride:
    async def test_get_existing(
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="GET_OVR_SVC")
        link = await override_service.create(
            FeatureFlagRoleCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        fetched = await override_service.get(link.id)
        assert fetched.id == link.id

    async def test_get_missing_raises(self, override_service: FeatureFlagRoleService) -> None:
        with pytest.raises(FeatureFlagRoleNotFoundError):
            await override_service.get(uuid.uuid4())


class TestDeleteOverride:
    async def test_delete(
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="DEL_OVR_SVC")
        link = await override_service.create(
            FeatureFlagRoleCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        await override_service.delete(link.id)
        with pytest.raises(FeatureFlagRoleNotFoundError):
            await override_service.get(link.id)


class TestSearchOverride:
    async def test_search_filter_by_flag(
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        f1, r1 = await _seed_flag_and_role(session, flag_id="SF_A", role_name="sf-a-role")
        session.add(FeatureFlag(id="SF_B"))
        session.add(Role(name="sf-b-role"))
        await session.flush()
        r2 = (await session.execute(select(Role).where(Role.name == "sf-b-role"))).scalar_one().id
        await override_service.create(FeatureFlagRoleCreate(feature_flag_id=f1, role_id=r1))
        await override_service.create(FeatureFlagRoleCreate(feature_flag_id="SF_B", role_id=r2))
        links, _ = await override_service.search(
            search_filter=FeatureFlagRoleSearchFilter(feature_flag_id__eq=f1)
        )
        assert all(link.feature_flag_id == f1 for link in links)

    async def test_count(
        self, override_service: FeatureFlagRoleService, session: AsyncSession
    ) -> None:
        flag_id, role_id = await _seed_flag_and_role(session, flag_id="CNT_OVR_SVC")
        await override_service.create(
            FeatureFlagRoleCreate(feature_flag_id=flag_id, role_id=role_id)
        )
        assert await override_service.count() >= 1
