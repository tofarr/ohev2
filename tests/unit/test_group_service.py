"""Unit tests for the group service (DB-backed)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.group.group_models import Group
from openhands.ev2.group.group_schemas import (
    GroupCreate,
    GroupUpdate,
    GroupUserCreate,
    GroupUserSearchFilter,
)
from openhands.ev2.group.group_service import (
    GroupNotFoundError,
    GroupService,
    GroupUserConflictError,
    GroupUserNotFoundError,
    GroupUserOrphanError,
    GroupUserService,
)
from openhands.ev2.user.user_models import User


@pytest.fixture
def group_service(session: AsyncSession) -> GroupService:
    return GroupService(session)


@pytest.fixture
def group_user_service(session: AsyncSession) -> GroupUserService:
    return GroupUserService(session)


async def _seed_user(session: AsyncSession, *, username: str = "g") -> User:
    user = User(email=f"{username}@example.com", username=username)
    session.add(user)
    await session.flush()
    return user


class TestGroupCreate:
    async def test_create_group(self, group_service: GroupService, session: AsyncSession) -> None:
        creator = await _seed_user(session)
        group = await group_service.create(
            GroupCreate(name="team-a", description="desc"), creator_id=creator.id
        )
        assert isinstance(group.id, uuid.UUID)
        assert group.name == "team-a"
        assert group.description == "desc"
        assert group.creator_id == creator.id
        assert group.created_at is not None

    async def test_create_group_without_description(
        self, group_service: GroupService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="g2")
        group = await group_service.create(GroupCreate(name="team-b"), creator_id=creator.id)
        assert group.description is None


class TestGroupGet:
    async def test_get_existing(self, group_service: GroupService, session: AsyncSession) -> None:
        creator = await _seed_user(session)
        group = await group_service.create(GroupCreate(name="g"), creator_id=creator.id)
        fetched = await group_service.get(group.id)
        assert fetched.id == group.id

    async def test_get_missing_raises(self, group_service: GroupService) -> None:
        with pytest.raises(GroupNotFoundError):
            await group_service.get(uuid.uuid4())


class TestGroupSearch:
    async def test_search_returns_groups(
        self, group_service: GroupService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session)
        for i in range(3):
            await group_service.create(GroupCreate(name=f"team-{i}"), creator_id=creator.id)
        groups, next_cursor = await group_service.search(limit=50)
        assert len(groups) == 3
        assert next_cursor is None

    async def test_search_pagination(
        self, group_service: GroupService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session)
        for i in range(5):
            await group_service.create(GroupCreate(name=f"page-{i}"), creator_id=creator.id)
        page1, cursor = await group_service.search(limit=2)
        assert len(page1) == 2
        assert cursor is not None
        page2, cursor = await group_service.search(cursor=cursor, limit=2)
        assert len(page2) == 2
        assert cursor is not None
        page3, next_cursor = await group_service.search(cursor=cursor, limit=2)
        assert len(page3) == 1
        assert next_cursor is None


class TestGroupUpdate:
    async def test_update_name_and_description(
        self, group_service: GroupService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session)
        group = await group_service.create(GroupCreate(name="old"), creator_id=creator.id)
        updated = await group_service.update(
            group.id, GroupUpdate(name="new", description="updated")
        )
        assert updated.name == "new"
        assert updated.description == "updated"

    async def test_update_missing_raises(self, group_service: GroupService) -> None:
        with pytest.raises(GroupNotFoundError):
            await group_service.update(uuid.uuid4(), GroupUpdate(name="x"))


class TestGroupDelete:
    async def test_delete_group(self, group_service: GroupService, session: AsyncSession) -> None:
        creator = await _seed_user(session)
        group = await group_service.create(GroupCreate(name="del"), creator_id=creator.id)
        await group_service.delete(group.id)
        with pytest.raises(GroupNotFoundError):
            await group_service.get(group.id)

    async def test_delete_missing_raises(self, group_service: GroupService) -> None:
        with pytest.raises(GroupNotFoundError):
            await group_service.delete(uuid.uuid4())


class TestGroupCount:
    async def test_count_after_creates(
        self, group_service: GroupService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session)
        await group_service.create(GroupCreate(name="c1"), creator_id=creator.id)
        await group_service.create(GroupCreate(name="c2"), creator_id=creator.id)
        assert await group_service.count() == 2


class TestGroupUserCreate:
    async def test_create_membership(
        self, group_user_service: GroupUserService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="owner")
        member = await _seed_user(session, username="member")
        group = Group(name="m", creator_id=creator.id)
        session.add(group)
        await session.flush()
        link = await group_user_service.create(
            GroupUserCreate(group_id=group.id, user_id=member.id), creator_id=creator.id
        )
        assert isinstance(link.id, uuid.UUID)
        assert link.group_id == group.id
        assert link.user_id == member.id
        assert link.creator_id == creator.id

    async def test_create_duplicate_conflicts(
        self, group_user_service: GroupUserService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="owner2")
        member = await _seed_user(session, username="member2")
        group = Group(name="m2", creator_id=creator.id)
        session.add(group)
        await session.flush()
        await group_user_service.create(
            GroupUserCreate(group_id=group.id, user_id=member.id), creator_id=creator.id
        )
        with pytest.raises(GroupUserConflictError):
            await group_user_service.create(
                GroupUserCreate(group_id=group.id, user_id=member.id), creator_id=creator.id
            )

    async def test_create_missing_group_raises(
        self, group_user_service: GroupUserService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="owner3")
        member = await _seed_user(session, username="member3")
        with pytest.raises((GroupUserOrphanError, Exception)):
            await group_user_service.create(
                GroupUserCreate(group_id=uuid.uuid4(), user_id=member.id),
                creator_id=creator.id,
            )


class TestGroupUserGet:
    async def test_get_existing(
        self, group_user_service: GroupUserService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="owner4")
        member = await _seed_user(session, username="member4")
        group = Group(name="g4", creator_id=creator.id)
        session.add(group)
        await session.flush()
        link = await group_user_service.create(
            GroupUserCreate(group_id=group.id, user_id=member.id), creator_id=creator.id
        )
        fetched = await group_user_service.get(link.id)
        assert fetched.id == link.id

    async def test_get_missing_raises(self, group_user_service: GroupUserService) -> None:
        with pytest.raises(GroupUserNotFoundError):
            await group_user_service.get(uuid.uuid4())


class TestGroupUserSearch:
    async def test_search_group_filter(
        self, group_user_service: GroupUserService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="owner5")
        group = Group(name="g5", creator_id=creator.id)
        session.add(group)
        await session.flush()
        for i in range(3):
            member = await _seed_user(session, username=f"m5{i}")
            await group_user_service.create(
                GroupUserCreate(group_id=group.id, user_id=member.id), creator_id=creator.id
            )
        links, _ = await group_user_service.search_group_users(
            search_filter=GroupUserSearchFilter(group_id__eq=group.id)
        )
        assert len(links) == 3
        assert all(link.group_id == group.id for link in links)


class TestGroupUserDelete:
    async def test_delete_membership(
        self, group_user_service: GroupUserService, session: AsyncSession
    ) -> None:
        creator = await _seed_user(session, username="owner6")
        member = await _seed_user(session, username="member6")
        group = Group(name="g6", creator_id=creator.id)
        session.add(group)
        await session.flush()
        link = await group_user_service.create(
            GroupUserCreate(group_id=group.id, user_id=member.id), creator_id=creator.id
        )
        await group_user_service.delete(link.id)
        with pytest.raises(GroupUserNotFoundError):
            await group_user_service.get(link.id)
