"""Unit tests for the ACL prune service (DB-backed).

Verifies that orphaned item ids are removed from AclPermission policies when
the referenced entity is deleted, and that existing ids are preserved.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.security.acl_prune_service import prune_orphaned_acl_ids
from openhands.ev2.security.security_models import AclPermission, Permitted
from openhands.ev2.user.user_models import User


@pytest.mark.asyncio
class TestPruneOrphanedAclIds:
    """Prune removes ids referencing deleted entities, keeps existing ones."""

    async def test_prunes_orphaned_user_ids(self, session: AsyncSession) -> None:
        live_user = User(email="live@example.com", username="live", enabled=True)
        session.add(live_user)
        await session.flush()
        live_id = live_user.id
        orphan_id = uuid.uuid4()

        role = Role(
            name="test-acl-prune",
            user_permission=AclPermission(item_ids=[live_id, orphan_id], on_match=Permitted()),
        )
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 1

        await session.refresh(role)
        assert isinstance(role.user_permission, AclPermission)
        assert live_id in role.user_permission.item_ids
        assert orphan_id not in role.user_permission.item_ids

    async def test_no_orphans_no_change(self, session: AsyncSession) -> None:
        live_user = User(email="live2@example.com", username="live2", enabled=True)
        session.add(live_user)
        await session.flush()
        live_id = live_user.id

        role = Role(
            name="test-acl-no-prune",
            user_permission=AclPermission(item_ids=[live_id], on_match=Permitted()),
        )
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 0

        await session.refresh(role)
        assert isinstance(role.user_permission, AclPermission)
        assert live_id in role.user_permission.item_ids

    async def test_non_acl_permission_skipped(self, session: AsyncSession) -> None:
        role = Role(name="test-non-acl", user_permission=Permitted())
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 0

    async def test_prunes_orphans_keeps_live(self, session: AsyncSession) -> None:
        live_user = User(email="live3@example.com", username="live3", enabled=True)
        session.add(live_user)
        await session.flush()
        live_id = live_user.id
        orphan_id = uuid.uuid4()

        role = Role(
            name="test-prune-keep-live",
            user_permission=AclPermission(item_ids=[live_id, orphan_id], on_match=Permitted()),
        )
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 1

        await session.refresh(role)
        policy = role.user_permission
        assert isinstance(policy, AclPermission)
        assert set(policy.item_ids) == {live_id}
