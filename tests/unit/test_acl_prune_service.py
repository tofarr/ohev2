"""Unit tests for the ACL prune service (DB-backed).

Verifies that orphaned item ids are removed from ACLPermission policies when
the referenced entity is deleted, and that existing ids are preserved.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.role.role_models import Role
from openhands.ev2.security.acl_prune_service import prune_orphaned_acl_ids
from openhands.ev2.security.security_models import ACLPermission, Action
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
            user_permission=ACLPermission(permitted_ids={Action.READ: [live_id, orphan_id]}),
        )
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 1

        await session.refresh(role)
        assert isinstance(role.user_permission, ACLPermission)
        assert live_id in role.user_permission.permitted_ids[Action.READ]
        assert orphan_id not in role.user_permission.permitted_ids[Action.READ]

    async def test_no_orphans_no_change(self, session: AsyncSession) -> None:
        live_user = User(email="live2@example.com", username="live2", enabled=True)
        session.add(live_user)
        await session.flush()
        live_id = live_user.id

        role = Role(
            name="test-acl-no-prune",
            user_permission=ACLPermission(permitted_ids={Action.READ: [live_id]}),
        )
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 0

        await session.refresh(role)
        assert isinstance(role.user_permission, ACLPermission)
        assert live_id in role.user_permission.permitted_ids[Action.READ]

    async def test_non_acl_permission_skipped(self, session: AsyncSession) -> None:
        from openhands.ev2.security.security_models import Permitted

        role = Role(name="test-non-acl", user_permission=Permitted())
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 0

    async def test_prunes_across_multiple_actions(self, session: AsyncSession) -> None:
        live_user = User(email="live3@example.com", username="live3", enabled=True)
        session.add(live_user)
        await session.flush()
        live_id = live_user.id
        orphan_read = uuid.uuid4()
        orphan_update = uuid.uuid4()

        role = Role(
            name="test-multi-action",
            user_permission=ACLPermission(
                permitted_ids={
                    Action.READ: [live_id, orphan_read],
                    Action.UPDATE: [live_id, orphan_update],
                }
            ),
        )
        session.add(role)
        await session.flush()

        pruned = await prune_orphaned_acl_ids(session)
        assert pruned == 1

        await session.refresh(role)
        policy = role.user_permission
        assert isinstance(policy, ACLPermission)
        assert set(policy.permitted_ids[Action.READ]) == {live_id}
        assert set(policy.permitted_ids[Action.UPDATE]) == {live_id}
