"""Unit tests for sandbox usage logging: the per-poll record service."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import make_principal as _make_principal

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox.sandbox_config_models import SandboxConfig
from openhands.ev2.sandbox.sandbox_models import SandboxStatus
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.sandbox.sandbox_usage_models import SandboxUsage
from openhands.ev2.sandbox.sandbox_usage_service import SandboxUsageService
from openhands.ev2.user.user_models import User


async def _seed_config(session: AsyncSession, *, username: str) -> tuple[uuid.UUID, uuid.UUID]:
    """Insert a user, template, and sandbox config; return (config_id, user_id)."""
    user = await _make_principal(session, email=f"{username}@example.com", username=username)
    template = SandboxTemplate(creator_id=user.id, docker_image_tag="img:latest")
    session.add(template)
    await session.flush()
    config = SandboxConfig(
        creator_id=user.id,
        sandbox_template_id=template.id,
        session_api_key="jwe-ciphertext",
    )
    session.add(config)
    await session.flush()
    return config.id, user.id


def _sandbox(sandbox_id: str, sandbox_config_id: uuid.UUID | None) -> DockerSandbox:
    return DockerSandbox(
        id=sandbox_id,
        sandbox_template_id="tmpl",
        sandbox_config_id=str(sandbox_config_id) if sandbox_config_id else None,
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
    )


class TestRecordUsage:
    async def test_records_one_row_per_claimed_sandbox(self, session: AsyncSession) -> None:
        config_a, _ = await _seed_config(session, username="usage-a")
        config_b, _ = await _seed_config(session, username="usage-b")
        service = SandboxUsageService(session)
        count = await service.record_usage([_sandbox("sb-1", config_a), _sandbox("sb-2", config_b)])
        assert count == 2
        rows = (
            (await session.execute(select(SandboxUsage).order_by(SandboxUsage.sandbox_config_id)))
            .scalars()
            .all()
        )
        assert [row.sandbox_config_id for row in rows] == sorted([config_a, config_b])
        # cpu/disk stay NULL until sandbox providers report resource stats.
        assert all(row.cpu is None and row.disk is None for row in rows)
        assert all(row.created_at is not None for row in rows)

    async def test_skips_unclaimed_warm_sandboxes(self, session: AsyncSession) -> None:
        config_id, _ = await _seed_config(session, username="usage-warm")
        service = SandboxUsageService(session)
        count = await service.record_usage(
            [_sandbox("sb-claimed", config_id), _sandbox("sb-warm", None)]
        )
        assert count == 1
        rows = (await session.execute(select(SandboxUsage))).scalars().all()
        assert [row.sandbox_config_id for row in rows] == [config_id]

    async def test_repeated_polls_append_rows(self, session: AsyncSession) -> None:
        config_id, _ = await _seed_config(session, username="usage-repeat")
        service = SandboxUsageService(session)
        await service.record_usage([_sandbox("sb-1", config_id)])
        count = await service.record_usage([_sandbox("sb-1", config_id)])
        assert count == 1
        rows = (
            (await session.execute(select(SandboxUsage).order_by(SandboxUsage.created_at)))
            .scalars()
            .all()
        )
        assert len(rows) == 2
        assert rows[0].created_at < rows[1].created_at

    async def test_empty_poll_records_nothing(self, session: AsyncSession) -> None:
        service = SandboxUsageService(session)
        assert await service.record_usage([]) == 0
        rows = (await session.execute(select(SandboxUsage))).scalars().all()
        assert rows == []

    async def test_stats_columns_accept_values(self, session: AsyncSession) -> None:
        config_id, _ = await _seed_config(session, username="usage-stats")
        session.add(SandboxUsage(sandbox_config_id=config_id, cpu=0.5, disk=1024.0))
        await session.commit()
        row = (await session.execute(select(SandboxUsage))).scalar_one()
        assert row.cpu == 0.5
        assert row.disk == 1024.0

    async def test_usage_associates_with_the_owning_user(self, session: AsyncSession) -> None:
        config_id, user_id = await _seed_config(session, username="usage-owner")
        service = SandboxUsageService(session)
        await service.record_usage([_sandbox("sb-1", config_id)])
        rows = (
            (
                await session.execute(
                    select(SandboxUsage)
                    .join(SandboxConfig)
                    .join(User, SandboxConfig.creator_id == User.id)
                    .where(User.id == user_id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 1
        assert rows[0].sandbox_config_id == config_id

    async def test_config_with_usage_cannot_be_deleted(self, session: AsyncSession) -> None:
        """The FK is ON DELETE RESTRICT: usage history outlives the sandbox."""
        config_id, _ = await _seed_config(session, username="usage-restrict")
        service = SandboxUsageService(session)
        await service.record_usage([_sandbox("sb-1", config_id)])
        with pytest.raises(IntegrityError):
            await session.execute(delete(SandboxConfig).where(SandboxConfig.id == config_id))
