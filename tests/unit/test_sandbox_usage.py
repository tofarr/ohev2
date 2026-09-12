"""Unit tests for sandbox usage logging: the per-poll record service."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.docker_sandbox_models import DockerSandbox
from openhands.ev2.sandbox.sandbox_models import SandboxStatus
from openhands.ev2.sandbox.sandbox_usage_models import SandboxUsage
from openhands.ev2.sandbox.sandbox_usage_service import SandboxUsageService


def _sandbox(sandbox_id: str) -> DockerSandbox:
    return DockerSandbox(
        id=sandbox_id,
        sandbox_template_id="tmpl",
        status=SandboxStatus.ACTIVE,
        desired_status=SandboxStatus.ACTIVE,
    )


class TestRecordUsage:
    async def test_records_one_row_per_sandbox(self, session: AsyncSession) -> None:
        service = SandboxUsageService(session)
        count = await service.record_usage([_sandbox("sb-1"), _sandbox("sb-2")])
        assert count == 2
        rows = (
            (await session.execute(select(SandboxUsage).order_by(SandboxUsage.sandbox_id)))
            .scalars()
            .all()
        )
        assert [row.sandbox_id for row in rows] == ["sb-1", "sb-2"]
        # cpu/disk stay NULL until sandbox providers report resource stats.
        assert all(row.cpu is None and row.disk is None for row in rows)
        assert all(row.created_at is not None for row in rows)

    async def test_repeated_polls_append_rows(self, session: AsyncSession) -> None:
        service = SandboxUsageService(session)
        await service.record_usage([_sandbox("sb-1")])
        count = await service.record_usage([_sandbox("sb-1")])
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
        session.add(SandboxUsage(sandbox_id="sb-1", cpu=0.5, disk=1024.0))
        await session.commit()
        row = (await session.execute(select(SandboxUsage))).scalar_one()
        assert row.cpu == 0.5
        assert row.disk == 1024.0
