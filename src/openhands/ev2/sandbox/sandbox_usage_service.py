"""Service layer for sandbox usage logging.

:class:`SandboxUsageService.record_usage` appends one
:class:`~openhands.ev2.sandbox.sandbox_usage_models.SandboxUsage` row per
sandbox. It is driven by the background poll loop in
:mod:`openhands.ev2.app` (config ``sandbox_usage_interval``); the loop lists
sandboxes from the configured ``SandboxService`` and passes them here.
"""

from __future__ import annotations

from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import Sandbox
from openhands.ev2.sandbox.sandbox_usage_models import SandboxUsage


class SandboxUsageService:
    """Records per-poll sandbox usage snapshots."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_usage(self, sandboxes: Iterable[Sandbox]) -> int:
        """Append one usage row per sandbox and return the number recorded.

        ``cpu`` / ``disk`` are left ``NULL`` — the :class:`Sandbox` model does
        not carry resource stats yet; providers will populate them later.
        """
        rows = [SandboxUsage(sandbox_id=sandbox.id) for sandbox in sandboxes]
        if not rows:
            return 0
        self._session.add_all(rows)
        await self._session.commit()
        return len(rows)
