"""Service layer for sandbox usage logging.

:class:`SandboxUsageService.record_usage` appends one
:class:`~openhands.ev2.sandbox.sandbox_usage_models.SandboxUsage` row per
claimed sandbox, keyed by ``sandbox_config_id`` so usage associates with the
DB-backed config and through it the owning user and their groups. It is
driven by the background poll loop in :mod:`openhands.ev2.app` (config
``sandbox_usage_interval``); the loop lists sandboxes from the configured
``SandboxService`` and passes them here.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import Sandbox
from openhands.ev2.sandbox.sandbox_usage_models import SandboxUsage


class SandboxUsageService:
    """Records per-poll sandbox usage snapshots."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record_usage(self, sandboxes: Iterable[Sandbox]) -> int:
        """Append one usage row per claimed sandbox and return the count.

        Sandboxes without a ``sandbox_config_id`` (unclaimed warm-pool
        sandboxes) are skipped — usage is tracked against the DB-backed
        config, not the provider sandbox. ``cpu`` / ``disk`` are left
        ``NULL`` — the :class:`Sandbox` model does not carry resource stats
        yet; providers will populate them later.
        """
        rows = [
            SandboxUsage(sandbox_config_id=uuid.UUID(sandbox.sandbox_config_id))
            for sandbox in sandboxes
            if sandbox.sandbox_config_id
        ]
        if not rows:
            return 0
        self._session.add_all(rows)
        await self._session.commit()
        return len(rows)
