"""Service layer for the DB-backed sandbox snapshot resource.

CRUD over :class:`SandboxSnapshot` (create/read/delete only — no update). The
artifact storage is hidden inside the sandbox service (local file for Docker,
S3 for K8s); this service owns the DB index row. The create flow delegates
artifact capture to the :class:`SandboxService` and stores the resulting
``download_url`` in the DB row.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_snapshot_models import SandboxSnapshot
from openhands.ev2.sandbox.sandbox_snapshot_schemas import (
    SandboxSnapshotBatchDelete,
    SandboxSnapshotBatchOp,
    SandboxSnapshotCreate,
    SandboxSnapshotRead,
    SandboxSnapshotSearchFilter,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SandboxSnapshotNotFoundError(Exception):
    """Raised when a sandbox snapshot does not exist or is out of scope."""


class SandboxSnapshotPermissionScopeError(Exception):
    """Raised when a snapshot create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class SandboxSnapshotService:
    """CRUD over :class:`SandboxSnapshot` (DB index + service-owned artifacts)."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    def to_read(
        self, snapshot: SandboxSnapshot, *, download_url: str | None = None
    ) -> SandboxSnapshotRead:
        """Build the API read model, overriding ``download_url`` when needed."""
        return SandboxSnapshotRead.model_validate(
            {
                "id": snapshot.id,
                "creator_id": snapshot.creator_id,
                "sandbox_template_id": snapshot.sandbox_template_id,
                "sandbox_id": snapshot.sandbox_id,
                "schema": snapshot.schema,
                "download_url": download_url or snapshot.download_url,
                "size_bytes": snapshot.size_bytes,
                "created_at": snapshot.created_at,
            }
        )

    async def create_from_sandbox(
        self,
        payload: SandboxSnapshotCreate,
        *,
        creator_id: uuid.UUID,
        download_url: str,
        size_bytes: int | None = None,
    ) -> SandboxSnapshot:
        """Create a snapshot DB row from an existing sandbox.

        The artifact capture itself is performed by the sandbox service; this
        method only persists the index row.
        """
        snapshot = SandboxSnapshot(
            creator_id=creator_id,
            sandbox_template_id=payload.sandbox_template_id,
            schema=payload.schema_type or "docker-workspace-tar-v1",
            download_url=download_url,
            sandbox_id=payload.sandbox_id,
            size_bytes=size_bytes,
        )
        if not self._perm_filter.matches(snapshot):
            raise SandboxSnapshotPermissionScopeError(str(payload.sandbox_id))
        self._session.add(snapshot)
        await self._session.flush()
        await self._session.refresh(snapshot)
        return snapshot

    async def create_from_file(
        self,
        payload: SandboxSnapshotCreate,
        *,
        creator_id: uuid.UUID,
        download_url: str,
        size_bytes: int | None = None,
    ) -> SandboxSnapshot:
        """Create a snapshot DB row from an uploaded file (no source sandbox)."""
        snapshot = SandboxSnapshot(
            creator_id=creator_id,
            sandbox_template_id=payload.sandbox_template_id,
            schema=payload.schema_type or "docker-workspace-tar-v1",
            download_url=download_url,
            sandbox_id=None,
            size_bytes=size_bytes,
        )
        if not self._perm_filter.matches(snapshot):
            raise SandboxSnapshotPermissionScopeError("file import")
        self._session.add(snapshot)
        await self._session.flush()
        await self._session.refresh(snapshot)
        return snapshot

    async def get(self, snapshot_id: uuid.UUID) -> SandboxSnapshot:
        """Retrieve a snapshot by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(SandboxSnapshot).where(SandboxSnapshot.id == snapshot_id)
        )
        result = await self._session.execute(stmt)
        snapshot = result.scalar_one_or_none()
        if snapshot is None:
            raise SandboxSnapshotNotFoundError(str(snapshot_id))
        return snapshot

    async def get_many(self, snapshot_ids: list[uuid.UUID]) -> list[SandboxSnapshot | None]:
        """Retrieve snapshots by ids, positionally aligned with ``None`` for misses."""
        if not snapshot_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(SandboxSnapshot).where(SandboxSnapshot.id.in_(snapshot_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, SandboxSnapshot] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(sid) for sid in snapshot_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SandboxSnapshotSearchFilter | None = None,
    ) -> tuple[list[SandboxSnapshot], uuid.UUID | None]:
        """Search snapshots ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(SandboxSnapshot).order_by(SandboxSnapshot.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(SandboxSnapshot.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: SandboxSnapshotSearchFilter | None = None) -> int:
        """Count snapshots visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(SandboxSnapshot))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def delete(self, snapshot_id: uuid.UUID) -> SandboxSnapshot:
        """Delete a snapshot DB row. Returns the row so the caller can clean up the artifact."""
        snapshot = await self.get(snapshot_id)
        await self._session.delete(snapshot)
        await self._session.flush()
        return snapshot

    async def apply_batch(
        self,
        operations: list[SandboxSnapshotBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxSnapshot] | None],
    ) -> list[SandboxSnapshot | None]:
        """Apply delete operations in one caller-owned transaction."""
        results: list[SandboxSnapshot | None] = []
        for op in operations:
            if isinstance(op, SandboxSnapshotBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_delete(
        self,
        op: SandboxSnapshotBatchDelete,
        perm_filters: dict[Action, SearchFilter[SandboxSnapshot] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await SandboxSnapshotService(self._session, filt).delete(op.id)
