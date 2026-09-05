"""Service layer for sandbox templates, sandboxes, and snapshots."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import (
    DockerSandboxRuntimeState,
    FuseySandboxSnapshotArtifact,
    FuseySandboxStorageSpec,
    OpenHandsAgentServerState,
    Sandbox,
    SandboxCompute,
    SandboxComputeStatus,
    SandboxFilesystem,
    SandboxFilesystemStatus,
    SandboxSnapshot,
    SandboxSnapshotStatus,
    SandboxStatus,
    SandboxStorageKind,
    SandboxTemplate,
)
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxBatchCreate,
    SandboxBatchDelete,
    SandboxBatchOp,
    SandboxBatchUpdate,
    SandboxCreate,
    SandboxSearchFilter,
    SandboxSnapshotBatchCreate,
    SandboxSnapshotBatchDelete,
    SandboxSnapshotBatchOp,
    SandboxSnapshotBatchUpdate,
    SandboxSnapshotCreate,
    SandboxSnapshotSearchFilter,
    SandboxSnapshotUpdate,
    SandboxTemplateBatchCreate,
    SandboxTemplateBatchDelete,
    SandboxTemplateBatchOp,
    SandboxTemplateBatchUpdate,
    SandboxTemplateCreate,
    SandboxTemplateSearchFilter,
    SandboxTemplateUpdate,
    SandboxUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SandboxNotFoundError(Exception):
    """Raised when a sandbox does not exist or is out of scope."""


class SandboxTemplateNotFoundError(Exception):
    """Raised when a template does not exist or is out of scope."""


class SandboxSnapshotNotFoundError(Exception):
    """Raised when a snapshot does not exist or is out of scope."""


class SandboxInvalidStateError(Exception):
    """Raised when a lifecycle action is not valid for the current state."""


class SandboxPermissionScopeError(Exception):
    """Raised when a new sandbox row falls outside the principal's scope."""


class SandboxTemplatePermissionScopeError(Exception):
    """Raised when a new template row falls outside the principal's scope."""


class SandboxSnapshotPermissionScopeError(Exception):
    """Raised when a new snapshot row falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class SandboxTemplateService:
    """CRUD operations over sandbox templates."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self, payload: SandboxTemplateCreate, *, user_id: uuid.UUID
    ) -> SandboxTemplate:
        template = SandboxTemplate(
            name=payload.name,
            provider_kind=payload.provider_kind,
            template_spec=payload.template_spec,
            server_spec=payload.server_spec,
            storage_spec=payload.storage_spec,
            user_id=user_id,
            description=payload.description,
            idle_timeout_seconds=payload.idle_timeout_seconds,
            max_lifetime_seconds=payload.max_lifetime_seconds,
        )
        if not self._perm_filter.matches(template):
            raise SandboxTemplatePermissionScopeError(payload.name)
        self._session.add(template)
        await self._session.flush()
        await self._session.refresh(template)
        return template

    async def get(self, template_id: uuid.UUID) -> SandboxTemplate:
        stmt = self._perm_filter.filter_sql(
            select(SandboxTemplate).where(SandboxTemplate.id == template_id)
        )
        result = await self._session.execute(stmt)
        template = result.scalar_one_or_none()
        if template is None:
            raise SandboxTemplateNotFoundError(str(template_id))
        return template

    async def get_many(self, template_ids: list[uuid.UUID]) -> list[SandboxTemplate | None]:
        if not template_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(SandboxTemplate).where(SandboxTemplate.id.in_(template_ids))
        )
        result = await self._session.execute(stmt)
        by_id = {template.id: template for template in result.scalars().all()}
        return [by_id.get(template_id) for template_id in template_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SandboxTemplateSearchFilter | None = None,
    ) -> tuple[list[SandboxTemplate], uuid.UUID | None]:
        stmt = self._perm_filter.filter_sql(select(SandboxTemplate).order_by(SandboxTemplate.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(SandboxTemplate.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        templates = list(result.scalars().all())
        next_cursor = templates[-1].id if len(templates) == limit else None
        return templates, next_cursor

    async def update(
        self, template_id: uuid.UUID, payload: SandboxTemplateUpdate
    ) -> SandboxTemplate:
        template = await self.get(template_id)
        for field in payload.model_fields_set:
            setattr(template, field, getattr(payload, field))
        await self._session.flush()
        await self._session.refresh(template)
        return template

    async def delete(self, template_id: uuid.UUID) -> None:
        template = await self.get(template_id)
        await self._session.delete(template)
        await self._session.flush()

    async def count(self, search_filter: SandboxTemplateSearchFilter | None = None) -> int:
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(SandboxTemplate))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[SandboxTemplateBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
        *,
        user_id: uuid.UUID,
    ) -> list[SandboxTemplate | None]:
        results: list[SandboxTemplate | None] = []
        for op in operations:
            if isinstance(op, SandboxTemplateBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                results.append(
                    await SandboxTemplateService(self._session, filt).create(
                        op.data, user_id=user_id
                    )
                )
            elif isinstance(op, SandboxTemplateBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(
                    await SandboxTemplateService(self._session, filt).update(op.id, op.data)
                )
            elif isinstance(op, SandboxTemplateBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await SandboxTemplateService(self._session, filt).delete(op.id)
                results.append(None)
        return results


class SandboxService:
    """CRUD and lifecycle operations over durable sandboxes."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: SandboxCreate,
        *,
        user_id: uuid.UUID,
        template_filter: SearchFilter[SandboxTemplate] = ALL,
        snapshot_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> Sandbox:
        template = await SandboxTemplateService(self._session, template_filter).get(
            payload.template_id
        )
        snapshot = None
        if payload.snapshot_id is not None:
            snapshot = await SandboxSnapshotService(self._session, snapshot_filter).get(
                payload.snapshot_id
            )
        filesystem = await self._filesystem_for_create(payload, template, snapshot, user_id=user_id)
        sandbox = Sandbox(
            name=payload.name,
            template_id=template.id,
            filesystem_id=filesystem.id,
            provider_kind=template.provider_kind,
            user_id=user_id,
            status=SandboxStatus.INACTIVE,
            description=payload.description,
            status_reason=None,
            current_snapshot_id=snapshot.id if snapshot is not None else None,
            current_compute_id=None,
            exposed_urls=[],
            idle_timeout_seconds=payload.idle_timeout_seconds,
            max_lifetime_seconds=payload.max_lifetime_seconds,
        )
        if not self._perm_filter.matches(sandbox):
            raise SandboxPermissionScopeError(payload.name)
        self._session.add(sandbox)
        await self._session.flush()
        await self._session.refresh(sandbox)
        return sandbox

    async def _filesystem_for_create(
        self,
        payload: SandboxCreate,
        template: SandboxTemplate,
        snapshot: SandboxSnapshot | None,
        *,
        user_id: uuid.UUID,
    ) -> SandboxFilesystem:
        if payload.filesystem_id is not None:
            filesystem = await self._get_owned_filesystem(payload.filesystem_id, user_id=user_id)
            if snapshot is not None and snapshot.filesystem_id != filesystem.id:
                raise SandboxInvalidStateError(
                    "snapshot does not belong to the requested filesystem"
                )
            return filesystem
        if not isinstance(template.storage_spec, FuseySandboxStorageSpec):
            raise SandboxInvalidStateError("only Fusey storage is supported")
        filesystem = SandboxFilesystem(
            storage_kind=SandboxStorageKind.FUSEY,
            object_prefix=f"sandbox-filesystems/{uuid.uuid4()}/",
            user_id=user_id,
            status=SandboxFilesystemStatus.READY,
            head_generation=snapshot.generation if snapshot is not None else None,
            mount_path_default=template.storage_spec.mount_path,
            max_size_bytes=template.storage_spec.max_size_bytes,
            size_bytes_estimate=None,
        )
        self._session.add(filesystem)
        await self._session.flush()
        await self._session.refresh(filesystem)
        return filesystem

    async def _get_owned_filesystem(
        self,
        filesystem_id: uuid.UUID,
        *,
        user_id: uuid.UUID,
    ) -> SandboxFilesystem:
        result = await self._session.execute(
            select(SandboxFilesystem).where(
                SandboxFilesystem.id == filesystem_id,
                SandboxFilesystem.user_id == user_id,
            )
        )
        filesystem = result.scalar_one_or_none()
        if filesystem is None:
            raise SandboxInvalidStateError("filesystem not found")
        return filesystem

    async def get(self, sandbox_id: uuid.UUID) -> Sandbox:
        stmt = self._perm_filter.filter_sql(select(Sandbox).where(Sandbox.id == sandbox_id))
        result = await self._session.execute(stmt)
        sandbox = result.scalar_one_or_none()
        if sandbox is None:
            raise SandboxNotFoundError(str(sandbox_id))
        return sandbox

    async def get_many(self, sandbox_ids: list[uuid.UUID]) -> list[Sandbox | None]:
        if not sandbox_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(Sandbox).where(Sandbox.id.in_(sandbox_ids)))
        result = await self._session.execute(stmt)
        by_id = {sandbox.id: sandbox for sandbox in result.scalars().all()}
        return [by_id.get(sandbox_id) for sandbox_id in sandbox_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SandboxSearchFilter | None = None,
    ) -> tuple[list[Sandbox], uuid.UUID | None]:
        stmt = self._perm_filter.filter_sql(select(Sandbox).order_by(Sandbox.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Sandbox.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        sandboxes = list(result.scalars().all())
        next_cursor = sandboxes[-1].id if len(sandboxes) == limit else None
        return sandboxes, next_cursor

    async def update(self, sandbox_id: uuid.UUID, payload: SandboxUpdate) -> Sandbox:
        sandbox = await self.get(sandbox_id)
        for field in payload.model_fields_set:
            setattr(sandbox, field, getattr(payload, field))
        await self._session.flush()
        await self._session.refresh(sandbox)
        return sandbox

    async def activate(self, sandbox_id: uuid.UUID) -> Sandbox:
        sandbox = await self.get(sandbox_id)
        if sandbox.status not in (SandboxStatus.INACTIVE, SandboxStatus.ERROR):
            raise SandboxInvalidStateError(f"cannot activate sandbox from {sandbox.status}")
        now = datetime.now(UTC)
        sandbox.status = SandboxStatus.ACTIVATING
        sandbox.status_reason = None
        compute = SandboxCompute(
            provider_kind=sandbox.provider_kind,
            status=SandboxComputeStatus.SERVING,
            runtime_state=DockerSandboxRuntimeState(
                container_id=f"docker-placeholder-{sandbox.id}"
            ),
            server_state=OpenHandsAgentServerState(initialized=True, healthy=True),
            template_id=sandbox.template_id,
            sandbox_id=sandbox.id,
            mount_lease_id=None,
            claimed_at=now,
            last_health_check_at=now,
        )
        self._session.add(compute)
        await self._session.flush()
        sandbox.current_compute_id = compute.id
        sandbox.status = SandboxStatus.ACTIVE
        sandbox.last_activated_at = now
        sandbox.last_activity_at = now
        sandbox.filesystem.status = SandboxFilesystemStatus.MOUNTED
        await self._session.flush()
        await self._session.refresh(sandbox)
        return sandbox

    async def deactivate(self, sandbox_id: uuid.UUID) -> Sandbox:
        sandbox = await self.get(sandbox_id)
        if sandbox.status not in (SandboxStatus.ACTIVE, SandboxStatus.ERROR):
            raise SandboxInvalidStateError(f"cannot deactivate sandbox from {sandbox.status}")
        now = datetime.now(UTC)
        sandbox.status = SandboxStatus.DEACTIVATING
        if sandbox.current_compute_id is not None:
            compute = await self._load_compute(sandbox.current_compute_id)
            if compute is not None:
                compute.status = SandboxComputeStatus.RELEASED
                compute.sandbox_id = None
                compute.terminated_at = now
        sandbox.current_compute_id = None
        sandbox.status = SandboxStatus.INACTIVE
        sandbox.last_deactivated_at = now
        sandbox.filesystem.status = SandboxFilesystemStatus.READY
        await self._session.flush()
        await self._session.refresh(sandbox)
        return sandbox

    async def delete(self, sandbox_id: uuid.UUID) -> None:
        sandbox = await self.get(sandbox_id)
        now = datetime.now(UTC)
        sandbox.status = SandboxStatus.DELETING
        sandbox.delete_started_at = now
        if sandbox.current_compute_id is not None:
            compute = await self._load_compute(sandbox.current_compute_id)
            if compute is not None:
                compute.status = SandboxComputeStatus.DELETED
                compute.terminated_at = now
        filesystem = sandbox.filesystem
        await self._session.flush()
        await self._session.delete(sandbox)
        await self._session.flush()
        await self._session.delete(filesystem)
        await self._session.flush()

    async def _load_compute(self, compute_id: uuid.UUID) -> SandboxCompute | None:
        result = await self._session.execute(
            select(SandboxCompute).where(SandboxCompute.id == compute_id)
        )
        return result.scalar_one_or_none()

    async def count(self, search_filter: SandboxSearchFilter | None = None) -> int:
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Sandbox))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[SandboxBatchOp],
        perm_filters: dict[Action, SearchFilter[Sandbox] | None],
        *,
        user_id: uuid.UUID,
        template_filter: SearchFilter[SandboxTemplate] = ALL,
        snapshot_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> list[Sandbox | None]:
        results: list[Sandbox | None] = []
        for op in operations:
            if isinstance(op, SandboxBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                results.append(
                    await SandboxService(self._session, filt).create(
                        op.data,
                        user_id=user_id,
                        template_filter=template_filter,
                        snapshot_filter=snapshot_filter,
                    )
                )
            elif isinstance(op, SandboxBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(await SandboxService(self._session, filt).update(op.id, op.data))
            elif isinstance(op, SandboxBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await SandboxService(self._session, filt).delete(op.id)
                results.append(None)
        return results


class SandboxSnapshotService:
    """CRUD operations over named Fusey filesystem snapshots."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: SandboxSnapshotCreate,
        *,
        user_id: uuid.UUID,
        sandbox_filter: SearchFilter[Sandbox] = ALL,
    ) -> SandboxSnapshot:
        sandbox = await SandboxService(self._session, sandbox_filter).get(payload.source_sandbox_id)
        generation = (
            payload.generation or sandbox.filesystem.head_generation or f"generation-{uuid.uuid4()}"
        )
        sandbox.filesystem.head_generation = generation
        artifact = FuseySandboxSnapshotArtifact(
            filesystem_id=sandbox.filesystem_id,
            generation=generation,
        )
        snapshot = SandboxSnapshot(
            name=payload.name,
            filesystem_id=sandbox.filesystem_id,
            storage_kind=SandboxStorageKind.FUSEY,
            generation=generation,
            snapshot_artifact=artifact,
            user_id=user_id,
            description=payload.description,
            source_sandbox_id=sandbox.id,
            status=SandboxSnapshotStatus.READY,
            expires_at=payload.expires_at,
        )
        if not self._perm_filter.matches(snapshot):
            raise SandboxSnapshotPermissionScopeError(payload.name)
        self._session.add(snapshot)
        await self._session.flush()
        sandbox.current_snapshot_id = snapshot.id
        await self._session.flush()
        await self._session.refresh(snapshot)
        return snapshot

    async def get(self, snapshot_id: uuid.UUID) -> SandboxSnapshot:
        stmt = self._perm_filter.filter_sql(
            select(SandboxSnapshot).where(SandboxSnapshot.id == snapshot_id)
        )
        result = await self._session.execute(stmt)
        snapshot = result.scalar_one_or_none()
        if snapshot is None:
            raise SandboxSnapshotNotFoundError(str(snapshot_id))
        return snapshot

    async def get_many(self, snapshot_ids: list[uuid.UUID]) -> list[SandboxSnapshot | None]:
        if not snapshot_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(SandboxSnapshot).where(SandboxSnapshot.id.in_(snapshot_ids))
        )
        result = await self._session.execute(stmt)
        by_id = {snapshot.id: snapshot for snapshot in result.scalars().all()}
        return [by_id.get(snapshot_id) for snapshot_id in snapshot_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SandboxSnapshotSearchFilter | None = None,
    ) -> tuple[list[SandboxSnapshot], uuid.UUID | None]:
        stmt = self._perm_filter.filter_sql(select(SandboxSnapshot).order_by(SandboxSnapshot.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(SandboxSnapshot.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        snapshots = list(result.scalars().all())
        next_cursor = snapshots[-1].id if len(snapshots) == limit else None
        return snapshots, next_cursor

    async def update(
        self, snapshot_id: uuid.UUID, payload: SandboxSnapshotUpdate
    ) -> SandboxSnapshot:
        snapshot = await self.get(snapshot_id)
        for field in payload.model_fields_set:
            setattr(snapshot, field, getattr(payload, field))
        await self._session.flush()
        await self._session.refresh(snapshot)
        return snapshot

    async def delete(self, snapshot_id: uuid.UUID) -> None:
        snapshot = await self.get(snapshot_id)
        snapshot.status = SandboxSnapshotStatus.DELETING
        await self._session.flush()
        await self._session.delete(snapshot)
        await self._session.flush()

    async def count(self, search_filter: SandboxSnapshotSearchFilter | None = None) -> int:
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(SandboxSnapshot))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[SandboxSnapshotBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxSnapshot] | None],
        *,
        user_id: uuid.UUID,
        sandbox_filter: SearchFilter[Sandbox] = ALL,
    ) -> list[SandboxSnapshot | None]:
        results: list[SandboxSnapshot | None] = []
        for op in operations:
            if isinstance(op, SandboxSnapshotBatchCreate):
                filt = perm_filters.get(Action.CREATE)
                if filt is None:
                    raise BatchPermissionDeniedError("create")
                results.append(
                    await SandboxSnapshotService(self._session, filt).create(
                        op.data,
                        user_id=user_id,
                        sandbox_filter=sandbox_filter,
                    )
                )
            elif isinstance(op, SandboxSnapshotBatchUpdate):
                filt = perm_filters.get(Action.UPDATE)
                if filt is None:
                    raise BatchPermissionDeniedError("update")
                results.append(
                    await SandboxSnapshotService(self._session, filt).update(op.id, op.data)
                )
            elif isinstance(op, SandboxSnapshotBatchDelete):
                filt = perm_filters.get(Action.DELETE)
                if filt is None:
                    raise BatchPermissionDeniedError("delete")
                await SandboxSnapshotService(self._session, filt).delete(op.id)
                results.append(None)
        return results


__all__ = [
    "BatchPermissionDeniedError",
    "SandboxInvalidStateError",
    "SandboxNotFoundError",
    "SandboxPermissionScopeError",
    "SandboxService",
    "SandboxSnapshotNotFoundError",
    "SandboxSnapshotPermissionScopeError",
    "SandboxSnapshotService",
    "SandboxTemplateNotFoundError",
    "SandboxTemplatePermissionScopeError",
    "SandboxTemplateService",
]
