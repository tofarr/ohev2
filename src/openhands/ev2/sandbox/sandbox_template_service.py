"""Service layer for the DB-backed sandbox template resource.

CRUD over :class:`SandboxTemplate` (mutable: create, read, update, delete).
Follows the ``routers → services → repositories → models`` layering: the
service owns authorization scoping via ``perm_filter.filter_sql(...)`` and the
session is injected per-request.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.sandbox.sandbox_models import ExposedPort
from openhands.ev2.sandbox.sandbox_template_models import SandboxTemplate
from openhands.ev2.sandbox.sandbox_template_schemas import (
    SandboxTemplateBatchCreate,
    SandboxTemplateBatchDelete,
    SandboxTemplateBatchOp,
    SandboxTemplateBatchUpdate,
    SandboxTemplateCreate,
    SandboxTemplateRead,
    SandboxTemplateSearchFilter,
    SandboxTemplateUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SandboxTemplateNotFoundError(Exception):
    """Raised when a sandbox template does not exist or is out of scope."""


class SandboxTemplatePermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class SandboxTemplateInUseError(Exception):
    """Raised when deleting a template referenced by a sandbox config (FK RESTRICT)."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


def _exposed_ports_to_dicts(ports: list[ExposedPort]) -> list[dict[str, Any]]:
    return [p.model_dump() for p in ports]


def _dicts_to_exposed_ports(data: list[dict[str, Any]]) -> list[ExposedPort]:
    return [ExposedPort(**d) for d in data]


class SandboxTemplateService:
    """CRUD over :class:`SandboxTemplate`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    def to_read(self, template: SandboxTemplate) -> SandboxTemplateRead:
        """Build the API read model from an ORM row."""
        return SandboxTemplateRead(
            id=template.id,
            creator_id=template.creator_id,
            docker_image_tag=template.docker_image_tag,
            delete_after_idle_seconds=template.delete_after_idle_seconds,
            in_container_user_id=template.in_container_user_id,
            in_container_group_id=template.in_container_group_id,
            max_memory=template.max_memory,
            exposed_ports=_dicts_to_exposed_ports(template.exposed_ports),
            env_vars=template.env_vars,
            working_dir=template.working_dir,
            snapshot_dirs=template.snapshot_dirs,
            snapshot_on_deactivate=template.snapshot_on_deactivate,
            meta=template.meta,
            created_at=template.created_at,
            updated_at=template.updated_at,
        )

    async def create(
        self,
        payload: SandboxTemplateCreate,
        *,
        creator_id: uuid.UUID,
    ) -> SandboxTemplate:
        """Create a sandbox template."""
        template = SandboxTemplate(
            creator_id=creator_id,
            docker_image_tag=payload.docker_image_tag,
            delete_after_idle_seconds=payload.delete_after_idle_seconds,
            in_container_user_id=payload.in_container_user_id,
            in_container_group_id=payload.in_container_group_id,
            max_memory=payload.max_memory,
            exposed_ports=_exposed_ports_to_dicts(payload.exposed_ports),
            env_vars=payload.env_vars,
            working_dir=payload.working_dir,
            snapshot_dirs=payload.snapshot_dirs,
            snapshot_on_deactivate=payload.snapshot_on_deactivate,
            meta=payload.meta,
        )
        if not self._perm_filter.matches(template):
            raise SandboxTemplatePermissionScopeError(payload.docker_image_tag)
        self._session.add(template)
        await self._session.flush()
        await self._session.refresh(template)
        return template

    async def get(self, template_id: uuid.UUID) -> SandboxTemplate:
        """Retrieve a template by id, scoped by ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(
            select(SandboxTemplate).where(SandboxTemplate.id == template_id)
        )
        result = await self._session.execute(stmt)
        template = result.scalar_one_or_none()
        if template is None:
            raise SandboxTemplateNotFoundError(str(template_id))
        return template

    async def get_many(self, template_ids: list[uuid.UUID]) -> list[SandboxTemplate | None]:
        """Retrieve templates by ids, positionally aligned with ``None`` for misses."""
        if not template_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(SandboxTemplate).where(SandboxTemplate.id.in_(template_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, SandboxTemplate] = {row.id: row for row in result.scalars().all()}
        return [by_id.get(tid) for tid in template_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: SandboxTemplateSearchFilter | None = None,
    ) -> tuple[list[SandboxTemplate], uuid.UUID | None]:
        """Search templates ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(SandboxTemplate).order_by(SandboxTemplate.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(SandboxTemplate.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def count(self, search_filter: SandboxTemplateSearchFilter | None = None) -> int:
        """Count templates visible to the service's permission filter."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(SandboxTemplate))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def update(
        self,
        template_id: uuid.UUID,
        payload: SandboxTemplateUpdate,
    ) -> SandboxTemplate:
        """Partially update a sandbox template."""
        template = await self.get(template_id)
        fields = payload.model_fields_set
        if "docker_image_tag" in fields and payload.docker_image_tag is not None:
            template.docker_image_tag = payload.docker_image_tag
        if "delete_after_idle_seconds" in fields:
            template.delete_after_idle_seconds = payload.delete_after_idle_seconds
        if "in_container_user_id" in fields:
            template.in_container_user_id = payload.in_container_user_id
        if "in_container_group_id" in fields:
            template.in_container_group_id = payload.in_container_group_id
        if "max_memory" in fields and payload.max_memory is not None:
            template.max_memory = payload.max_memory
        if "exposed_ports" in fields and payload.exposed_ports is not None:
            template.exposed_ports = _exposed_ports_to_dicts(payload.exposed_ports)
        if "env_vars" in fields and payload.env_vars is not None:
            template.env_vars = payload.env_vars
        if "working_dir" in fields and payload.working_dir is not None:
            template.working_dir = payload.working_dir
        if "snapshot_dirs" in fields and payload.snapshot_dirs is not None:
            template.snapshot_dirs = payload.snapshot_dirs
        if "snapshot_on_deactivate" in fields and payload.snapshot_on_deactivate is not None:
            template.snapshot_on_deactivate = payload.snapshot_on_deactivate
        if "meta" in fields and payload.meta is not None:
            template.meta = payload.meta
        await self._session.flush()
        await self._session.refresh(template)
        return template

    async def delete(self, template_id: uuid.UUID) -> None:
        """Delete a sandbox template (RESTRICT if configs reference it)."""
        template = await self.get(template_id)
        try:
            await self._session.delete(template)
            await self._session.flush()
        except IntegrityError as exc:
            raise SandboxTemplateInUseError(str(template_id)) from exc

    async def apply_batch(
        self,
        operations: list[SandboxTemplateBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[SandboxTemplate | None]:
        """Apply create/update/delete operations in one caller-owned transaction."""
        results: list[SandboxTemplate | None] = []
        for op in operations:
            if isinstance(op, SandboxTemplateBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, SandboxTemplateBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, SandboxTemplateBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: SandboxTemplateBatchCreate,
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
        *,
        creator_id: uuid.UUID,
    ) -> SandboxTemplate:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await SandboxTemplateService(self._session, filt).create(
            op.data, creator_id=creator_id
        )

    async def _batch_update(
        self,
        op: SandboxTemplateBatchUpdate,
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
    ) -> SandboxTemplate:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await SandboxTemplateService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: SandboxTemplateBatchDelete,
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await SandboxTemplateService(self._session, filt).delete(op.id)
