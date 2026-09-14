"""Service layer for the conversation template feature.

CRUD over :class:`ConversationTemplate`. Services contain business logic; the
service holds the effective ``perm_filter`` (from the centralized permission
checker) as a field, set at construction, that scopes the SQL to rows the
principal is allowed to see/modify; :meth:`create` validates the incoming item
against it in memory (AGENTS.md §9 — authorization enforced in services, not
just routers).

The ``llm_id`` FK is validated on create/update (a deleted LLM nulls the
template's default per ``ON DELETE SET NULL``, but an explicit dangling id is
rejected). The list-typed references (``mcp_server_config_ids``,
``secret_provider_ids``, ``static_secret_ids``) are stored as stringified UUID
lists in JSONB; they are resolved by the start service (issue #2).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.conversation_template.conversation_template_models import (
    ConversationTemplate,
)
from openhands.ev2.conversation_template.conversation_template_schemas import (
    ConversationTemplateBatchCreate,
    ConversationTemplateBatchDelete,
    ConversationTemplateBatchOp,
    ConversationTemplateBatchUpdate,
    ConversationTemplateCreate,
    ConversationTemplateSearchFilter,
    ConversationTemplateUpdate,
    _stringify_ids,
)
from openhands.ev2.llm.llm_models import StoredLLM
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter

# Field -> value transform for partial updates. Id lists and opaque dicts copy
# wholesale; the transform is the identity otherwise.


def _identity(value: Any) -> Any:
    return value


_UPDATE_TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "name": _identity,
    "agent_kind": _identity,
    "mcp_server_config_ids": _stringify_ids,
    "secret_provider_ids": _stringify_ids,
    "static_secret_ids": _stringify_ids,
    "agent_config": _identity,
    "conversation_config": _identity,
    "default_callbacks": _identity,
}


class ConversationTemplateNotFoundError(Exception):
    """Raised when a conversation template id does not exist (or is out of scope)."""


class ConversationTemplatePermissionScopeError(Exception):
    """Raised when a create/update payload falls outside the principal's scope."""


class ReferencedEntityNotFoundError(Exception):
    """Raised when a create/update references a governable row that does not exist."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


class ConversationTemplateService:
    """CRUD over :class:`ConversationTemplate`."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[ConversationTemplate] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    async def create(
        self,
        payload: ConversationTemplateCreate,
        *,
        creator_id: uuid.UUID,
    ) -> ConversationTemplate:
        """Persist a conversation template.

        Raises :class:`ConversationTemplatePermissionScopeError` if the
        prospective row does not satisfy the service's ``perm_filter``, or
        :class:`ReferencedEntityNotFoundError` when ``llm_id`` points at a
        missing ``StoredLLM`` row.
        """
        if payload.llm_id is not None:
            await self._require_llm(payload.llm_id)
        template = ConversationTemplate(
            creator_id=creator_id,
            name=payload.name,
            agent_kind=payload.agent_kind,
            llm_id=payload.llm_id,
            mcp_server_config_ids=_stringify_ids(payload.mcp_server_config_ids),
            secret_provider_ids=_stringify_ids(payload.secret_provider_ids),
            static_secret_ids=_stringify_ids(payload.static_secret_ids),
            agent_config=payload.agent_config,
            conversation_config=payload.conversation_config,
            system_message_suffix=payload.system_message_suffix,
            default_callbacks=payload.default_callbacks,
        )
        if not self._perm_filter.matches(template):
            raise ConversationTemplatePermissionScopeError(payload.name)
        self._session.add(template)
        await self._session.flush()
        await self._session.refresh(template)
        return template

    async def get(self, template_id: uuid.UUID) -> ConversationTemplate:
        """Retrieve a template by id, scoped by ``perm_filter``.

        Raises :class:`ConversationTemplateNotFoundError` if the template is
        missing or out of the principal's scope (so callers return 404 without
        leaking existence).
        """
        stmt = self._perm_filter.filter_sql(
            select(ConversationTemplate).where(ConversationTemplate.id == template_id)
        )
        result = await self._session.execute(stmt)
        template = result.scalar_one_or_none()
        if template is None:
            raise ConversationTemplateNotFoundError(str(template_id))
        return template

    async def get_many(
        self,
        template_ids: list[uuid.UUID],
    ) -> list[ConversationTemplate | None]:
        """Retrieve templates by ids in one query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *template_ids*: the i-th entry
        is the :class:`ConversationTemplate` for ``template_ids[i]`` or ``None``
        when missing/out of scope. Duplicate ids are preserved. An empty list
        yields an empty result without hitting the DB.
        """
        if not template_ids:
            return []
        stmt = self._perm_filter.filter_sql(
            select(ConversationTemplate).where(ConversationTemplate.id.in_(template_ids))
        )
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, ConversationTemplate] = {t.id: t for t in result.scalars().all()}
        return [by_id.get(tid) for tid in template_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: ConversationTemplateSearchFilter | None = None,
    ) -> tuple[list[ConversationTemplate], uuid.UUID | None]:
        """Search templates ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(
            select(ConversationTemplate).order_by(ConversationTemplate.id)
        )
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(ConversationTemplate.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def update(
        self,
        template_id: uuid.UUID,
        payload: ConversationTemplateUpdate,
    ) -> ConversationTemplate:
        """Partially update a conversation template.

        ``llm_id`` may be changed (validated against the ``llms`` table); a
        ``None`` value explicitly clears the default LLM. If ``llm_id`` is not
        changed it is left untouched. List fields replace the stored lists
        wholesale.
        """
        template = await self.get(template_id)
        fields = payload.model_fields_set
        if "llm_id" in fields:
            if payload.llm_id is not None:
                await self._require_llm(payload.llm_id)
            template.llm_id = payload.llm_id
        self._apply_update(template, payload, fields)
        await self._session.flush()
        await self._session.refresh(template)
        return template

    @staticmethod
    def _apply_update(
        template: ConversationTemplate,
        payload: ConversationTemplateUpdate,
        fields: set[str],
    ) -> None:
        """Map a partial update onto an existing row, ignoring explicit nulls.

        ``system_message_suffix`` is the one field that may be explicitly
        cleared to ``None``; every other field only writes when non-None.
        """
        for field, transform in _UPDATE_TRANSFORMS.items():
            if field in fields and getattr(payload, field) is not None:
                setattr(template, field, transform(getattr(payload, field)))
        if "system_message_suffix" in fields:
            template.system_message_suffix = payload.system_message_suffix

    async def delete(self, template_id: uuid.UUID) -> None:
        """Delete a conversation template."""
        template = await self.get(template_id)
        await self._session.delete(template)
        await self._session.flush()

    async def count(
        self,
        search_filter: ConversationTemplateSearchFilter | None = None,
    ) -> int:
        """Total template count, scoped by the service's ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(ConversationTemplate))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    async def apply_batch(
        self,
        operations: list[ConversationTemplateBatchOp],
        perm_filters: dict[Action, SearchFilter[ConversationTemplate] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[ConversationTemplate | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the template for create/update,
        ``None`` for delete.
        """
        results: list[ConversationTemplate | None] = []
        for op in operations:
            if isinstance(op, ConversationTemplateBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, ConversationTemplateBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, ConversationTemplateBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: ConversationTemplateBatchCreate,
        perm_filters: dict[Action, SearchFilter[ConversationTemplate] | None],
        *,
        creator_id: uuid.UUID,
    ) -> ConversationTemplate:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await ConversationTemplateService(self._session, filt).create(
            op.data, creator_id=creator_id
        )

    async def _batch_update(
        self,
        op: ConversationTemplateBatchUpdate,
        perm_filters: dict[Action, SearchFilter[ConversationTemplate] | None],
    ) -> ConversationTemplate:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await ConversationTemplateService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: ConversationTemplateBatchDelete,
        perm_filters: dict[Action, SearchFilter[ConversationTemplate] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await ConversationTemplateService(self._session, filt).delete(op.id)

    async def _require_llm(self, llm_id: uuid.UUID) -> None:
        """Raise :class:`ReferencedEntityNotFoundError` when *llm_id* is missing.

        The FETCH FIRST 1 is only a guard against a degenerate duplicate-id
        table; the id column is unique.
        """
        result = await self._session.execute(
            select(StoredLLM.id).where(StoredLLM.id == llm_id).limit(1)
        )
        if result.scalar_one_or_none() is None:
            raise ReferencedEntityNotFoundError(str(llm_id))
