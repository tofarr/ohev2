"""Service layer for the sandbox_v2 feature.

The sandbox control plane is supplied by a pluggable :class:`SandboxService`
implementation selected at startup via the ``sandbox_service_class`` config attribute
(a fully qualified class name). The service is constructed once and held as an
async context manager tied to the server lifespan; the concrete implementations
(Docker, Kubernetes, E2B, ...) live in their own modules and are only imported
when selected via the factory below.
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin

from openhands.ev2.sandbox_v2.sandbox_v2_models import SandboxTemplate
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxTemplateBatchCreate,
    SandboxTemplateBatchDelete,
    SandboxTemplateBatchOp,
    SandboxTemplateBatchUpdate,
    SandboxTemplateCreate,
    SandboxTemplateSearchFilter,
    SandboxTemplateUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SandboxTemplateNotFoundError(Exception):
    """Raised when a sandbox template does not exist or is out of scope."""


class SandboxTemplateConflictError(Exception):
    """Raised when a create collides with an existing template."""


class SandboxTemplatePermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class SandboxService(DiscriminatedUnionMixin, ABC):
    """Abstract base for the sandbox control plane.

    Concrete subclasses provide provider-specific template persistence. The
    generic CRUD helpers (search, batch, count) are implemented here over the
    provider hooks and are shared by every implementation. The service is
    created once at startup and held as an async context manager for the
    server's lifetime; every request resolves the same instance and passes its
    own ``perm_filter`` so authorization stays per-principal.
    """

    # ------------------------------------------------------------------ #
    # Async context manager (server lifecycle). Concrete subclasses hold
    # provider clients; ``__aenter__`` acquires them and ``aclose`` releases.
    # ------------------------------------------------------------------ #
    async def __aenter__(self) -> SandboxService:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: Any,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release any provider resources. Default is a no-op."""
        return None

    # ------------------------------------------------------------------ #
    # Generic public CRUD (built on the provider hooks below).
    # ------------------------------------------------------------------ #
    async def list_templates(
        self,
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> list[SandboxTemplate]:
        """List every template the principal may see."""
        templates = await self._list_templates()
        return [template for template in templates if perm_filter.matches(template)]

    async def get_template(
        self,
        template_id: str,
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> SandboxTemplate:
        """Retrieve a template, scoped by ``perm_filter``.

        Raises :class:`SandboxTemplateNotFoundError` when missing or out of
        scope so callers return 404 without leaking existence.
        """
        template = await self._get_template(template_id)
        if not perm_filter.matches(template):
            raise SandboxTemplateNotFoundError(template_id)
        return template

    async def create_template(
        self,
        payload: SandboxTemplateCreate,
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> SandboxTemplate:
        """Create a template. Raises on out-of-scope payload or duplicate id."""
        template = self._template_from_create(payload)
        if not perm_filter.matches(template):
            raise SandboxTemplatePermissionScopeError(payload.id)
        return await self._create_template(template)

    async def update_template(
        self,
        template_id: str,
        payload: SandboxTemplateUpdate,
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> SandboxTemplate:
        """Partially update a template. Raises when missing or out of scope."""
        await self.get_template(template_id, perm_filter=perm_filter)
        template = await self._get_template(template_id)
        return await self._update_template(template, payload)

    async def delete_template(
        self,
        template_id: str,
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> None:
        """Delete a template. Raises when missing or out of scope."""
        await self.get_template(template_id, perm_filter=perm_filter)
        await self._delete_template(template_id)

    async def get_templates(
        self,
        template_ids: list[str],
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> list[SandboxTemplate | None]:
        """Batch retrieve templates, positionally aligned with the ids."""
        templates = await self.list_templates(perm_filter=perm_filter)
        by_id = {template.id: template for template in templates}
        return [by_id.get(template_id) for template_id in template_ids]

    async def search_templates(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        search_filter: SandboxTemplateSearchFilter | None = None,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> tuple[list[SandboxTemplate], str | None]:
        """Search templates ordered by id, key-paginated via an opaque id cursor."""
        templates = await self.list_templates(perm_filter=perm_filter)
        if search_filter is not None:
            templates = [t for t in templates if search_filter.matches(t)]
        templates.sort(key=lambda template: template.id)
        if cursor is not None:
            templates = [t for t in templates if t.id > cursor]
        page = templates[:limit]
        next_cursor = page[-1].id if len(templates) > limit else None
        return page, next_cursor

    async def count_templates(
        self,
        search_filter: SandboxTemplateSearchFilter | None = None,
        *,
        perm_filter: SearchFilter[SandboxTemplate] = ALL,
    ) -> int:
        """Count templates in scope, optionally narrowed by ``search_filter``."""
        templates = await self.list_templates(perm_filter=perm_filter)
        if search_filter is not None:
            templates = [t for t in templates if search_filter.matches(t)]
        return len(templates)

    async def apply_batch(
        self,
        operations: list[SandboxTemplateBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
    ) -> list[SandboxTemplate | None]:
        """Apply a mix of create/update/delete operations.

        Each operation is authorized against its own action via *perm_filters*;
        an action with a ``None`` filter denies that operation. Operations are
        applied sequentially — the provider has no transaction, so batch
        atomicity cannot be guaranteed. Returns results positionally aligned
        with *operations* (``None`` for deletes).
        """
        return [await self._apply_batch_op(op, perm_filters) for op in operations]

    async def _apply_batch_op(
        self,
        op: SandboxTemplateBatchOp,
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
    ) -> SandboxTemplate | None:
        if isinstance(op, SandboxTemplateBatchCreate):
            filt = self._require_action(perm_filters, Action.CREATE, "create")
            return await self.create_template(op.data, perm_filter=filt)
        if isinstance(op, SandboxTemplateBatchUpdate):
            filt = self._require_action(perm_filters, Action.UPDATE, "update")
            return await self.update_template(op.id, op.data, perm_filter=filt)
        if isinstance(op, SandboxTemplateBatchDelete):
            filt = self._require_action(perm_filters, Action.DELETE, "delete")
            await self.delete_template(op.id, perm_filter=filt)
            return None
        raise TypeError(f"Unknown sandbox-template batch op: {type(op).__name__}")

    @staticmethod
    def _require_action(
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
        action: Action,
        label: str,
    ) -> SearchFilter[SandboxTemplate]:
        filt = perm_filters.get(action)
        if filt is None:
            raise BatchPermissionDeniedError(label)
        return filt

    # ------------------------------------------------------------------ #
    # Provider hooks (overridden by implementations).
    # ------------------------------------------------------------------ #
    @abstractmethod
    async def _list_templates(self) -> list[SandboxTemplate]:
        """Return all templates known to the provider (unfiltered)."""

    @abstractmethod
    async def _get_template(self, template_id: str) -> SandboxTemplate:
        """Return a template, raising ``SandboxTemplateNotFoundError`` if absent."""

    @abstractmethod
    def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
        """Build a provider template model from a create payload (no persistence)."""

    @abstractmethod
    async def _create_template(self, template: SandboxTemplate) -> SandboxTemplate:
        """Persist a freshly-built template."""

    @abstractmethod
    async def _update_template(
        self,
        template: SandboxTemplate,
        payload: SandboxTemplateUpdate,
    ) -> SandboxTemplate:
        """Persist changes from *payload* onto *template* and return the result."""

    @abstractmethod
    async def _delete_template(self, template_id: str) -> None:
        """Remove a template from the provider."""


def resolve_sandbox_service_class(fqcn: str) -> type[SandboxService]:
    """Resolve a fully qualified class name to a ``SandboxService`` subclass."""
    module_name, _, class_name = fqcn.rpartition(".")
    if not module_name or not class_name:
        raise ValueError(f"Invalid sandbox_service class name: {fqcn!r}")
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"Cannot import sandbox_service module {module_name!r}") from exc
    candidate = getattr(module, class_name, None)
    if not (isinstance(candidate, type) and issubclass(candidate, SandboxService)):
        raise TypeError(f"{fqcn!r} is not a SandboxService subclass.")
    return candidate


__all__ = [
    "BatchPermissionDeniedError",
    "SandboxService",
    "SandboxTemplateConflictError",
    "SandboxTemplateNotFoundError",
    "SandboxTemplatePermissionScopeError",
    "resolve_sandbox_service_class",
]
