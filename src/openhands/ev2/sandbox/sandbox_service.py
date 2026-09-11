"""Service layer for the sandbox feature.

The sandbox control plane is supplied by a pluggable :class:`SandboxService`
implementation selected at startup via the ``sandbox_service_class`` config
attribute (a fully qualified class name). The service is constructed once and
held as an async context manager tied to the server lifespan; the concrete
implementations (Docker, Kubernetes, E2B, ...) live in their own modules and
are only imported when selected via the factory below.

The service owns two governed surfaces:

* **Sandbox templates** — functionally immutable (create and delete only).
  There is no ``update_template`` path; provider image/label metadata is set
  at build time and cannot be patched.
* **Sandboxes** — created from a template, deleted when no longer needed, and
  paused/resumed by updating the single mutable field ``desired_status``.
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin

from openhands.ev2.sandbox.sandbox_models import Sandbox, SandboxSnapshot, SandboxTemplate
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxBatchCreate,
    SandboxBatchDelete,
    SandboxBatchOp,
    SandboxCreate,
    SandboxSnapshotBatchDelete,
    SandboxSnapshotBatchOp,
    SandboxSnapshotCreate,
    SandboxSnapshotSearchFilter,
    SandboxTemplateBatchCreate,
    SandboxTemplateBatchDelete,
    SandboxTemplateBatchOp,
    SandboxTemplateCreate,
    SandboxTemplateSearchFilter,
    SandboxUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


class SandboxTemplateNotFoundError(Exception):
    """Raised when a sandbox template does not exist or is out of scope."""


class SandboxTemplateConflictError(Exception):
    """Raised when a create collides with an existing template."""


class SandboxTemplatePermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class SandboxNotFoundError(Exception):
    """Raised when a sandbox does not exist or is out of scope."""


class SandboxConflictError(Exception):
    """Raised when a create collides with an existing sandbox."""


class SandboxPermissionScopeError(Exception):
    """Raised when a sandbox create payload falls outside the principal's scope."""


class SandboxSnapshotNotFoundError(Exception):
    """Raised when a sandbox snapshot does not exist or is out of scope."""


class SandboxSnapshotConflictError(Exception):
    """Raised when a snapshot create collides with an existing id."""


class SandboxSnapshotPermissionScopeError(Exception):
    """Raised when a snapshot create payload falls outside the principal's scope."""


class SandboxSnapshotUnsupportedError(Exception):
    """Raised when the provider does not support snapshots for a sandbox."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class SandboxService(DiscriminatedUnionMixin, ABC):
    """Abstract base for the sandbox control plane.

    Concrete subclasses provide provider-specific template and sandbox
    persistence. The generic CRUD helpers (search, batch, count) are
    implemented here over the provider hooks and are shared by every
    implementation. The service is created once at startup and held as an
    async context manager for the server's lifetime; every request resolves
    the same instance and passes its own ``perm_filter`` so authorization
    stays per-principal.

    Templates are immutable: only ``create_template``/``delete_template`` are
    exposed (no update). Sandboxes are mutable solely via ``desired_status``
    (``update_sandbox``), which drives pause/resume.
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
    # Generic public template CRUD (built on the provider hooks below).
    # Templates are immutable: no update method.
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
        """Apply a mix of create/delete template operations.

        Each operation is authorized against its own action via *perm_filters*;
        an action with a ``None`` filter denies that operation. Operations are
        applied sequentially — the provider has no transaction, so batch
        atomicity cannot be guaranteed. Returns results positionally aligned
        with *operations* (``None`` for deletes).
        """
        return [await self._apply_template_batch_op(op, perm_filters) for op in operations]

    async def _apply_template_batch_op(
        self,
        op: SandboxTemplateBatchOp,
        perm_filters: dict[Action, SearchFilter[SandboxTemplate] | None],
    ) -> SandboxTemplate | None:
        if isinstance(op, SandboxTemplateBatchCreate):
            filt = self._require_action(perm_filters, Action.CREATE, "create")
            return await self.create_template(op.data, perm_filter=filt)
        if isinstance(op, SandboxTemplateBatchDelete):
            filt = self._require_action(perm_filters, Action.DELETE, "delete")
            await self.delete_template(op.id, perm_filter=filt)
            return None
        raise TypeError(f"Unknown sandbox-template batch op: {type(op).__name__}")

    # ------------------------------------------------------------------ #
    # Generic public sandbox CRUD (built on the provider hooks below).
    # Only ``desired_status`` is mutable (via ``update_sandbox``).
    # ------------------------------------------------------------------ #
    async def list_sandboxes(
        self,
        *,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> list[Sandbox]:
        """List every sandbox the principal may see."""
        sandboxes = await self._list_sandboxes()
        return [sandbox for sandbox in sandboxes if perm_filter.matches(sandbox)]

    async def get_sandbox(
        self,
        sandbox_id: str,
        *,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> Sandbox:
        """Retrieve a sandbox, scoped by ``perm_filter``.

        Raises :class:`SandboxNotFoundError` when missing or out of scope so
        callers return 404 without leaking existence.
        """
        sandbox = await self._get_sandbox(sandbox_id)
        if not perm_filter.matches(sandbox):
            raise SandboxNotFoundError(sandbox_id)
        return sandbox

    async def create_sandbox(
        self,
        payload: SandboxCreate,
        *,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> Sandbox:
        """Create a sandbox. Raises on out-of-scope payload or provider conflict.

        The sandbox ``id`` is assigned by the provider during creation; the
        pre-persistence model built by ``_sandbox_from_create`` is checked
        against ``perm_filter`` (the principal's create scope) before the
        backing compute is started. When ``payload.snapshot_id`` is set the
        provider restores that snapshot's workspace into the new sandbox
        before starting it.
        """
        sandbox = self._sandbox_from_create(payload)
        if not perm_filter.matches(sandbox):
            raise SandboxPermissionScopeError(payload.sandbox_template_id)
        return await self._create_sandbox(sandbox, snapshot_id=payload.snapshot_id)

    async def update_sandbox(
        self,
        sandbox_id: str,
        payload: SandboxUpdate,
        *,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> Sandbox:
        """Update a sandbox's ``desired_status`` (pause/resume).

        Raises :class:`SandboxNotFoundError` when missing or out of scope.
        """
        await self.get_sandbox(sandbox_id, perm_filter=perm_filter)
        return await self._update_sandbox(sandbox_id, payload)

    async def delete_sandbox(
        self,
        sandbox_id: str,
        *,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> None:
        """Delete a sandbox. Raises when missing or out of scope."""
        await self.get_sandbox(sandbox_id, perm_filter=perm_filter)
        await self._delete_sandbox(sandbox_id)

    async def get_sandboxes(
        self,
        sandbox_ids: list[str],
        *,
        perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> list[Sandbox | None]:
        """Batch retrieve sandboxes, positionally aligned with the ids."""
        sandboxes = await self.list_sandboxes(perm_filter=perm_filter)
        by_id = {sandbox.id: sandbox for sandbox in sandboxes}
        return [by_id.get(sandbox_id) for sandbox_id in sandbox_ids]

    async def apply_sandbox_batch(
        self,
        operations: list[SandboxBatchOp],
        perm_filters: dict[Action, SearchFilter[Sandbox] | None],
    ) -> list[Sandbox | None]:
        """Apply a mix of create/delete sandbox operations.

        Each operation is authorized against its own action via *perm_filters*;
        an action with a ``None`` filter denies that operation. Returns results
        aligned with *operations* (the sandbox for create, ``None`` for delete).
        """
        return [await self._apply_sandbox_batch_op(op, perm_filters) for op in operations]

    async def _apply_sandbox_batch_op(
        self,
        op: SandboxBatchOp,
        perm_filters: dict[Action, SearchFilter[Sandbox] | None],
    ) -> Sandbox | None:
        if isinstance(op, SandboxBatchCreate):
            filt = self._require_action(perm_filters, Action.CREATE, "create")
            return await self.create_sandbox(op.data, perm_filter=filt)
        if isinstance(op, SandboxBatchDelete):
            filt = self._require_action(perm_filters, Action.DELETE, "delete")
            await self.delete_sandbox(op.id, perm_filter=filt)
            return None
        raise TypeError(f"Unknown sandbox batch op: {type(op).__name__}")

    # ------------------------------------------------------------------ #
    # Generic public snapshot CRUD (built on the provider hooks below).
    # Snapshots support create, read, and delete only (no update).
    # ------------------------------------------------------------------ #
    async def list_snapshots(
        self,
        *,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> list[SandboxSnapshot]:
        """List every snapshot the principal may see."""
        snapshots = await self._list_snapshots()
        return [snapshot for snapshot in snapshots if perm_filter.matches(snapshot)]

    async def get_snapshot(
        self,
        snapshot_id: str,
        *,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> SandboxSnapshot:
        """Retrieve a snapshot, scoped by ``perm_filter``.

        Raises :class:`SandboxSnapshotNotFoundError` when missing or out of
        scope so callers return 404 without leaking existence.
        """
        snapshot = await self._get_snapshot(snapshot_id)
        if not perm_filter.matches(snapshot):
            raise SandboxSnapshotNotFoundError(snapshot_id)
        return snapshot

    async def create_snapshot(
        self,
        payload: SandboxSnapshotCreate,
        *,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
        sandbox_perm_filter: SearchFilter[Sandbox] = ALL,
    ) -> SandboxSnapshot:
        """Create a snapshot from a sandbox or an uploaded file.

        Raises :class:`SandboxSnapshotUnsupportedError` when the provider does
        not support snapshots, :class:`SandboxSnapshotPermissionScopeError`
        when the resulting snapshot is out of scope, or
        :class:`SandboxNotFoundError` when ``sandbox_id`` names a sandbox the
        principal cannot use.
        """
        if payload.sandbox_id is not None:
            sandbox = await self.get_sandbox(payload.sandbox_id, perm_filter=sandbox_perm_filter)
            snapshot = await self._snapshot_from_sandbox(payload, sandbox)
        else:
            snapshot = await self._snapshot_from_file(payload)
        if not perm_filter.matches(snapshot):
            raise SandboxSnapshotPermissionScopeError(payload.sandbox_id or "file import")
        return await self._create_snapshot(snapshot, payload)

    async def delete_snapshot(
        self,
        snapshot_id: str,
        *,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> None:
        """Delete a snapshot. Raises when missing or out of scope."""
        await self.get_snapshot(snapshot_id, perm_filter=perm_filter)
        await self._delete_snapshot(snapshot_id)

    async def get_snapshots(
        self,
        snapshot_ids: list[str],
        *,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> list[SandboxSnapshot | None]:
        """Batch retrieve snapshots, positionally aligned with the ids."""
        snapshots = await self.list_snapshots(perm_filter=perm_filter)
        by_id = {snapshot.id: snapshot for snapshot in snapshots}
        return [by_id.get(snapshot_id) for snapshot_id in snapshot_ids]

    async def search_snapshots(
        self,
        *,
        cursor: str | None = None,
        limit: int = 50,
        search_filter: SandboxSnapshotSearchFilter | None = None,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> tuple[list[SandboxSnapshot], str | None]:
        """Search snapshots ordered by id, key-paginated via an opaque id cursor."""
        snapshots = await self.list_snapshots(perm_filter=perm_filter)
        if search_filter is not None:
            snapshots = [s for s in snapshots if search_filter.matches(s)]
        snapshots.sort(key=lambda snapshot: snapshot.id)
        if cursor is not None:
            snapshots = [s for s in snapshots if s.id > cursor]
        page = snapshots[:limit]
        next_cursor = page[-1].id if len(snapshots) > limit else None
        return page, next_cursor

    async def count_snapshots(
        self,
        search_filter: SandboxSnapshotSearchFilter | None = None,
        *,
        perm_filter: SearchFilter[SandboxSnapshot] = ALL,
    ) -> int:
        """Count snapshots in scope, optionally narrowed by ``search_filter``."""
        snapshots = await self.list_snapshots(perm_filter=perm_filter)
        if search_filter is not None:
            snapshots = [s for s in snapshots if search_filter.matches(s)]
        return len(snapshots)

    async def apply_snapshot_batch(
        self,
        operations: list[SandboxSnapshotBatchOp],
        perm_filters: dict[Action, SearchFilter[SandboxSnapshot] | None],
    ) -> list[SandboxSnapshot | None]:
        """Apply a batch of delete snapshot operations.

        Each operation is authorized against its own action via *perm_filters*;
        an action with a ``None`` filter denies that operation. Returns results
        aligned with *operations* (``None`` for deletes).
        """
        return [await self._apply_snapshot_batch_op(op, perm_filters) for op in operations]

    async def _apply_snapshot_batch_op(
        self,
        op: SandboxSnapshotBatchOp,
        perm_filters: dict[Action, SearchFilter[SandboxSnapshot] | None],
    ) -> SandboxSnapshot | None:
        if isinstance(op, SandboxSnapshotBatchDelete):
            filt = self._require_action(perm_filters, Action.DELETE, "delete")
            await self.delete_snapshot(op.id, perm_filter=filt)
            return None
        raise TypeError(f"Unknown sandbox-snapshot batch op: {type(op).__name__}")

    @staticmethod
    def _require_action(
        perm_filters: dict[Action, SearchFilter[Any] | None],
        action: Action,
        label: str,
    ) -> SearchFilter[Any]:
        filt = perm_filters.get(action)
        if filt is None:
            raise BatchPermissionDeniedError(label)
        return filt

    # ------------------------------------------------------------------ #
    # Provider hooks — templates (overridden by implementations).
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
    async def _delete_template(self, template_id: str) -> None:
        """Remove a template from the provider."""

    # ------------------------------------------------------------------ #
    # Provider hooks — sandboxes (overridden by implementations).
    # ------------------------------------------------------------------ #
    @abstractmethod
    async def _list_sandboxes(self) -> list[Sandbox]:
        """Return all sandboxes known to the provider (unfiltered)."""

    @abstractmethod
    async def _get_sandbox(self, sandbox_id: str) -> Sandbox:
        """Return a sandbox, raising ``SandboxNotFoundError`` if absent."""

    @abstractmethod
    def _sandbox_from_create(self, payload: SandboxCreate) -> Sandbox:
        """Build a provider sandbox model from a create payload (no persistence).

        The returned sandbox has no ``id`` yet (it defaults to ``""``); the
        provider assigns the id during ``_create_sandbox``.
        """

    @abstractmethod
    async def _create_sandbox(self, sandbox: Sandbox, *, snapshot_id: str | None = None) -> Sandbox:
        """Persist a freshly-built sandbox, assign its id, and start backing compute.

        When *snapshot_id* is set, restore that snapshot's workspace contents
        into the new sandbox before starting it (analogous to creating a PVC
        from a VolumeSnapshot). Providers that do not support snapshots raise
        :class:`SandboxSnapshotUnsupportedError` when a snapshot id is given.
        """

    @abstractmethod
    async def _update_sandbox(self, sandbox_id: str, payload: SandboxUpdate) -> Sandbox:
        """Apply a ``desired_status`` change (pause/resume) and return the sandbox."""

    @abstractmethod
    async def _delete_sandbox(self, sandbox_id: str) -> None:
        """Remove a sandbox (and its backing compute) from the provider."""

    # ------------------------------------------------------------------ #
    # Provider hooks - snapshots (overridden by implementations).
    # A provider that does not support snapshots raises
    # ``SandboxSnapshotUnsupportedError`` from each hook.
    # ------------------------------------------------------------------ #
    async def _list_snapshots(self) -> list[SandboxSnapshot]:
        """Return all snapshots known to the provider (unfiltered)."""
        raise SandboxSnapshotUnsupportedError("snapshots are not supported")

    async def _get_snapshot(self, snapshot_id: str) -> SandboxSnapshot:
        """Return a snapshot, raising ``SandboxSnapshotNotFoundError`` if absent."""
        raise SandboxSnapshotUnsupportedError("snapshots are not supported")

    async def _snapshot_from_sandbox(
        self,
        payload: SandboxSnapshotCreate,
        sandbox: Sandbox,
    ) -> SandboxSnapshot:
        """Build a snapshot model from a sandbox (no persistence)."""
        raise SandboxSnapshotUnsupportedError("snapshots are not supported")

    async def _snapshot_from_file(
        self,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        """Build a snapshot model from an uploaded file (no persistence)."""
        raise SandboxSnapshotUnsupportedError("snapshots are not supported")

    async def _create_snapshot(
        self,
        snapshot: SandboxSnapshot,
        payload: SandboxSnapshotCreate,
    ) -> SandboxSnapshot:
        """Persist a freshly-built snapshot."""
        raise SandboxSnapshotUnsupportedError("snapshots are not supported")

    async def _delete_snapshot(self, snapshot_id: str) -> None:
        """Remove a snapshot from the provider."""
        raise SandboxSnapshotUnsupportedError("snapshots are not supported")

    async def stream_snapshot(self, snapshot_id: str) -> Any:
        """Return an iterable of bytes for downloading a snapshot artifact.

        Raises :class:`SandboxSnapshotUnsupportedError` when the provider cannot
        stream snapshots. The base implementation is unsupported; providers that
        back snapshots with a downloadable artifact override this.
        """
        raise SandboxSnapshotUnsupportedError("snapshot download is not supported")

    async def capture_snapshot(
        self,
        sandbox_id: str,
        *,
        sandbox_perm_filter: SearchFilter[Any] = ALL,
    ) -> tuple[str, int | None]:
        """Capture a snapshot artifact from a live sandbox.

        Returns ``(download_url, size_bytes)``. The DB index row is persisted by
        the caller (:class:`SandboxSnapshotService`). Raises
        :class:`SandboxSnapshotUnsupportedError` when the provider cannot capture.
        """
        raise SandboxSnapshotUnsupportedError("snapshot capture is not supported")

    async def import_snapshot_file(
        self,
        file_data: bytes | None,
        *,
        schema_type: str | None = None,
    ) -> tuple[str, int | None]:
        """Store an uploaded snapshot artifact and return ``(download_url, size_bytes)``.

        Raises :class:`SandboxSnapshotUnsupportedError` when the provider cannot
        import files.
        """
        raise SandboxSnapshotUnsupportedError("snapshot file import is not supported")

    async def delete_snapshot_artifact(self, snapshot_id: str) -> None:
        """Delete the stored artifact for a snapshot (the DB row is deleted by the caller).

        Raises :class:`SandboxSnapshotUnsupportedError` when the provider does not
        manage artifacts.
        """
        raise SandboxSnapshotUnsupportedError("snapshot artifact deletion is not supported")


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
