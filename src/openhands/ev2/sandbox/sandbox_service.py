"""Service layer for the live sandbox surface.

The live sandbox control plane is supplied by a pluggable :class:`SandboxService`
implementation selected at startup via the ``sandbox_service_class`` config
attribute (a fully qualified class name). The service is constructed once and
held as an async context manager tied to the server lifespan; the concrete
implementations (Docker, Kubernetes, E2B, ...) live in their own modules and
are only imported when selected via the factory below.

The service owns the **live sandbox** surface (list/get/create/update/delete)
and the **snapshot artifact** operations (capture, import, stream, delete
artifact). Durable intent — templates, configs, and snapshot index rows —
lives in the database and is served by the DB-backed services
(:mod:`sandbox_template_service`, :mod:`sandbox_config_service`,
:mod:`sandbox_snapshot_service`); those services delegate artifact capture to
this ABC via ``capture_snapshot`` / ``import_snapshot_file`` /
``stream_snapshot`` / ``delete_snapshot_artifact``.
"""

from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any

from openhands.sdk.utils.models import DiscriminatedUnionMixin

from openhands.ev2.sandbox.sandbox_models import Sandbox
from openhands.ev2.sandbox.sandbox_schemas import (
    SandboxBatchCreate,
    SandboxBatchDelete,
    SandboxBatchOp,
    SandboxCreate,
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
    """Abstract base for the live sandbox control plane.

    Concrete subclasses provide provider-specific sandbox persistence and
    snapshot artifact storage. The generic CRUD helpers (search, batch, count)
    are implemented here over the provider hooks and are shared by every
    implementation. The service is created once at startup and held as an
    async context manager for the server's lifetime; every request resolves
    the same instance and passes its own ``perm_filter`` so authorization
    stays per-principal.

    Templates, configs, and snapshot index rows are DB-backed and served by
    their own services; this ABC only owns the live sandbox and the snapshot
    *artifact* (tarball) operations those DB services delegate to.
    """

    # ------------------------------------------------------------------ #
    # Async context manager (server lifecycle). Concrete subclasses hold
    # provider clients; ``__aenter__`` acquires them and ``aclose`` releases.
    # ``__aenter__`` also refreshes provider-side template state so the service
    # is consistent with the durable templates at startup.
    # ------------------------------------------------------------------ #
    async def __aenter__(self) -> SandboxService:
        await self.refresh_templates()
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

    async def refresh_templates(self, image_tags: Iterable[str] = ()) -> None:
        """Refresh provider-side template state for the given image tags.

        Called by the lifespan ``__aenter__`` and by the template service after
        any template mutation so the provider reconciles its image inventory
        (e.g. the Docker backend pulls missing images in the background). The
        default implementation is a no-op; providers that maintain an image
        inventory override this. *image_tags* are the template image references
        the provider should ensure are available; an empty iterable is a no-op.
        """
        return None

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
    # Snapshot artifact hooks (overridden by implementations that support
    # snapshots). A provider that does not support snapshots raises
    # ``SandboxSnapshotUnsupportedError`` from each hook. These operate on
    # artifact identifiers (snapshot id / download url), not on DB rows — the
    # DB index row is owned by :class:`SandboxSnapshotService`.
    # ------------------------------------------------------------------ #
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
