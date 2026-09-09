"""Service layer for the sandbox_v2 feature.

The sandbox control plane is supplied by a pluggable :class:`SandboxService`
implementation selected at startup via the ``sandbox_service`` config attribute
(a fully qualified class name). The service is constructed once and held as an
async context manager tied to the server lifespan; later implementations
(Kubernetes, E2B, ...) register their own FQCN and replace the Docker backend.

The :class:`DockerSandboxService` backs template CRUD with the Docker *Image*
API rather than a database table: a template's ``id`` is the Docker image
name, and the lifecycle metadata (``idle_pause_seconds``,
``paused_delete_seconds``, ``max_age_seconds``) are read from image labels.
"""

from __future__ import annotations

import asyncio
import importlib
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, cast

import docker  # type: ignore[import-untyped]  # docker SDK ships no type stubs
from docker.errors import ImageNotFound  # type: ignore[import-untyped]

from openhands.ev2.sandbox_v2.sandbox_v2_models import (
    DockerSandboxTemplate,
    SandboxTemplate,
)
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

# Docker image labels carrying the lifespan metadata.
_TAG_IDLE_PAUSE_SECONDS = "io.openhands.sandbox_v2.idle_pause_seconds"
_TAG_PAUSED_DELETE_SECONDS = "io.openhands.sandbox_v2.paused_delete_seconds"
_TAG_MAX_AGE_SECONDS = "io.openhands.sandbox_v2.max_age_seconds"


class SandboxTemplateNotFoundError(Exception):
    """Raised when a sandbox template does not exist or is out of scope."""


class SandboxTemplateConflictError(Exception):
    """Raised when a create collides with an existing template."""


class SandboxTemplatePermissionScopeError(Exception):
    """Raised when a create payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted."""


class SandboxService(ABC):
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


class DockerSandboxService(SandboxService):
    """Docker-backed sandbox control plane.

    Template state is the Docker image inventory: ``id`` is the image name and
    the lifespan metadata are image labels. ``max_memory`` is read from the
    image's host config.
    """

    def __init__(self) -> None:
        self._client: Any = None

    async def __aenter__(self) -> DockerSandboxService:
        return self

    async def aclose(self) -> None:
        self._client = None

    @property
    def _images(self) -> Any:
        # Lazily connect so the server can boot without a running Docker
        # daemon; the first sandbox operation surfaces any connection error.
        if self._client is None:
            self._client = docker.from_env()
        return self._client.images

    # ------------------------------------------------------------------ #
    # Provider hooks.
    # ------------------------------------------------------------------ #
    async def _list_templates(self) -> list[SandboxTemplate]:
        return cast("list[SandboxTemplate]", await asyncio.to_thread(self._sync_list_templates))

    async def _get_template(self, template_id: str) -> SandboxTemplate:
        return await asyncio.to_thread(self._sync_get_template, template_id)

    def _template_from_create(self, payload: SandboxTemplateCreate) -> SandboxTemplate:
        return _docker_template_from_payload(payload)

    async def _create_template(self, template: SandboxTemplate) -> DockerSandboxTemplate:
        docker_template = cast(DockerSandboxTemplate, template)
        await asyncio.to_thread(self._sync_create_template, docker_template.id)
        return docker_template

    async def _update_template(
        self,
        template: SandboxTemplate,
        payload: SandboxTemplateUpdate,
    ) -> DockerSandboxTemplate:
        if not isinstance(template, DockerSandboxTemplate):
            raise SandboxTemplateNotFoundError(str(template.id))
        return _apply_template_update(template, payload)

    async def _delete_template(self, template_id: str) -> None:
        await asyncio.to_thread(self._sync_delete_template, template_id)

    # ------------------------------------------------------------------ #
    # Synchronous Docker Image API calls (offloaded from the event loop).
    # ------------------------------------------------------------------ #
    def _sync_list_templates(self) -> list[DockerSandboxTemplate]:
        templates: list[DockerSandboxTemplate] = []
        for image in self._images.list():
            try:
                templates.append(_template_from_image_attrs(image.attrs))
            except SandboxTemplateNotFoundError:
                # Untagged intermediate images are not templates.
                continue
        return templates

    def _sync_get_template(self, template_id: str) -> DockerSandboxTemplate:
        try:
            image = self._images.get(template_id)
        except ImageNotFound:
            raise SandboxTemplateNotFoundError(template_id) from None
        return _template_from_image_attrs(image.attrs)

    def _sync_create_template(self, template_id: str) -> None:
        images = self._images
        try:
            images.get(template_id)
        except ImageNotFound:
            images.pull(repository=template_id)
            return
        raise SandboxTemplateConflictError(template_id)

    def _sync_delete_template(self, template_id: str) -> None:
        try:
            self._images.remove(image=template_id)
        except ImageNotFound:
            raise SandboxTemplateNotFoundError(template_id) from None


# ---------------------------------------------------------------------- #
# Pure template <-> Docker Image plumbing.
# ---------------------------------------------------------------------- #


def _template_from_image_attrs(attrs: dict[str, Any]) -> DockerSandboxTemplate:
    """Build a :class:`DockerSandboxTemplate` from a Docker image's ``attrs``.

    Uses the first repository tag as the template id; an untagged image is not
    a usable template.
    """
    tags = [tag for tag in (attrs.get("RepoTags") or []) if tag != "<none>:<none>"]
    if not tags:
        raise SandboxTemplateNotFoundError("image is untagged")
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    host_config = attrs.get("HostConfig") or {}
    memory = host_config.get("Memory")
    return DockerSandboxTemplate(
        id=tags[0],
        command=config.get("Cmd"),
        created_at=_parse_created(attrs.get("Created")),
        initial_env=_parse_env(config.get("Env")),
        working_dir=config.get("WorkingDir") or "/home/openhands/workspace",
        idle_pause_seconds=_label_int(labels, _TAG_IDLE_PAUSE_SECONDS),
        paused_delete_seconds=_label_int(labels, _TAG_PAUSED_DELETE_SECONDS),
        max_age_seconds=_label_int(labels, _TAG_MAX_AGE_SECONDS),
        max_memory=int(memory) if memory else None,
    )


def _docker_template_from_payload(payload: SandboxTemplateCreate) -> DockerSandboxTemplate:
    """Build a Docker template from a create payload (no persistence)."""
    return DockerSandboxTemplate(
        id=payload.id,
        command=payload.command,
        initial_env=payload.initial_env,
        working_dir=payload.working_dir,
        idle_pause_seconds=payload.idle_pause_seconds,
        paused_delete_seconds=payload.paused_delete_seconds,
        max_age_seconds=payload.max_age_seconds,
        max_memory=payload.max_memory,
    )


def _apply_template_update(
    template: DockerSandboxTemplate,
    payload: SandboxTemplateUpdate,
) -> DockerSandboxTemplate:
    """Return *template* with every set field in *payload* applied.

    The Docker Image API has no in-place metadata mutation, so labels are only
    read (set at image build time); update returns the projected template.
    """
    return DockerSandboxTemplate(
        id=template.id,
        command=template.command if payload.command is None else payload.command,
        created_at=template.created_at,
        initial_env=template.initial_env if payload.initial_env is None else payload.initial_env,
        working_dir=template.working_dir if payload.working_dir is None else payload.working_dir,
        idle_pause_seconds=(
            template.idle_pause_seconds
            if payload.idle_pause_seconds is None
            else payload.idle_pause_seconds
        ),
        paused_delete_seconds=(
            template.paused_delete_seconds
            if payload.paused_delete_seconds is None
            else payload.paused_delete_seconds
        ),
        max_age_seconds=(
            template.max_age_seconds if payload.max_age_seconds is None else payload.max_age_seconds
        ),
        max_memory=template.max_memory if payload.max_memory is None else payload.max_memory,
    )


def _parse_env(env: list[str] | None) -> dict[str, str]:
    """Parse a Docker ``Config.Env`` list into a name/value mapping."""
    if not env:
        return {}
    result: dict[str, str] = {}
    for entry in env:
        if "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        result[key] = value
    return result


def _label_int(labels: dict[str, Any], name: str) -> int | None:
    """Parse an integer label, returning ``None`` when absent or invalid."""
    raw = labels.get(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _parse_created(created: object) -> datetime:
    """Parse a Docker ``Created`` timestamp into an aware UTC datetime."""
    if isinstance(created, str):
        try:
            parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(UTC)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    return datetime.now(UTC)


# ---------------------------------------------------------------------- #
# Factory.
# ---------------------------------------------------------------------- #


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


def build_sandbox_service(fqcn: str) -> SandboxService:
    """Instantiate a ``SandboxService`` from its fully qualified class name."""
    service_class = resolve_sandbox_service_class(fqcn)
    return service_class()


__all__ = [
    "BatchPermissionDeniedError",
    "DockerSandboxService",
    "SandboxService",
    "SandboxTemplateConflictError",
    "SandboxTemplateNotFoundError",
    "SandboxTemplatePermissionScopeError",
    "build_sandbox_service",
    "resolve_sandbox_service_class",
]
