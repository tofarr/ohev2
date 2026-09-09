"""Docker implementation of the sandbox_v2 control plane.

This module is intentionally isolated from :mod:`sandbox_v2_service` so the
Docker SDK is only imported when a Docker-backed service is actually selected
(other implementations will live in their own modules). ``DockerSandboxService``
backs template CRUD with the Docker *Image* API rather than a database table: a
template's ``id`` is the Docker image name, and the lifecycle metadata
(``idle_pause_seconds``, ``paused_delete_seconds``, ``max_age_seconds``) are
read from image labels.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any, cast

import docker  # type: ignore[import-untyped]  # docker SDK ships no type stubs
from docker.errors import ImageNotFound  # type: ignore[import-untyped]

from openhands.ev2.sandbox_v2.sandbox_v2_models import (
    DockerSandboxTemplate,
    SandboxTemplate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_schemas import (
    SandboxTemplateCreate,
    SandboxTemplateUpdate,
)
from openhands.ev2.sandbox_v2.sandbox_v2_service import (
    SandboxService,
    SandboxTemplateConflictError,
    SandboxTemplateNotFoundError,
)

# Docker image labels carrying the lifespan metadata.
_TAG_IDLE_PAUSE_SECONDS = "io.openhands.sandbox_v2.idle_pause_seconds"
_TAG_PAUSED_DELETE_SECONDS = "io.openhands.sandbox_v2.paused_delete_seconds"
_TAG_MAX_AGE_SECONDS = "io.openhands.sandbox_v2.max_age_seconds"


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


__all__ = [
    "DockerSandboxService",
    "_apply_template_update",
    "_docker_template_from_payload",
    "_label_int",
    "_parse_created",
    "_parse_env",
    "_template_from_image_attrs",
]
