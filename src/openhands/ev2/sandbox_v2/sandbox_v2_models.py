"""Pydantic models for the sandbox_v2 feature.

The public shape of a sandbox template lives here rather than in the ORM
models: template state is owned by the configured ``SandboxService``
implementation (see :mod:`openhands.ev2.sandbox_v2.sandbox_v2_service`), not
by a database table. ``SandboxTemplate`` is therefore a plain
``DiscriminatedUnionMixin`` Pydantic model whose concrete subclasses
(:class:`DockerSandboxTemplate`) contribute implementation-specific optional
parameters.
"""

from __future__ import annotations

from abc import ABC
from datetime import datetime

from openhands.sdk.utils import utc_now
from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import Field


class SandboxTemplate(DiscriminatedUnionMixin, ABC):
    """A template for creating a Sandbox (e.g: A Docker Image vs Container)."""

    id: str
    command: list[str] | None = None
    created_at: datetime = Field(default_factory=utc_now)
    initial_env: dict[str, str] = Field(
        default_factory=dict, description="Initial Environment Variables"
    )
    working_dir: str = "/home/openhands/workspace"
    idle_pause_seconds: int | None = Field(
        default=None, description="Idle time before a sandbox should be automatically paused."
    )
    paused_delete_seconds: int | None = Field(
        default=None,
        description="Idle time before a paused sandbox should be automatically deleted.",
    )
    max_age_seconds: int | None = Field(
        default=None, description="Max age for sandboxes after which they will be deleted."
    )


class DockerSandboxTemplate(SandboxTemplate):
    """A sandbox template backed by a Docker image.

    The ``id`` is the Docker image name (e.g. ``ghcr.io/org/agent-server:latest``).
    """

    max_memory: int | None = None


__all__ = ["DockerSandboxTemplate", "SandboxTemplate"]
