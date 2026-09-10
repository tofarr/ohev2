"""Pydantic models for the sandbox_v2 feature.

The public shape of a sandbox template (and, now, a sandbox) lives here
rather than in the ORM models: template/sandbox state is owned by the
configured ``SandboxService`` implementation (see
:mod:`openhands.ev2.sandbox_v2.sandbox_v2_service`), not by a database
table. ``SandboxTemplate`` and ``Sandbox`` are therefore plain
``DiscriminatedUnionMixin`` Pydantic models whose concrete subclasses
(:class:`DockerSandboxTemplate`, :class:`DockerSandbox`) contribute
implementation-specific parameters.

``SandboxStatus`` is the provider-neutral public lifecycle state, moved here
from the phasing-out :mod:`openhands.ev2.sandbox` package; the old module
re-exports it so existing callers keep working while it is retired.
"""

from __future__ import annotations

import enum
from abc import ABC
from datetime import datetime

from openhands.sdk.utils import utc_now
from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import BaseModel, ConfigDict, Field


class SandboxStatus(enum.StrEnum):
    """Provider-neutral public sandbox lifecycle states."""

    INACTIVE = "inactive"
    ACTIVATING = "activating"
    ACTIVE = "active"
    DEACTIVATING = "deactivating"
    DELETING = "deleting"
    ERROR = "error"


class ExposedPort(BaseModel):
    """Exposed port within a container to be matched to a free port on the host.

    Declared on a sandbox template; the service allocates a host port per
    container at runtime and surfaces the resulting URL via
    :class:`ExposedUrl`.
    """

    name: str
    description: str
    container_port: int = 8000

    model_config = ConfigDict(frozen=True)


class ExposedUrl(BaseModel):
    """URL to access some named service within the container."""

    name: str
    url: str
    port: int


class VolumeMount(BaseModel):
    """Mounted volume within the container."""

    host_path: str
    container_path: str
    mode: str = "rw"


class SandboxTemplate(DiscriminatedUnionMixin, ABC):
    """A template for creating a Sandbox (e.g: A Docker Image vs Container).

    Templates are functionally immutable: they are created and deleted only,
    never updated — image/label metadata is set at build time.
    """

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
    exposed_ports: list[ExposedPort] = Field(
        default_factory=list,
        description="Named container ports exposed to the host as URLs.",
    )


class Sandbox(DiscriminatedUnionMixin, ABC):
    """Information about a sandbox."""

    id: str
    sandbox_spec_id: str
    status: SandboxStatus
    desired_status: SandboxStatus
    session_api_key: str | None = Field(
        default=None,
        description=(
            "Key to access sandbox, to be added as an `X-Session-API-Key` header "
            "in each request. In cases where the sandbox status is STARTING or "
            "PAUSED, or the current user does not have full access, "
            "the session_api_key will be None."
        ),
    )
    exposed_urls: list[ExposedUrl] | None = Field(
        default_factory=lambda: [],
        description=(
            "URLs exposed by the sandbox (App server, Vscode, etc...). "
            "Sandboxes which are not in an ACTIVE state may not return urls."
        ),
    )
    created_at: datetime = Field(default_factory=utc_now)
    status_detail: str | None = Field(
        default=None,
        description=(
            "Last pod/scheduling reason from the runtime (e.g. insufficient kvm, "
            "ImagePullBackOff), surfaced when a sandbox is stuck or errored."
        ),
    )


__all__ = [
    "DockerSandboxTemplate",
    "ExposedPort",
    "ExposedUrl",
    "Sandbox",
    "SandboxStatus",
    "SandboxTemplate",
    "VolumeMount",
]
