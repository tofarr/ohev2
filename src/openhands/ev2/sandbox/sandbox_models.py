"""Pydantic models for the sandbox feature.

The public shape of a sandbox template (and, now, a sandbox) lives here
rather than in the ORM models: template/sandbox state is owned by the
configured ``SandboxService`` implementation (see
:mod:`openhands.ev2.sandbox.sandbox_service`), not by a database
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
import uuid
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


class SnapshotMode(enum.StrEnum):
    """Provider-neutral snapshot support strategy for a sandbox.

    ``UNSUPPORTED`` — snapshots are not available. ``MANUAL`` — snapshots are
    created on demand (a caller invokes the create endpoint). ``AUTOMATIC`` —
    the provider maintains a rolling snapshot in the background and updates it
    as the sandbox evolves; callers may still create explicit pins.
    """

    UNSUPPORTED = "unsupported"
    MANUAL = "manual"
    AUTOMATIC = "automatic"


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

    ``snapshot_mode`` declares the snapshot strategy a sandbox built from this
    template supports; when a provider supports multiple modes the one in use
    is recorded on the template so callers can discover it without a separate
    probe.
    """

    id: str
    command: list[str] | None = None
    created_at: datetime = Field(default_factory=utc_now)
    user_id: uuid.UUID | None = Field(
        default=None,
        description="The user who created this sandbox template; null when unknown.",
    )
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
    snapshot_mode: SnapshotMode = Field(
        default=SnapshotMode.UNSUPPORTED,
        description="Snapshot strategy supported by sandboxes built from this template.",
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

    # ``id`` defaults to the empty string for the pre-persistence model built
    # by ``_sandbox_from_create``; the provider assigns the real id during
    # ``_create_sandbox`` (e.g. Docker mints a container name).
    id: str = ""
    sandbox_template_id: str
    status: SandboxStatus
    desired_status: SandboxStatus
    snapshot_mode: SnapshotMode = Field(
        default=SnapshotMode.UNSUPPORTED,
        description=(
            "Snapshot strategy in use for this sandbox. Mirrors the template's "
            "mode when the sandbox is created; providers that support more than "
            "one mode report the active one here."
        ),
    )
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
    user_id: uuid.UUID | None = Field(
        default=None,
        description="The user who created this sandbox; null when unknown.",
    )
    last_accessed_at: datetime | None = Field(
        default=None,
        description=(
            "Last time the sandbox was determined to be active, derived from "
            "the agent server's reported idle time (now - idle_time). Null when "
            "the provider could not determine it (e.g. the sandbox is not "
            "running or the agent server did not respond)."
        ),
    )
    status_detail: str | None = Field(
        default=None,
        description=(
            "Last pod/scheduling reason from the runtime (e.g. insufficient kvm, "
            "ImagePullBackOff), surfaced when a sandbox is stuck or errored."
        ),
    )


class SandboxSnapshot(DiscriminatedUnionMixin, ABC):
    """A point-in-time snapshot of a sandbox.

    Snapshots are created either from an existing sandbox (``sandbox_id``) or
    by importing an uploaded snapshot file (``schema_type``). Each snapshot
    carries an id, the time it was created, and a download URL the caller can
    use to fetch the snapshot artifact. Provider-specific subclasses (e.g.
    :class:`DockerSandboxSnapshot`) carry implementation detail such as the
    backing image id.
    """

    id: str
    created_at: datetime = Field(default_factory=utc_now)
    user_id: uuid.UUID | None = Field(
        default=None,
        description="The user who created this snapshot; null when unknown.",
    )
    download_url: str | None = Field(
        default=None,
        description="URL to download the snapshot artifact, when available.",
    )
