"""Pydantic models for the live sandbox surface.

The live ``Sandbox`` is an in-memory representation of a running (or paused,
or stopped) container/deployment owned by the configured
:class:`SandboxService` implementation (see
:mod:`openhands.ev2.sandbox.sandbox_service`). It is a plain
``DiscriminatedUnionMixin`` Pydantic model whose concrete subclasses
(:class:`DockerSandbox`, :class:`K8sSandbox`) contribute implementation-
specific parameters.

Durable sandbox intent — templates, configs, and snapshots — lives in the
database as governed ORM models (see :mod:`sandbox_template_models`,
:mod:`sandbox_config_models`, :mod:`sandbox_snapshot_models`); those are the
source of truth, not the Pydantic types here. ``SandboxStatus`` is the
provider-neutral public lifecycle state.
"""

from __future__ import annotations

import enum
import uuid
from abc import ABC
from datetime import datetime

from openhands.sdk.utils import utc_now
from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import BaseModel, Field


class SandboxStatus(enum.StrEnum):
    """Provider-neutral public sandbox lifecycle states."""

    INACTIVE = "inactive"
    ACTIVATING = "activating"
    ACTIVE = "active"
    DEACTIVATING = "deactivating"
    DELETING = "deleting"
    # A snapshot of the sandbox workspace is being captured. While in this
    # state the sandbox may not be started/activated — the workspace must be
    # quiescent for a consistent tarball. Providers transition inactive ->
    # snapshotting -> inactive around the capture.
    SNAPSHOTTING = "snapshotting"
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


class Sandbox(DiscriminatedUnionMixin, ABC):
    """Information about a sandbox."""

    # ``id`` defaults to the empty string for the pre-persistence model built
    # by ``_sandbox_from_create``; the provider assigns the real id during
    # ``_create_sandbox`` (e.g. Docker mints a container name).
    id: str = ""
    sandbox_template_id: str
    sandbox_config_id: str | None = None
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
