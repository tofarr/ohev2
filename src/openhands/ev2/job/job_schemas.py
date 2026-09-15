"""Pydantic schemas for the job feature.

Uniform REST surface (AGENTS.md §3): the collection is ``/jobs`` with cursor
pagination; create is ``POST``, update is ``PATCH``, retrieve is ``GET``, and
remove is ``DELETE``. Batch read + batch write and count are also provided.

Input schemas use a **restricted status set**: on create/update a client may
only set ``PENDING`` or ``SUSPENDED`` (``JobCreateStatus``). Runner-managed
statuses (``RUNNING`` / ``COMPLETED`` / ``ERROR``) are not client-settable, so
a separate input enum enforces this. ``created_at`` is never exposed on the
REST surface — clients interact by ``id`` alone (partitioning is internal).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from openhands.ev2.job.job_models import Job, JobDetails
from openhands.ev2.util.search_filter import BaseSearchFilter

#: Status a client may set on create/update (the restricted input set).
JobCreateStatus = Literal["PENDING", "SUSPENDED"]

#: Terminal runner-set statuses a :class:`JobRun` may carry.
JobRunStatus = Literal["COMPLETED", "ERROR"]


class JobCreate(BaseModel):
    """Payload to create a job.

    ``status`` defaults to ``PENDING`` and may only be ``PENDING`` /
    ``SUSPENDED``. ``created_at`` is server-set and never appears here.
    """

    model_config = ConfigDict(populate_by_name=True)

    job_details: JobDetails
    status: JobCreateStatus = Field(
        default="PENDING",
        description="Client-settable status: PENDING or SUSPENDED.",
    )
    detail: str | None = Field(default=None, max_length=65536)
    max_seconds_for_run: int = Field(default=60, ge=1, le=86400)


class JobUpdate(BaseModel):
    """Payload to partially update a job. All fields optional.

    ``status`` may only be set to ``PENDING`` / ``SUSPENDED`` (e.g. suspending
    a ``PENDING`` job). Runner-managed statuses are not client-settable.
    """

    model_config = ConfigDict(populate_by_name=True)

    job_details: JobDetails | None = None
    status: JobCreateStatus | None = None
    detail: str | None = Field(default=None, max_length=65536)
    max_seconds_for_run: int | None = Field(default=None, ge=1, le=86400)


class JobRead(BaseModel):
    """Job representation returned by the API.

    ``created_at`` (the partition key) is intentionally absent: partitioning is
    internal and clients interact by ``id`` alone (mirrors the usage tables).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    creator_id: uuid.UUID
    runner_id: uuid.UUID | None
    status: str
    detail: str | None
    max_seconds_for_run: int
    started_at: datetime | None
    job_details_kind: str
    job_details: JobDetails
    updated_at: datetime


class JobSearchFilter(BaseSearchFilter[Job]):
    """Optional filter clauses for ``GET /jobs``."""

    status__eq: str | None = Field(default=None, description="Exact status match.")
    job_details_kind__eq: str | None = Field(
        default=None, description="Exact job_details_kind match."
    )
    creator_id__eq: uuid.UUID | None = Field(default=None, description="Exact creator_id match.")
    runner_id__eq: uuid.UUID | None = Field(default=None, description="Exact runner_id match.")


class JobSearchResult(BaseModel):
    """Paginated collection of jobs."""

    items: list[JobRead]
    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor for the next page; null when no more results.",
    )
    limit: int


# Batch write: POST /jobs/batch applies create/update/delete atomically
# (AGENTS.md §3). Operations reuse the single-item payloads; updates and
# deletes target a specific id.


class JobBatchCreate(BaseModel):
    """Create operation within a job batch write."""

    op: Literal["create"] = "create"
    data: JobCreate


class JobBatchUpdate(BaseModel):
    """Update operation within a job batch write."""

    op: Literal["update"] = "update"
    id: uuid.UUID
    data: JobUpdate


class JobBatchDelete(BaseModel):
    """Delete operation within a job batch write."""

    op: Literal["delete"] = "delete"
    id: uuid.UUID


JobBatchOp = Annotated[
    JobBatchCreate | JobBatchUpdate | JobBatchDelete,
    Field(discriminator="op"),
]


class JobBatchWriteRequest(BaseModel):
    """Request body for ``POST /jobs/batch``."""

    operations: list[JobBatchOp] = Field(
        min_length=1,
        max_length=100,
        description="Create/update/delete operations applied atomically in one transaction.",
    )
