"""ORM model and callable union for the job feature (issue #157).

A :class:`Job` is a governed, durable, date-range-partitioned row representing
a unit of asynchronous background work. The work itself is a polymorphic
:class:`JobDetails` async callable (a ``DiscriminatedUnionMixin`` mirroring
:class:`~openhands.ev2.event_callback.event_callback_models.EventCallbackProcessor`)
serialized to the ``job_details`` JSONB column and discriminated by the
``job_details_kind`` column. The :class:`~openhands.ev2.job.job_runner_service.JobRunnerService`
claims ``PENDING`` jobs, invokes ``JobDetails.__call__``, and persists the
terminal status via a conditional UPDATE (see the runner service).

Partitioning is internal only, mirroring the usage tables
(``sandbox_usage`` / ``mcp_usage``): the composite primary key
``(id, created_at)`` is the PostgreSQL range-partition-key-in-PK requirement,
and ``created_at`` is ``init=False``, ``server_default=func.clock_timestamp()``,
and never exposed on the REST surface — clients interact with a job by ``id``
alone.

Ownership is direct via ``creator_id``. Access is governed by the
``job_permission`` role column; see ``job_security`` and AGENTS.md §11.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Protocol

from openhands.sdk.utils.models import DiscriminatedUnionMixin
from pydantic import BaseModel, Field
from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import TypeDecorator

from openhands.ev2.db import Base

_TZ = DateTime(timezone=True)

#: The full lifecycle status set. ``PENDING`` / ``SUSPENDED`` are client-settable
#: on create/update; ``RUNNING`` / ``COMPLETED`` / ``ERROR`` are runner-managed.
JOB_PENDING = "PENDING"
JOB_SUSPENDED = "SUSPENDED"
JOB_RUNNING = "RUNNING"
JOB_COMPLETED = "COMPLETED"
JOB_ERROR = "ERROR"

#: Statuses a client may set on create/update (the restricted input set).
JOB_CLIENT_STATUSES: tuple[str, ...] = (JOB_PENDING, JOB_SUSPENDED)
#: Terminal statuses — never overwritten with ``COMPLETED`` once reached.
JOB_TERMINAL_STATUSES: tuple[str, ...] = (JOB_COMPLETED, JOB_ERROR)

logger = logging.getLogger("openhands.ev2.job")


class JobProgressReporter(Protocol):
    """Runner-provided handle a job body uses to report mid-run progress.

    Each call opens its own short-lived DB session and performs a conditional
    ``UPDATE jobs SET progress = :p, status_code = :s WHERE id = :id AND
    status = 'RUNNING' AND runner_id = :own`` — the same race-guard pattern as
    :meth:`JobService.complete`, so a dead-runner recovery that already flipped
    the row to ``ERROR`` is not clobbered by a late progress tick. A call that
    matches 0 rows is a silent no-op (the job is no longer ``RUNNING``).

    The runner constructs a concrete instance bound to ``(job_id, runner_id)``
    and never holds a DB session open while the job body runs.
    """

    async def update(self, progress: float, status_code: str | None = None) -> None:
        """Persist *progress* (0.0-1.0) and optional *status_code* to the job row.

        No-op when the job is no longer ``RUNNING`` for the owning runner.
        """
        ...


class JobRun(BaseModel):
    """The terminal result of running a job's :meth:`JobDetails.__call__`.

    The runner maps a returned :class:`JobRun` onto the job row's ``status`` /
    ``detail`` via the conditional completion UPDATE. ``status`` is restricted
    to the runner-set terminal statuses (``COMPLETED`` / ``ERROR``).
    """

    status: str = Field(description="Terminal runner-set status: COMPLETED or ERROR.")
    detail: str | None = Field(default=None, description="Optional status description.")


class JobDetails(DiscriminatedUnionMixin, ABC):
    """Abstract base for a callable job body.

    A job details object is a self-contained async callable that performs the
    job's work and returns a :class:`JobRun` describing the terminal outcome.
    It stores whatever polymorphic state it needs in its own Pydantic fields,
    serialized to the job row's ``job_details`` JSONB column. Concrete variants
    participate in the SDK discriminated-union machinery (a ``kind`` computed
    field tags the concrete type) so a stored details object can be serialized
    to JSON and deserialized back to the right subclass.

    The runner invokes ``__call__`` with the job's identity and a progress
    handle, and never holds a DB session open while a job is running.
    """

    @abstractmethod
    async def __call__(
        self,
        job_id: uuid.UUID,
        creator_id: uuid.UUID,
        progress: JobProgressReporter,
    ) -> JobRun:
        """Perform the job's work and return the terminal :class:`JobRun`.

        *job_id* is the id of the :class:`Job` row being run; *creator_id* is
        the user the job acts on behalf of; *progress* is a runner-provided
        handle for mid-run progress / status_code updates.
        """
        raise NotImplementedError


class LogJobDetails(JobDetails):
    """Reference job details that logs a message and completes successfully.

    A minimal variant that serves as the reference implementation for the
    :class:`JobDetails` discriminated union. Additional variants will be
    introduced in future PRs.
    """

    message: str = Field(description="Message to log when the job runs.")

    async def __call__(
        self,
        job_id: uuid.UUID,
        creator_id: uuid.UUID,
        progress: JobProgressReporter,
    ) -> JobRun:
        logger.info(self.message)
        return JobRun(status=JOB_COMPLETED)


class JobDetailsType(TypeDecorator[JobDetails]):
    """SQLAlchemy column type that persists a :class:`JobDetails` as JSONB.

    Stores the details object as a JSONB column on read/write, transparently
    serializing via ``model_dump`` and deserializing via the discriminated-union
    ``JobDetails.model_validate`` so the round-trip restores the concrete
    subclass.
    """

    impl = JSONB
    cache_ok = True

    def process_bind_param(
        self,
        value: JobDetails | dict[str, Any] | None,
        dialect: Any,
    ) -> dict[str, Any] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            return value
        return value.model_dump(mode="json")

    def process_result_value(
        self,
        value: dict[str, Any] | None,
        dialect: Any,
    ) -> JobDetails | None:
        if value is None:
            return None
        return JobDetails.model_validate(value)


class Job(Base):
    """A governed, durable, date-range-partitioned background job row.

    The table is PostgreSQL range-partitioned by ``created_at`` (one daily
    partition) so old partitions can be dropped cheaply by the background
    house-cleaning sweep. The composite primary key ``(id, created_at)`` is
    required for partitioning (every column in the partition key must be part
    of the PK) — mirroring ``sandbox_usage`` / ``mcp_usage``. ``created_at`` is
    ``init=False`` and not exposed on the REST surface; clients interact by
    ``id`` alone.
    """

    __tablename__ = "jobs"
    __table_args__ = (
        CheckConstraint("progress >= 0.0 AND progress <= 1.0", name="ck_jobs_progress_range"),
        {
            "postgresql_partition_by": "RANGE(created_at)",
            "comment": "Durable background jobs, daily-partitioned by created_at (governed CRUD)",
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        init=False,
        primary_key=True,
        server_default=func.gen_random_uuid(),
    )
    # Partition key — must be part of the PK and NOT NULL for range partitioning.
    # init=False / server_default so it is never client-settable and never
    # exposed on the REST surface (clients interact by id alone).
    created_at: Mapped[datetime] = mapped_column(
        _TZ,
        primary_key=True,
        init=False,
        server_default=func.clock_timestamp(),
        index=True,
    )
    creator_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )
    # Non-default fields must precede defaulted ones (dataclass ordering).
    job_details_kind: Mapped[str] = mapped_column(
        String(255),
        comment="Discriminator naming the concrete JobDetails subclass (mirrors the kind field).",
    )
    job_details: Mapped[JobDetails] = mapped_column(
        JobDetailsType,
        comment="Serialized JobDetails discriminated union.",
    )
    runner_id: Mapped[uuid.UUID | None] = mapped_column(
        nullable=True,
        default=None,
        index=True,
        comment="Id of the JobRunnerService instance that claimed/created the job.",
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default=JOB_PENDING,
        server_default=JOB_PENDING,
        index=True,
        comment="Lifecycle status: PENDING/SUSPENDED/RUNNING/COMPLETED/ERROR.",
    )
    # Runner-managed mid-run progress / sub-status. Not client-settable: they do
    # not appear on JobCreate/JobUpdate (mirroring how RUNNING/COMPLETED are not
    # client-settable). progress is constrained to [0.0, 1.0] via a CHECK; set
    # to 0.0 on create/claim and to 1.0 by the runner on COMPLETED.
    progress: Mapped[float] = mapped_column(
        Float,
        default=0.0,
        server_default="0.0",
        comment="Runner-managed fractional progress in [0.0, 1.0].",
    )
    status_code: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
        default=None,
        comment="Runner-managed machine-readable sub-status (e.g. a stage name).",
    )
    detail: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
        comment="Optional description of the current status.",
    )
    max_seconds_for_run: Mapped[int] = mapped_column(
        Integer,
        default=60,
        server_default="60",
        comment="Max wall-clock seconds a job may run before it is timed out / recovered.",
    )
    # Set on transition to RUNNING (claim + claim-on-create) and never written
    # mid-run — a self-documenting run-duration baseline so the timeout /
    # dead-runner checks do not rely on the non-obvious invariant that
    # updated_at is not touched mid-run.
    started_at: Mapped[datetime | None] = mapped_column(
        _TZ,
        nullable=True,
        default=None,
        comment="Set when the job transitions to RUNNING; never written mid-run.",
    )
    updated_at: Mapped[datetime] = mapped_column(
        _TZ,
        init=False,
        server_default=func.clock_timestamp(),
        onupdate=func.now(),
    )
