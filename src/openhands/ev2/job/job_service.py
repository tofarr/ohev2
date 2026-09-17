"""Service layer for the job feature.

Two concerns, each a small single-purpose method, mirroring the established
``routers → services → repositories → models`` layering:

* :class:`JobService` — governed CRUD over :class:`Job` (create / get /
  get_many / search / update / delete / count / batch). Services hold the
  effective ``perm_filter`` (from the centralized permission checker) so SQL is
  scoped to rows the principal may see/modify; :meth:`create` validates the
  prospective row against it in memory (AGENTS.md §9).
* :class:`JobService.create_runner_owned` — the claim-on-create path a runner
  uses to insert a job directly as ``RUNNING`` (claim-on-insert), falling back
  to ``PENDING`` when the runner cannot run it now.
* :class:`JobService.complete` — the conditional completion UPDATE (the race
  guard): only fires while the job is still ``RUNNING`` and still owned by the
  calling runner; on 0 rows updated the job was already moved to a terminal
  state and the runner abandons the write (never overwrites ``ERROR``/
  terminal with ``COMPLETED``).
* :meth:`JobService.ensure_partitions` — allocate future daily partitions of
  the range-partitioned ``jobs`` table and drop expired ones. Driven by the
  background house-cleaning loop.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from sqlalchemy import bindparam, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from openhands.ev2.job.job_models import (
    JOB_COMPLETED,
    JOB_ERROR,
    JOB_PENDING,
    JOB_RUNNING,
    Job,
    JobDetails,
    JobRun,
)
from openhands.ev2.job.job_schemas import (
    JobBatchCreate,
    JobBatchDelete,
    JobBatchOp,
    JobBatchUpdate,
    JobCreate,
    JobUpdate,
)
from openhands.ev2.security.security_models import Action
from openhands.ev2.util.search_filter import ALL, SearchFilter


def _identity(value: Any) -> Any:
    return value


def _details_kind(details: Any) -> str:
    """The discriminator kind for a JobDetails object (its concrete class name)."""
    return str(details.kind)


_UPDATE_TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "status": _identity,
    "detail": _identity,
    "max_seconds_for_run": _identity,
}


class JobNotFoundError(Exception):
    """Raised when a job id does not exist (or is out of scope)."""


class JobPermissionScopeError(Exception):
    """Raised when a create/update payload falls outside the principal's scope."""


class BatchPermissionDeniedError(Exception):
    """Raised when a batch operation's action is not granted to the principal."""


def _partition_name(day: datetime) -> str:
    """The daily partition table name for *day* (a UTC date)."""
    return f"jobs_{day.strftime('%Y%m%d')}"


def _day_bounds(day: datetime) -> tuple[str, str]:
    """The ``[from, to)`` DATE bounds for the *day* partition (ISO strings)."""
    start = day.date().isoformat()
    end = (day + timedelta(days=1)).date().isoformat()
    return start, end


class JobService:
    """CRUD over :class:`Job` plus the runner-owned create/complete paths."""

    def __init__(
        self,
        session: AsyncSession,
        perm_filter: SearchFilter[Job] = ALL,
    ) -> None:
        self._session = session
        self._perm_filter = perm_filter

    # ------------------------------------------------------------------ #
    # Standard CRUD
    # ------------------------------------------------------------------ #

    async def create(
        self,
        payload: JobCreate,
        *,
        creator_id: uuid.UUID,
    ) -> Job:
        """Persist a job (client-created path).

        The job is inserted with the client-supplied (restricted) status
        (``PENDING`` / ``SUSPENDED``); ``started_at`` is ``None`` and
        ``runner_id`` is ``None``. Raises :class:`JobPermissionScopeError` if
        the prospective row does not satisfy the service's ``perm_filter``.
        """
        details = payload.job_details
        job = Job(
            creator_id=creator_id,
            status=payload.status,
            detail=payload.detail,
            max_seconds_for_run=payload.max_seconds_for_run,
            job_details_kind=_details_kind(details),
            job_details=details,
        )
        if not self._perm_filter.matches(job):
            raise JobPermissionScopeError(str(details.kind))
        self._session.add(job)
        await self._session.flush()
        await self._session.refresh(job)
        return job

    async def get(self, job_id: uuid.UUID) -> Job:
        """Retrieve a job by id, scoped by ``perm_filter``.

        Raises :class:`JobNotFoundError` if the job is missing or out of the
        principal's scope (so callers return 404 without leaking existence).
        """
        stmt = self._perm_filter.filter_sql(select(Job).where(Job.id == job_id))
        result = await self._session.execute(stmt)
        job = result.scalar_one_or_none()
        if job is None:
            raise JobNotFoundError(str(job_id))
        return job

    async def get_many(self, job_ids: list[uuid.UUID]) -> list[Job | None]:
        """Retrieve jobs by ids in one query, scoped by ``perm_filter``.

        Returns a list positionally aligned with *job_ids*: the i-th entry is
        the :class:`Job` for ``job_ids[i]`` or ``None`` when missing/out of
        scope. Duplicate ids are preserved. An empty list yields an empty
        result without hitting the DB.
        """
        if not job_ids:
            return []
        stmt = self._perm_filter.filter_sql(select(Job).where(Job.id.in_(job_ids)))
        result = await self._session.execute(stmt)
        by_id: dict[uuid.UUID, Job] = {j.id: j for j in result.scalars().all()}
        return [by_id.get(jid) for jid in job_ids]

    async def search(
        self,
        *,
        cursor: uuid.UUID | None = None,
        limit: int = 50,
        search_filter: Any | None = None,
    ) -> tuple[list[Job], uuid.UUID | None]:
        """Search jobs ordered by id, keyed-pagination via cursor."""
        stmt = self._perm_filter.filter_sql(select(Job).order_by(Job.id))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        if cursor is not None:
            stmt = stmt.where(Job.id > cursor)
        stmt = stmt.limit(limit)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        next_cursor = rows[-1].id if len(rows) == limit else None
        return rows, next_cursor

    async def update(
        self,
        job_id: uuid.UUID,
        payload: JobUpdate,
    ) -> Job:
        """Partially update a job.

        ``status`` may only be set to the restricted client set
        (``PENDING`` / ``SUSPENDED``); the schema enforces this. Updating
        ``job_details`` refreshes ``job_details_kind`` to match.
        """
        job = await self.get(job_id)
        fields = payload.model_fields_set
        for field, transform in _UPDATE_TRANSFORMS.items():
            if field in fields:
                setattr(job, field, transform(getattr(payload, field)))
        if "job_details" in fields and payload.job_details is not None:
            job.job_details = payload.job_details
            job.job_details_kind = _details_kind(payload.job_details)
        await self._session.flush()
        await self._session.refresh(job)
        return job

    async def delete(self, job_id: uuid.UUID) -> None:
        """Delete a job."""
        job = await self.get(job_id)
        await self._session.delete(job)
        await self._session.flush()

    async def count(self, search_filter: Any | None = None) -> int:
        """Total job count, scoped by the service's ``perm_filter``."""
        stmt = self._perm_filter.filter_sql(select(func.count()).select_from(Job))
        if search_filter is not None:
            stmt = search_filter.filter_sql(stmt)
        result = await self._session.execute(stmt)
        return int(result.scalar_one())

    # ------------------------------------------------------------------ #
    # Runner-owned create (claim-on-create) + conditional completion
    # ------------------------------------------------------------------ #

    async def create_runner_owned(
        self,
        payload: JobCreate,
        *,
        creator_id: uuid.UUID,
        runner_id: uuid.UUID,
        run_now: bool,
    ) -> Job:
        """Insert a job owned by a runner.

        When *run_now* is true the row is inserted directly as ``RUNNING`` with
        this runner's ``runner_id`` and ``started_at = now()`` (claim-on-insert)
        — the runner intends to run it immediately. When *run_now* is false the
        row is inserted as ``PENDING`` (``started_at = None``) for a later sweep
        to pick up. The client-supplied ``status`` on *payload* is ignored on
        this path (the runner owns the lifecycle).
        """
        details = payload.job_details
        now = datetime.now(UTC)
        job = Job(
            creator_id=creator_id,
            runner_id=runner_id,
            status=JOB_RUNNING if run_now else JOB_PENDING,
            detail=payload.detail,
            max_seconds_for_run=payload.max_seconds_for_run,
            started_at=now if run_now else None,
            job_details_kind=_details_kind(details),
            job_details=details,
        )
        self._session.add(job)
        await self._session.flush()
        await self._session.refresh(job)
        return job

    async def claim_pending(
        self,
        *,
        runner_id: uuid.UUID,
        limit: int,
    ) -> list[Job]:
        """Atomically claim up to *limit* ``PENDING`` jobs for *runner_id*.

        Sets ``runner_id``, ``status = RUNNING``, ``started_at = now()`` on each
        claimed row, scoped to ``perm_filter``. Uses
        ``FOR UPDATE SKIP LOCKED`` so concurrent runners do not block each other
        or claim the same job. The caller is responsible for not exceeding
        ``max_concurrent_jobs`` (it computes the remaining capacity and passes
        it as *limit*). Returns the freshly claimed jobs.
        """
        if limit <= 0:
            return []
        now = datetime.now(UTC)
        # Two-step claim within the same transaction. A single
        # `UPDATE ... WHERE id IN (SELECT ... LIMIT n FOR UPDATE SKIP LOCKED)`
        # is unreliable: the planner may flatten the subquery and drop the
        # LIMIT, claiming more than *limit* rows. Selecting the candidate ids
        # with `LIMIT n` first, then updating exactly those ids with a
        # `status = PENDING` re-check, keeps the count deterministic. The
        # re-check also makes concurrent claims safe: a row another runner
        # already moved to RUNNING is simply not matched here.
        claim_ids = (
            self._perm_filter.filter_sql(select(Job.id).where(Job.status == JOB_PENDING))
            .order_by(Job.id)
            .limit(limit)
        )
        ids = [row for (row,) in (await self._session.execute(claim_ids)).all()]
        if not ids:
            return []
        result = await self._session.execute(
            update(Job)
            .where(Job.id.in_(ids), Job.status == JOB_PENDING)
            .values(runner_id=runner_id, status=JOB_RUNNING, started_at=now)
            .returning(Job)
        )
        return list(result.scalars().all())

    async def update_progress(
        self,
        job_id: uuid.UUID,
        *,
        runner_id: uuid.UUID,
        progress: float,
        status_code: str | None = None,
    ) -> bool:
        """Conditionally update a running job's ``progress`` / ``status_code``.

        The UPDATE only fires while the job is still ``RUNNING`` and still owned
        by *runner_id* — the same race-guard pattern as :meth:`complete`, so a
        dead-runner recovery that already flipped the row to ``ERROR`` is not
        clobbered by a late progress tick. Returns True if a row was updated,
        False on 0 rows (the job is no longer ``RUNNING`` for this runner — a
        silent no-op for the caller).
        """
        if not 0.0 <= progress <= 1.0:
            raise ValueError(f"progress must be in [0.0, 1.0]; got {progress}")
        from sqlalchemy import CursorResult

        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                update(Job)
                .where(
                    Job.id == job_id,
                    Job.runner_id == runner_id,
                    Job.status == JOB_RUNNING,
                )
                .values(progress=progress, status_code=status_code)
            ),
        )
        return bool(result.rowcount)

    async def complete(
        self,
        job_id: uuid.UUID,
        *,
        runner_id: uuid.UUID,
        run: JobRun | None,
        job_details: JobDetails | None = None,
        exception: BaseException | None = None,
    ) -> bool:
        """Conditionally complete a job (the race guard).

        On success (*run* is not None) persist ``run.status`` / ``run.detail``;
        on exception persist ``status = ERROR`` and the exception text as
        ``detail``. The UPDATE only fires while the job is still ``RUNNING``
        and still owned by *runner_id*::

            UPDATE jobs SET status = :new, detail = :new_detail,
                            job_details = :..., updated_at = now()
            WHERE id = :id AND runner_id = :own AND status = 'RUNNING'

        *job_details* is the (possibly mutated) details object to persist back;
        when None the ``job_details`` column is left untouched. Returns True if
        a row was updated, False if 0 rows updated (the job was already moved
        to a terminal state — the runner abandons the write and never
        overwrites an existing ``ERROR``/terminal status with ``COMPLETED``).
        """
        if exception is not None:
            new_status = JOB_ERROR
            new_detail: str | None = f"{type(exception).__name__}: {exception}"
        else:
            assert run is not None
            new_status = run.status
            new_detail = run.detail
        values: dict[str, Any] = {"status": new_status, "detail": new_detail}
        # On COMPLETED, advance progress to 1.0; on ERROR leave it as-is so a
        # caller can still see how far a failed run got.
        if new_status == JOB_COMPLETED:
            values["progress"] = 1.0
        if job_details is not None:
            values["job_details"] = job_details
        from sqlalchemy import CursorResult

        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                update(Job)
                .where(
                    Job.id == job_id,
                    Job.runner_id == runner_id,
                    Job.status == JOB_RUNNING,
                )
                .values(**values)
            ),
        )
        return bool(result.rowcount)

    async def recover_dead_runners(self, *, now: datetime | None = None) -> int:
        """Mark ``RUNNING`` jobs past their ``max_seconds_for_run`` as ``ERROR``.

        Idempotent: concurrent runners running it is harmless (each oversize
        ``RUNNING`` row flips to ``ERROR`` once). The dead-runner sweep recovers
        rows orphaned when an owning runner crashed — the per-runner in-memory
        cancellation can only stop live tasks. Any runner can run this; it runs
        before claiming on each sweep.
        """
        now = now or datetime.now(UTC)
        # Per-row max_seconds_for_run means the cutoff must be computed in SQL:
        # started_at < :now - max_seconds_for_run * interval '1 second'.
        cutoff = text(":now_ts - max_seconds_for_run * interval '1 second'").bindparams(
            bindparam("now_ts", value=now)
        )
        from sqlalchemy import CursorResult

        result = cast(
            "CursorResult[Any]",
            await self._session.execute(
                update(Job)
                .where(
                    Job.status == JOB_RUNNING,
                    Job.started_at.is_not(None),
                    Job.started_at < cutoff,
                )
                .values(
                    status=JOB_ERROR,
                    detail="dead-runner/timeout recovery: run exceeded max_seconds_for_run",
                )
            ),
        )
        return int(result.rowcount or 0)

    # ------------------------------------------------------------------ #
    # Batch write
    # ------------------------------------------------------------------ #

    async def apply_batch(
        self,
        operations: list[JobBatchOp],
        perm_filters: dict[Action, SearchFilter[Job] | None],
        *,
        creator_id: uuid.UUID,
    ) -> list[Job | None]:
        """Apply a mix of create/update/delete operations in one transaction.

        Each operation is authorized against its own action via *perm_filters*;
        a ``None`` filter denies that operation
        (:class:`BatchPermissionDeniedError`). No commit is performed — the
        caller commits once after the whole batch succeeds (atomic). Returns
        results aligned with *operations*: the job for create/update, ``None``
        for delete.
        """
        results: list[Job | None] = []
        for op in operations:
            if isinstance(op, JobBatchCreate):
                results.append(await self._batch_create(op, perm_filters, creator_id=creator_id))
            elif isinstance(op, JobBatchUpdate):
                results.append(await self._batch_update(op, perm_filters))
            elif isinstance(op, JobBatchDelete):
                await self._batch_delete(op, perm_filters)
                results.append(None)
        return results

    async def _batch_create(
        self,
        op: JobBatchCreate,
        perm_filters: dict[Action, SearchFilter[Job] | None],
        *,
        creator_id: uuid.UUID,
    ) -> Job:
        filt = perm_filters.get(Action.CREATE)
        if filt is None:
            raise BatchPermissionDeniedError("create")
        return await JobService(self._session, filt).create(op.data, creator_id=creator_id)

    async def _batch_update(
        self,
        op: JobBatchUpdate,
        perm_filters: dict[Action, SearchFilter[Job] | None],
    ) -> Job:
        filt = perm_filters.get(Action.UPDATE)
        if filt is None:
            raise BatchPermissionDeniedError("update")
        return await JobService(self._session, filt).update(op.id, op.data)

    async def _batch_delete(
        self,
        op: JobBatchDelete,
        perm_filters: dict[Action, SearchFilter[Job] | None],
    ) -> None:
        filt = perm_filters.get(Action.DELETE)
        if filt is None:
            raise BatchPermissionDeniedError("delete")
        await JobService(self._session, filt).delete(op.id)

    # ------------------------------------------------------------------ #
    # Partition management
    # ------------------------------------------------------------------ #

    async def ensure_partitions(
        self,
        *,
        preallocate_days: int,
        retention_days: int,
        now: datetime | None = None,
    ) -> tuple[list[str], list[str]]:
        """Allocate future daily partitions and drop expired ones.

        Returns ``(created, dropped)`` — the names of partitions created and
        dropped this sweep. Idempotent: a partition that already exists is
        skipped. A ``DEFAULT`` partition is ensured once so inserts never fail
        if the manager falls behind. Mirrors
        :meth:`SandboxUsageService.ensure_partitions`.
        """
        now = now or datetime.now(UTC)
        created: list[str] = []
        for offset in range(preallocate_days):
            day = (now + timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
            name = await self._ensure_partition(day)
            if name is not None:
                created.append(name)
        await self._session.execute(
            text("CREATE TABLE IF NOT EXISTS jobs_default PARTITION OF jobs DEFAULT")
        )
        dropped = await self._drop_expired_partitions(retention_days, now)
        await self._session.commit()
        return created, dropped

    async def _ensure_partition(self, day: datetime) -> str | None:
        """Create the daily partition for *day* if absent; return its name or None."""
        name = _partition_name(day)
        start, end = _day_bounds(day)
        exists = (
            await self._session.execute(
                text("SELECT 1 FROM pg_class WHERE relname = :n"), {"n": name}
            )
        ).scalar_one_or_none()
        if exists is not None:
            return None
        await self._session.execute(
            text(f"CREATE TABLE {name} PARTITION OF jobs FOR VALUES FROM ('{start}') TO ('{end}')")
        )
        return name

    async def _drop_expired_partitions(self, retention_days: int, now: datetime) -> list[str]:
        """Drop partitions older than ``retention_days``. Never drops DEFAULT."""
        cutoff = (now - timedelta(days=retention_days)).date()
        rows = (
            await self._session.execute(
                text(
                    "SELECT inhrelid::regclass::text AS name FROM pg_inherits "
                    "WHERE inhparent = 'jobs'::regclass "
                    "AND inhrelid::regclass::text LIKE 'jobs_%'"
                )
            )
        ).all()
        dropped: list[str] = []
        for row in rows:
            name = row[0]
            suffix = name.rsplit("_", 1)[-1] if "_" in name else ""
            try:
                day = datetime.strptime(suffix, "%Y%m%d").date()
            except ValueError:
                continue  # not a dated partition (e.g. jobs_default)
            if day < cutoff:
                await self._session.execute(text(f"DROP TABLE IF EXISTS {name}"))
                dropped.append(name)
        return dropped


async def count_running_for_runner(session: AsyncSession, runner_id: uuid.UUID) -> int:
    """Count ``RUNNING`` jobs owned by *runner_id* (for max_concurrent_jobs)."""
    result = await session.execute(
        select(func.count())
        .select_from(Job)
        .where(Job.runner_id == runner_id, Job.status == JOB_RUNNING)
    )
    return int(result.scalar_one())
