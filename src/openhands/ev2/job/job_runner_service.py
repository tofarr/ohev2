"""Background :class:`JobRunnerService` that claims and runs jobs (issue #157).

Tied to the app lifespan. On startup each :class:`JobRunnerService` generates
its own unique UUID (so each process has its own ``runner_id``). The job sweep
(every ``sweep_interval``) runs, in order:

1. **Dead-runner sweep** (idempotent, runs before claiming): finds ``RUNNING``
   jobs whose ``now - started_at > max_seconds_for_run`` and marks them
   ``ERROR``. Recovers rows orphaned when an owning runner crashed.
2. **Per-runner timeout cancellation** (live tasks only): cancel the owning
   runner's overdue in-memory ``asyncio.Task``\\ s whose runtime exceeds
   ``max_seconds_for_run``.
3. **Claim**: atomically claim ``PENDING`` jobs (``RUNNING`` + own
   ``runner_id`` + ``started_at = now()``) without exceeding
   ``max_concurrent_jobs``; each claimed job runs as a background task with no
   DB session held open while running.

Completion uses the conditional UPDATE (``WHERE runner_id = :own AND status =
'RUNNING'``); on 0 rows updated the job was already terminal and the runner
abandons the write (never overwrites ``ERROR``/terminal with ``COMPLETED``).

The house-cleaning sweep (every ``house_cleaning_interval``) pre-creates future
daily partitions and drops expired ones (mirrors the usage-table loops).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from openhands.ev2.db import get_session_factory
from openhands.ev2.job.job_models import Job, JobDetails, JobProgressReporter, JobRun
from openhands.ev2.job.job_service import (
    JobService,
    count_running_for_runner,
)

logger = logging.getLogger(__name__)


class _JobProgressHandle:
    """Concrete :class:`JobProgressReporter` bound to ``(job_id, runner_id)``.

    Each :meth:`update` call opens its own short-lived DB session (the runner
    holds no session open while a job body runs) and performs the conditional
    UPDATE via :meth:`JobService.update_progress`. A call that matches 0 rows
    (the job is no longer ``RUNNING`` for this runner) is a silent no-op.
    """

    __slots__ = ("_job_id", "_runner_id")

    def __init__(self, job_id: uuid.UUID, runner_id: uuid.UUID) -> None:
        self._job_id = job_id
        self._runner_id = runner_id

    async def update(self, progress: float, status_code: str | None = None) -> None:
        factory = get_session_factory()
        async with factory() as session:
            await JobService(session).update_progress(
                self._job_id,
                runner_id=self._runner_id,
                progress=progress,
                status_code=status_code,
            )
            await session.commit()


class JobRunnerService:
    """Claims and runs jobs in the background, tied to the app lifespan.

    Each instance generates a unique ``runner_id`` on construction so each
    process has its own id. The sweep loop is driven externally (see
    :meth:`sweep_once` and the app lifespan wiring); the runner tracks its
    live in-memory :class:`asyncio.Task`\\ s so per-runner timeout
    cancellation can cancel overdue ones.
    """

    def __init__(self, *, max_concurrent_jobs: int = 1) -> None:
        self.runner_id = uuid.uuid4()
        self._max_concurrent_jobs = max_concurrent_jobs
        # job_id -> (Task, started_at) for live in-memory runs.
        self._live: dict[uuid.UUID, tuple[asyncio.Task[None], datetime]] = {}

    # ------------------------------------------------------------------ #
    # Sweep (dead-runner recovery + timeout cancellation + claim + run)
    # ------------------------------------------------------------------ #

    async def sweep_once(self) -> str | None:
        """Run one job sweep: dead-runner recovery, timeout cancel, claim, run.

        Returns a summary message for logging. Each phase uses its own session
        (opened and committed independently) so no DB session is held open
        while a job is running.
        """
        recovered = await self._recover_dead_runners()
        self._cancel_overdue_live_tasks()
        claimed = await self._claim_and_run()
        parts: list[str] = []
        if recovered:
            parts.append(f"recovered {recovered} dead jobs")
        if claimed:
            parts.append(f"claimed {claimed} jobs")
        return "; ".join(parts) if parts else None

    async def _recover_dead_runners(self) -> int:
        """Idempotent dead-runner sweep: mark oversize RUNNING jobs ERROR."""
        factory = get_session_factory()
        async with factory() as session:
            service = JobService(session)
            count = await service.recover_dead_runners()
            await session.commit()
        return count

    def _cancel_overdue_live_tasks(self) -> int:
        """Cancel this runner's live tasks whose runtime exceeds their timeout."""
        now = datetime.now(UTC)
        cancelled = 0
        for job_id, (task, started_at) in list(self._live.items()):
            job: Job | None = getattr(task, "_job", None)
            max_seconds = job.max_seconds_for_run if job is not None else 60
            if (now - started_at).total_seconds() > max_seconds:
                task.cancel()
                cancelled += 1
                logger.warning("Cancelling overdue job %s (ran > %ss)", job_id, max_seconds)
        return cancelled

    async def _claim_and_run(self) -> int:
        """Claim PENDING jobs up to remaining capacity and start them running."""
        factory = get_session_factory()
        async with factory() as session:
            running = await count_running_for_runner(session, self.runner_id)
            capacity = max(0, self._max_concurrent_jobs - running)
            if capacity <= 0:
                return 0
            service = JobService(session)
            claimed = await service.claim_pending(runner_id=self.runner_id, limit=capacity)
            await session.commit()
        for job in claimed:
            self._start_run(job)
        return len(claimed)

    def _start_run(self, job: Job) -> None:
        """Spawn the background task that runs *job* and completes it.

        The task opens its own session for the final conditional UPDATE; no DB
        session is held open while the job body runs. The job's ``id`` /
        ``creator_id`` and a progress handle are threaded into the body.
        """
        job_id = job.id
        creator_id = job.creator_id
        details = job.job_details
        progress: JobProgressReporter = _JobProgressHandle(job_id, self.runner_id)
        started_at = datetime.now(UTC)
        task = asyncio.create_task(
            self._run_job(job_id, creator_id, details, progress),
            name=f"job-run-{job_id}",
        )
        task._job = job  # type: ignore[attr-defined]  # for timeout cancellation
        self._live[job_id] = (task, started_at)

        def _on_done(_t: asyncio.Task[None], jid: uuid.UUID = job_id) -> None:
            self._live.pop(jid, None)

        task.add_done_callback(_on_done)

    async def _run_job(
        self,
        job_id: uuid.UUID,
        creator_id: uuid.UUID,
        details: JobDetails,
        progress: JobProgressReporter,
    ) -> None:
        """Invoke the job body and persist the terminal status (conditional)."""
        run: JobRun | None = None
        exception: BaseException | None = None
        try:
            run = await details(job_id, creator_id, progress)
        except BaseException as exc:  # runner must persist any failure
            exception = exc
            logger.exception("Job %s raised; persisting ERROR", job_id)
        factory = get_session_factory()
        async with factory() as session:
            service = JobService(session)
            updated = await service.complete(
                job_id,
                runner_id=self.runner_id,
                run=run,
                exception=exception,
            )
            await session.commit()
        if not updated:
            logger.info("Job %s already terminal; abandoning completion write", job_id)

    # ------------------------------------------------------------------ #
    # House-cleaning (partition management)
    # ------------------------------------------------------------------ #

    async def house_clean_once(self, *, preallocate_days: int, retention_days: int) -> str | None:
        """Pre-create future daily partitions and drop expired ones (idempotent)."""
        factory = get_session_factory()
        async with factory() as session:
            service = JobService(session)
            created, dropped = await service.ensure_partitions(
                preallocate_days=preallocate_days,
                retention_days=retention_days,
            )
            await session.commit()
        parts: list[str] = []
        if created:
            parts.append(f"created {len(created)} partitions")
        if dropped:
            parts.append(f"dropped {len(dropped)} partitions")
        return "; ".join(parts) if parts else None

    # ------------------------------------------------------------------ #
    # Shutdown
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        """Cancel all live in-memory tasks on shutdown."""
        for _job_id, (task, _started_at) in list(self._live.items()):
            task.cancel()
        for _job_id, (task, _started_at) in list(self._live.items()):
            try:
                await task
            except asyncio.CancelledError:
                pass
            except BaseException:  # best-effort drain on shutdown
                logger.exception("Live job task raised during shutdown drain")
        self._live.clear()
