"""Unit tests for the job feature (issue #157).

Hermetic PostgreSQL + FastAPI ASGI client fixtures (see ``conftest.py``).
Covers:

* the service layer (create / get / get_many / search / update / delete /
  count / batch) and the JobDetails discriminated-union round-trip
* the runner paths: claim-on-create, claim_pending, conditional completion
  (the race guard — never overwrites a terminal status), dead-runner recovery
* partition management (ensure_partitions creates future daily partitions and
  drops expired ones; the DEFAULT partition always exists)
* the HTTP routes (governed CRUD + batch + count) including role-schema parity
  for ``job_permission``
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from pydantic import Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import assign_role, make_principal

from openhands.ev2.db import get_session_factory
from openhands.ev2.job.job_models import (
    JOB_COMPLETED,
    JOB_ERROR,
    JOB_PENDING,
    JOB_RUNNING,
    Job,
    JobDetails,
    JobProgressReporter,
    JobRun,
    LogJobDetails,
)
from openhands.ev2.job.job_schemas import (
    JobCreate,
    JobUpdate,
)
from openhands.ev2.job.job_service import (
    JobNotFoundError,
    JobService,
    count_running_for_runner,
)
from openhands.ev2.security.security_models import CreatorPermission, Denied
from openhands.ev2.user.user_models import User
from openhands.ev2.util.search_filter import ALL

pytestmark = pytest.mark.asyncio


class _NullProgressReporter:
    """No-op :class:`JobProgressReporter` for tests that don't persist progress."""

    async def update(self, progress: float, status_code: str | None = None) -> None:
        return None


def _details(message: str = "hello") -> LogJobDetails:
    return LogJobDetails(message=message)


def _details_json(message: str = "hello") -> dict[str, Any]:
    return _details(message).model_dump(mode="json")


def _payload(message: str = "hello", status: str = "PENDING") -> dict[str, Any]:
    return {
        "job_details": _details_json(message),
        "status": status,
        "max_seconds_for_run": 60,
    }


@pytest.fixture
async def owner(session: AsyncSession) -> User:
    return await make_principal(session, email="job-owner@example.com", username="job-owner")


# --------------------------------------------------------------------------- #
# JobDetails round-trip
# --------------------------------------------------------------------------- #


class TestJobDetailsRoundTrip:
    async def test_details_serializes_and_deserializes(self) -> None:
        d = LogJobDetails(message="run-me")
        blob = d.model_dump(mode="json")
        assert blob["kind"] == "LogJobDetails"
        restored = JobDetails.model_validate(blob)
        assert isinstance(restored, LogJobDetails)
        assert restored.message == "run-me"
        assert restored.kind == "LogJobDetails"

    async def test_log_job_details_completes(self) -> None:
        run = await _details("go").__call__(
            uuid.uuid4(), uuid.uuid4(), _NullProgressReporter()
        )
        assert run.status == JOB_COMPLETED


# --------------------------------------------------------------------------- #
# Service layer
# --------------------------------------------------------------------------- #


class TestJobService:
    async def test_create_and_get(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        job = await service.create(
            JobCreate(job_details=_details("a"), status="PENDING"),
            creator_id=owner.id,
        )
        assert job.status == JOB_PENDING
        assert job.creator_id == owner.id
        assert job.runner_id is None
        assert job.started_at is None
        assert job.job_details_kind == "LogJobDetails"
        fetched = await service.get(job.id)
        assert fetched.id == job.id
        assert isinstance(fetched.job_details, LogJobDetails)

    async def test_create_default_status_is_pending(
        self, session: AsyncSession, owner: User
    ) -> None:
        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        assert job.status == JOB_PENDING

    async def test_get_missing_returns_not_found(self, session: AsyncSession) -> None:
        with pytest.raises(JobNotFoundError):
            await JobService(session, ALL).get(uuid.uuid4())

    async def test_get_many_aligned_with_ids(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        j1 = await service.create(JobCreate(job_details=_details("1")), creator_id=owner.id)
        j2 = await service.create(JobCreate(job_details=_details("2")), creator_id=owner.id)
        missing = uuid.uuid4()
        result = await service.get_many([j1.id, missing, j2.id])
        assert result[0] is not None and result[0].id == j1.id
        assert result[1] is None
        assert result[2] is not None and result[2].id == j2.id

    async def test_get_many_empty(self, session: AsyncSession) -> None:
        assert await JobService(session, ALL).get_many([]) == []

    async def test_search_paginates_by_cursor(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        created = []
        for i in range(5):
            j = await service.create(JobCreate(job_details=_details(str(i))), creator_id=owner.id)
            created.append(j)
        rows, nxt = await service.search(limit=2)
        assert len(rows) == 2
        assert nxt is not None
        rows2, nxt2 = await service.search(limit=2, cursor=nxt)
        assert len(rows2) == 2
        assert {r.id for r in rows} != {r.id for r in rows2}
        rows3, nxt3 = await service.search(limit=100, cursor=nxt2)
        assert len(rows3) == 1
        assert nxt3 is None

    async def test_count(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        assert await service.count() == 0
        await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        assert await service.count() == 2

    async def test_update_changes_fields(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        updated = await service.update(job.id, JobUpdate(status="SUSPENDED", detail="paused"))
        assert updated.status == "SUSPENDED"
        assert updated.detail == "paused"

    async def test_update_swaps_details_kind(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details("a")), creator_id=owner.id)
        new_details = LogJobDetails(message="b")
        updated = await service.update(job.id, JobUpdate(job_details=new_details))
        assert updated.job_details_kind == "LogJobDetails"
        assert isinstance(updated.job_details, LogJobDetails)
        assert updated.job_details.message == "b"

    async def test_update_missing_returns_not_found(self, session: AsyncSession) -> None:
        with pytest.raises(JobNotFoundError):
            await JobService(session, ALL).update(uuid.uuid4(), JobUpdate(detail="x"))

    async def test_delete_removes(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        await service.delete(job.id)
        with pytest.raises(JobNotFoundError):
            await service.get(job.id)

    async def test_delete_missing_returns_not_found(self, session: AsyncSession) -> None:
        with pytest.raises(JobNotFoundError):
            await JobService(session, ALL).delete(uuid.uuid4())

    async def test_batch_write_mixed_cud(self, session: AsyncSession, owner: User) -> None:
        from openhands.ev2.job.job_schemas import (
            JobBatchCreate,
            JobBatchDelete,
            JobBatchUpdate,
        )
        from openhands.ev2.security.security_models import Action
        from openhands.ev2.util.search_filter import SearchFilter

        service = JobService(session)
        perms: dict[Action, SearchFilter[Job] | None] = dict.fromkeys(Action, ALL)
        ops: list[JobBatchCreate | JobBatchUpdate | JobBatchDelete] = [
            JobBatchCreate(data=JobCreate(job_details=_details("c1"))),
            JobBatchCreate(data=JobCreate(job_details=_details("c2"))),
        ]
        results = await service.apply_batch(ops, perms, creator_id=owner.id)
        assert len(results) == 2
        created_id = results[0].id  # type: ignore[union-attr]
        ops2: list[JobBatchCreate | JobBatchUpdate | JobBatchDelete] = [
            JobBatchUpdate(id=created_id, data=JobUpdate(detail="updated")),
            JobBatchDelete(id=results[1].id),  # type: ignore[union-attr]
        ]
        await service.apply_batch(ops2, perms, creator_id=owner.id)
        fetched = await JobService(session, ALL).get(created_id)
        assert fetched.detail == "updated"
        with pytest.raises(JobNotFoundError):
            await JobService(session, ALL).get(results[1].id)  # type: ignore[union-attr]


# --------------------------------------------------------------------------- #
# Runner paths: claim-on-create, claim, conditional completion, dead-runner
# --------------------------------------------------------------------------- #


class TestJobRunnerPaths:
    async def test_create_runner_owned_run_now(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        assert job.status == JOB_RUNNING
        assert job.runner_id == runner_id
        assert job.started_at is not None

    async def test_create_runner_owned_not_run_now(
        self, session: AsyncSession, owner: User
    ) -> None:
        service = JobService(session, ALL)
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=uuid.uuid4(),
            run_now=False,
        )
        assert job.status == JOB_PENDING
        assert job.started_at is None

    async def test_claim_pending_marks_running(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        runner_id = uuid.uuid4()
        claimed = await service.claim_pending(runner_id=runner_id, limit=10)
        assert len(claimed) == 2
        assert all(c.status == JOB_RUNNING for c in claimed)
        assert all(c.runner_id == runner_id for c in claimed)
        assert all(c.started_at is not None for c in claimed)

    async def test_claim_pending_respects_limit(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        for _ in range(3):
            await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        claimed = await service.claim_pending(runner_id=uuid.uuid4(), limit=1)
        assert len(claimed) == 1

    async def test_claim_pending_zero_limit(self, session: AsyncSession) -> None:
        claimed = await JobService(session, ALL).claim_pending(runner_id=uuid.uuid4(), limit=0)
        assert claimed == []

    async def test_claim_skips_suspended(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        await service.create(
            JobCreate(job_details=_details(), status="SUSPENDED"), creator_id=owner.id
        )
        claimed = await service.claim_pending(runner_id=uuid.uuid4(), limit=10)
        assert claimed == []

    async def test_complete_success(self, session: AsyncSession, owner: User) -> None:
        from openhands.ev2.job.job_models import JobRun

        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        runner_id = uuid.uuid4()
        claimed = await service.claim_pending(runner_id=runner_id, limit=1)
        assert len(claimed) == 1
        ok = await service.complete(
            job.id, runner_id=runner_id, run=JobRun(status=JOB_COMPLETED, detail="done")
        )
        assert ok is True
        fetched = await service.get(job.id)
        assert fetched.status == JOB_COMPLETED
        assert fetched.detail == "done"

    async def test_complete_on_exception_persists_error(
        self, session: AsyncSession, owner: User
    ) -> None:
        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        runner_id = uuid.uuid4()
        await service.claim_pending(runner_id=runner_id, limit=1)
        ok = await service.complete(
            job.id, runner_id=runner_id, run=None, exception=ValueError("boom")
        )
        assert ok is True
        fetched = await service.get(job.id)
        assert fetched.status == JOB_ERROR
        assert "ValueError" in (fetched.detail or "")

    async def test_complete_race_guard_does_not_overwrite_terminal(
        self, session: AsyncSession, owner: User
    ) -> None:
        """A job already moved to ERROR must not be overwritten with COMPLETED."""
        from openhands.ev2.job.job_models import JobRun

        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        runner_id = uuid.uuid4()
        await service.claim_pending(runner_id=runner_id, limit=1)
        # First completion: ERROR (e.g. dead-runner recovery raced).
        ok1 = await service.complete(
            job.id, runner_id=runner_id, run=None, exception=RuntimeError("crashed")
        )
        assert ok1 is True
        # Second completion (the live runner finishing): COMPLETED must be abandoned.
        ok2 = await service.complete(job.id, runner_id=runner_id, run=JobRun(status=JOB_COMPLETED))
        assert ok2 is False
        fetched = await service.get(job.id)
        assert fetched.status == JOB_ERROR

    async def test_complete_wrong_runner_does_not_persist(
        self, session: AsyncSession, owner: User
    ) -> None:
        from openhands.ev2.job.job_models import JobRun

        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        owner_runner = uuid.uuid4()
        await service.claim_pending(runner_id=owner_runner, limit=1)
        other = uuid.uuid4()
        ok = await service.complete(job.id, runner_id=other, run=JobRun(status=JOB_COMPLETED))
        assert ok is False
        fetched = await service.get(job.id)
        assert fetched.status == JOB_RUNNING

    async def test_recover_dead_runners(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details(), max_seconds_for_run=1),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        # Simulate the job having started 2 minutes ago (past its 1s limit).
        await session.execute(
            text("UPDATE jobs SET started_at = :ago WHERE id = :id"),
            {"ago": datetime.now(UTC) - timedelta(minutes=2), "id": job.id},
        )
        await session.commit()
        recovered = await service.recover_dead_runners()
        assert recovered >= 1
        fetched = await service.get(job.id)
        assert fetched.status == JOB_ERROR

    async def test_recover_dead_runners_leaves_fresh_running(
        self, session: AsyncSession, owner: User
    ) -> None:
        service = JobService(session, ALL)
        await service.create_runner_owned(
            JobCreate(job_details=_details(), max_seconds_for_run=60),
            creator_id=owner.id,
            runner_id=uuid.uuid4(),
            run_now=True,
        )
        recovered = await service.recover_dead_runners()
        assert recovered == 0

    async def test_count_running_for_runner(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session, ALL)
        r1 = uuid.uuid4()
        await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=r1,
            run_now=True,
        )
        await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=r1,
            run_now=True,
        )
        assert await count_running_for_runner(session, r1) == 2
        assert await count_running_for_runner(session, uuid.uuid4()) == 0


# --------------------------------------------------------------------------- #
# JobRunnerService end-to-end sweep / run / shutdown (issue #176)
# --------------------------------------------------------------------------- #


class _FailingJobDetails(JobDetails):
    """Job body that always raises, to exercise the runner's ERROR path."""

    message: str = Field(default="boom")

    async def __call__(
        self,
        job_id: uuid.UUID,
        creator_id: uuid.UUID,
        progress: JobProgressReporter,
    ) -> JobRun:
        raise RuntimeError("job body crashed")


class _SlowJobDetails(JobDetails):
    """Job body that sleeps, to exercise timeout cancellation / shutdown drain."""

    message: str = Field(default="slow")

    async def __call__(
        self,
        job_id: uuid.UUID,
        creator_id: uuid.UUID,
        progress: JobProgressReporter,
    ) -> JobRun:
        await asyncio.sleep(10)
        return JobRun(status=JOB_COMPLETED, detail=self.message)


class TestJobRunnerService:
    """Exercises the JobRunnerService background-sweep path end to end.

    These tests commit so the runner's short-lived sessions (opened via
    get_session_factory()) can see the seeded rows.
    """

    async def test_sweep_once_claims_and_runs_pending_job(
        self, session: AsyncSession, owner: User
    ) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        service = JobService(session, ALL)
        await service.create(JobCreate(job_details=_details("sweep-me")), creator_id=owner.id)
        await session.commit()

        runner = JobRunnerService(max_concurrent_jobs=1)
        msg = await runner.sweep_once()
        assert msg is not None
        assert "claimed 1 jobs" in msg
        # Let the background task finish.
        await asyncio.gather(*[t for t, _ in runner._live.values()])
        await runner.aclose()

        async with get_session_factory()() as s:
            rows, _ = await JobService(s, ALL).search(limit=1)
            assert rows[0].status == JOB_COMPLETED

    async def test_sweep_once_no_jobs_returns_none(
        self, session: AsyncSession
    ) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        await session.commit()
        runner = JobRunnerService()
        msg = await runner.sweep_once()
        assert msg is None
        await runner.aclose()

    async def test_sweep_once_recovers_dead_runner(
        self, session: AsyncSession, owner: User
    ) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        service = JobService(session, ALL)
        # Create a RUNNING job that looks like it belongs to a dead runner
        # (started_at pushed past its max_seconds_for_run).
        job = await service.create_runner_owned(
            JobCreate(job_details=_details(), max_seconds_for_run=1),
            creator_id=owner.id,
            runner_id=uuid.uuid4(),
            run_now=True,
        )
        await session.execute(
            text("UPDATE jobs SET started_at = :ago WHERE id = :id"),
            {"ago": datetime.now(UTC) - timedelta(minutes=2), "id": job.id},
        )
        await session.commit()

        runner = JobRunnerService()
        msg = await runner.sweep_once()
        assert msg is not None
        assert "recovered 1 dead jobs" in msg
        await runner.aclose()

    async def test_run_job_persists_error_on_exception(
        self, session: AsyncSession, owner: User
    ) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        service = JobService(session, ALL)
        await service.create(JobCreate(job_details=_FailingJobDetails()), creator_id=owner.id)
        await session.commit()

        runner = JobRunnerService(max_concurrent_jobs=1)
        await runner.sweep_once()
        await asyncio.gather(*[t for t, _ in runner._live.values()])
        await runner.aclose()

        async with get_session_factory()() as s:
            rows, _ = await JobService(s, ALL).search(limit=1)
            assert rows[0].status == JOB_ERROR

    async def test_cancel_overdue_live_task(
        self, session: AsyncSession, owner: User
    ) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        service = JobService(session, ALL)
        await service.create(
            JobCreate(job_details=_SlowJobDetails(), max_seconds_for_run=1), creator_id=owner.id
        )
        await session.commit()

        runner = JobRunnerService(max_concurrent_jobs=1)
        await runner.sweep_once()
        await asyncio.sleep(0.05)  # let the task start
        # Push the in-memory started_at into the past so the task is overdue.
        for jid in list(runner._live):
            task = runner._live[jid][0]
            runner._live[jid] = (task, datetime.now(UTC) - timedelta(minutes=2))
        cancelled = runner._cancel_overdue_live_tasks()
        assert cancelled == 1
        await runner.aclose()

    async def test_house_clean_once(self, session: AsyncSession) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        await session.commit()
        runner = JobRunnerService()
        msg = await runner.house_clean_once(preallocate_days=7, retention_days=30)
        # Partitions may already exist; msg is None if nothing to create/drop.
        assert msg is None or "partitions" in msg
        await runner.aclose()

    async def test_aclose_cancels_live_tasks(
        self, session: AsyncSession, owner: User
    ) -> None:
        from openhands.ev2.job.job_runner_service import JobRunnerService

        service = JobService(session, ALL)
        await service.create(JobCreate(job_details=_SlowJobDetails()), creator_id=owner.id)
        await session.commit()

        runner = JobRunnerService(max_concurrent_jobs=1)
        await runner.sweep_once()
        await asyncio.sleep(0.05)  # let the task start
        assert len(runner._live) == 1
        await runner.aclose()
        assert len(runner._live) == 0


# --------------------------------------------------------------------------- #
# Progress / status_code (issue #176)
# --------------------------------------------------------------------------- #


class _RecordingProgressReporter:
    """JobProgressReporter that records update calls (does not persist)."""

    def __init__(self) -> None:
        self.calls: list[tuple[float, str | None]] = []

    async def update(self, progress: float, status_code: str | None = None) -> None:
        self.calls.append((progress, status_code))


class TestJobProgress:
    async def test_update_progress_persists_while_running(
        self, session: AsyncSession, owner: User
    ) -> None:
        """A progress.update while RUNNING persists progress / status_code."""
        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        ok = await service.update_progress(
            job.id, runner_id=runner_id, progress=0.5, status_code="stage-2"
        )
        assert ok is True
        fetched = await service.get(job.id)
        assert fetched.progress == 0.5
        assert fetched.status_code == "stage-2"

    async def test_update_progress_noop_after_error(
        self, session: AsyncSession, owner: User
    ) -> None:
        """A late progress.update after dead-runner recovery to ERROR is a no-op."""

        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        # First move the job to ERROR (simulating dead-runner recovery).
        await service.complete(job.id, runner_id=runner_id, run=None, exception=RuntimeError("crashed"))
        # A late progress tick must not overwrite the terminal row.
        ok = await service.update_progress(
            job.id, runner_id=runner_id, progress=0.9, status_code="late"
        )
        assert ok is False
        fetched = await service.get(job.id)
        assert fetched.status == JOB_ERROR
        assert fetched.progress == 0.0  # never advanced past the initial 0.0
        assert fetched.status_code is None

    async def test_update_progress_wrong_runner_is_noop(
        self, session: AsyncSession, owner: User
    ) -> None:
        """A progress.update from a non-owning runner matches 0 rows."""
        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        ok = await service.update_progress(
            job.id, runner_id=uuid.uuid4(), progress=0.5
        )
        assert ok is False
        fetched = await service.get(job.id)
        assert fetched.progress == 0.0
        assert fetched.status_code is None

    async def test_update_progress_rejects_out_of_range(
        self, session: AsyncSession, owner: User
    ) -> None:
        """progress outside [0.0, 1.0] raises ValueError."""
        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        with pytest.raises(ValueError):
            await service.update_progress(job.id, runner_id=runner_id, progress=1.5)
        with pytest.raises(ValueError):
            await service.update_progress(job.id, runner_id=runner_id, progress=-0.1)

    async def test_complete_sets_progress_to_one_on_completed(
        self, session: AsyncSession, owner: User
    ) -> None:
        """On COMPLETED, complete sets progress = 1.0."""
        from openhands.ev2.job.job_models import JobRun

        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        await service.update_progress(job.id, runner_id=runner_id, progress=0.3)
        ok = await service.complete(
            job.id, runner_id=runner_id, run=JobRun(status=JOB_COMPLETED, detail="done")
        )
        assert ok is True
        fetched = await service.get(job.id)
        assert fetched.status == JOB_COMPLETED
        assert fetched.progress == 1.0

    async def test_complete_error_leaves_progress_unchanged(
        self, session: AsyncSession, owner: User
    ) -> None:
        """On ERROR, complete leaves progress as-is (the last reported value)."""
        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_details()),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        await service.update_progress(
            job.id, runner_id=runner_id, progress=0.4, status_code="stage-1"
        )
        ok = await service.complete(job.id, runner_id=runner_id, run=None, exception=ValueError("boom"))
        assert ok is True
        fetched = await service.get(job.id)
        assert fetched.status == JOB_ERROR
        assert fetched.progress == 0.4  # unchanged
        assert fetched.status_code == "stage-1"

    async def test_new_job_defaults_progress_zero(
        self, session: AsyncSession, owner: User
    ) -> None:
        """A freshly created job has progress 0.0 and status_code None."""
        service = JobService(session, ALL)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        assert job.progress == 0.0
        assert job.status_code is None


# --------------------------------------------------------------------------- #
# JobDetails signature round-trip with the new __call__ contract (issue #176)
# --------------------------------------------------------------------------- #


class _ProgressJobDetails(JobDetails):
    """Test variant that calls progress.update mid-run and records identity."""

    message: str = Field(description="Message logged on run.")

    async def __call__(
        self,
        job_id: uuid.UUID,
        creator_id: uuid.UUID,
        progress: JobProgressReporter,
    ) -> JobRun:
        await progress.update(0.5, status_code="stage-2")
        return JobRun(status=JOB_COMPLETED, detail=self.message)


class TestJobDetailsSignature:
    async def test_progress_job_details_round_trips(self) -> None:
        """A stored _ProgressJobDetails deserializes back to the right subclass."""
        d = _ProgressJobDetails(message="run-me")
        blob = d.model_dump(mode="json")
        assert blob["kind"] == "_ProgressJobDetails"
        restored = JobDetails.model_validate(blob)
        assert isinstance(restored, _ProgressJobDetails)
        assert restored.message == "run-me"

    async def test_progress_job_details_receives_identity_and_progress(self) -> None:
        """The new __call__ signature receives job_id, creator_id, and progress."""
        d = _ProgressJobDetails(message="run-me")
        job_id = uuid.uuid4()
        creator_id = uuid.uuid4()
        reporter = _RecordingProgressReporter()
        run = await d(job_id, creator_id, reporter)
        assert run.status == JOB_COMPLETED
        assert run.detail == "run-me"
        assert reporter.calls == [(0.5, "stage-2")]

    async def test_progress_job_details_runs_through_service(
        self, session: AsyncSession, owner: User
    ) -> None:
        """A job body calling progress.update persists values while RUNNING.

        The _JobProgressHandle opens its own short-lived session (mirroring
        production), so the creating session must commit first to make the
        row visible to it. Reads after the handle's commit use a fresh
        session to avoid the test session's stale identity map (the factory
        is configured with ``expire_on_commit=False``).
        """
        from openhands.ev2.db import get_session_factory
        from openhands.ev2.job.job_runner_service import _JobProgressHandle

        service = JobService(session, ALL)
        runner_id = uuid.uuid4()
        job = await service.create_runner_owned(
            JobCreate(job_details=_ProgressJobDetails(message="stage-run")),
            creator_id=owner.id,
            runner_id=runner_id,
            run_now=True,
        )
        await session.commit()
        # Simulate the runner invoking the body with a real progress handle.
        handle: JobProgressReporter = _JobProgressHandle(job.id, runner_id)
        run = await job.job_details(job.id, owner.id, handle)
        # Read with a fresh session to see the handle's committed update.
        async with get_session_factory()() as s:
            fetched = await JobService(s, ALL).get(job.id)
            assert fetched.progress == 0.5
            assert fetched.status_code == "stage-2"
        # Then complete the job and read the final state with a fresh session.
        await service.complete(job.id, runner_id=runner_id, run=run)
        await session.commit()
        async with get_session_factory()() as s:
            done = await JobService(s, ALL).get(job.id)
            assert done.status == JOB_COMPLETED
            assert done.progress == 1.0


# --------------------------------------------------------------------------- #
# Schema exposure (JobRead exposes progress/status_code; create/update reject)
# --------------------------------------------------------------------------- #


class TestJobProgressSchemas:
    async def test_job_read_exposes_progress_and_status_code(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload("a"))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["progress"] == 0.0
        assert body["status_code"] is None

    async def test_job_create_ignores_progress(self, client: AsyncClient) -> None:
        """progress is not client-settable: an extra field is ignored (Pydantic
        default behavior) and the created job's progress stays 0.0."""
        payload = _payload("a")
        payload["progress"] = 0.5
        resp = await client.post("/jobs", json=payload)
        assert resp.status_code == 201, resp.text
        assert resp.json()["progress"] == 0.0

    async def test_job_create_ignores_status_code(self, client: AsyncClient) -> None:
        """status_code is not client-settable: an extra field is ignored and
        the created job's status_code stays None."""
        payload = _payload("a")
        payload["status_code"] = "stage-1"
        resp = await client.post("/jobs", json=payload)
        assert resp.status_code == 201, resp.text
        assert resp.json()["status_code"] is None

    async def test_job_update_ignores_progress(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload("a"))
        job_id = resp.json()["id"]
        resp = await client.patch(f"/jobs/{job_id}", json={"progress": 0.5})
        assert resp.status_code == 200, resp.text
        assert resp.json()["progress"] == 0.0

    async def test_job_update_ignores_status_code(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload("a"))
        job_id = resp.json()["id"]
        resp = await client.patch(f"/jobs/{job_id}", json={"status_code": "stage-1"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status_code"] is None


# --------------------------------------------------------------------------- #
# Partition management
# --------------------------------------------------------------------------- #


class TestJobPartitions:
    async def test_ensure_partitions_creates_today_and_future(self, session: AsyncSession) -> None:
        service = JobService(session)
        created, _dropped = await service.ensure_partitions(preallocate_days=3, retention_days=365)
        today = datetime.now(UTC).strftime("%Y%m%d")
        assert any(today in name for name in created)
        # DEFAULT partition always exists.
        assert await session.execute(text("SELECT 1 FROM pg_class WHERE relname = 'jobs_default'"))

    async def test_ensure_partitions_idempotent(self, session: AsyncSession) -> None:
        service = JobService(session)
        await service.ensure_partitions(preallocate_days=2, retention_days=365)
        created, _ = await service.ensure_partitions(preallocate_days=2, retention_days=365)
        # Second call creates no new partitions (all already exist).
        assert created == []

    async def test_insert_routes_to_partition(self, session: AsyncSession, owner: User) -> None:
        service = JobService(session)
        await service.ensure_partitions(preallocate_days=1, retention_days=365)
        job = await service.create(JobCreate(job_details=_details()), creator_id=owner.id)
        # The row landed in a dated partition (or default).
        parent = await session.execute(
            text("SELECT tableoid::regclass::text FROM jobs WHERE id = :id"),
            {"id": job.id},
        )
        table_name = parent.scalar_one()
        assert table_name.startswith("jobs")


# --------------------------------------------------------------------------- #
# HTTP routes (authenticated as the test admin principal — Permitted for job)
# --------------------------------------------------------------------------- #


class TestJobRoutes:
    async def test_create_and_get(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload("a"))
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "PENDING"
        assert body["job_details_kind"] == "LogJobDetails"
        assert "created_at" not in body  # partition key not exposed
        got = await client.get(f"/jobs/{body['id']}")
        assert got.status_code == 200
        assert got.json()["id"] == body["id"]

    async def test_create_rejects_runner_status(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload(status="RUNNING"))
        assert resp.status_code == 422

    async def test_search_lists_jobs(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/jobs", json=_payload(str(i)))
        resp = await client.get("/jobs")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["items"]) == 3

    async def test_count(self, client: AsyncClient) -> None:
        await client.post("/jobs", json=_payload())
        resp = await client.get("/jobs/count")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    async def test_update_changes_fields(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload())
        job_id = resp.json()["id"]
        resp = await client.patch(f"/jobs/{job_id}", json={"status": "SUSPENDED"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "SUSPENDED"

    async def test_delete_removes(self, client: AsyncClient) -> None:
        resp = await client.post("/jobs", json=_payload())
        job_id = resp.json()["id"]
        resp = await client.delete(f"/jobs/{job_id}")
        assert resp.status_code == 204
        got = await client.get(f"/jobs/{job_id}")
        assert got.status_code == 404

    async def test_get_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.get(f"/jobs/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_batch_read(self, client: AsyncClient) -> None:
        ids = []
        for i in range(3):
            r = await client.post("/jobs", json=_payload(str(i)))
            ids.append(r.json()["id"])
        resp = await client.get("/jobs/batch", params={"ids": ids})
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 3
        assert all(i is not None for i in items)

    async def test_batch_write_mixed_cud(self, client: AsyncClient) -> None:
        c1 = (await client.post("/jobs", json=_payload("c1"))).json()["id"]
        c2 = (await client.post("/jobs", json=_payload("c2"))).json()["id"]
        batch = {
            "operations": [
                {"op": "update", "id": c1, "data": {"detail": "upd"}},
                {"op": "delete", "id": c2},
                {"op": "create", "data": _payload("c3")},
            ]
        }
        resp = await client.post("/jobs/batch", json=batch)
        assert resp.status_code == 200, resp.text
        items = resp.json()["items"]
        assert items[0]["detail"] == "upd"
        assert items[1] is None
        assert items[2]["job_details_kind"] == "LogJobDetails"

    async def test_search_rejects_invalid_cursor(self, client: AsyncClient) -> None:
        resp = await client.get("/jobs", params={"cursor": "not-a-uuid"})
        assert resp.status_code == 400
        assert "Invalid cursor" in resp.json()["detail"]

    async def test_search_with_valid_cursor_paginates(self, client: AsyncClient) -> None:
        for i in range(3):
            await client.post("/jobs", json=_payload(str(i)))
        first = await client.get("/jobs", params={"limit": 2})
        assert first.status_code == 200
        cursor = first.json()["next_cursor"]
        assert cursor is not None
        second = await client.get("/jobs", params={"limit": 2, "cursor": cursor})
        assert second.status_code == 200
        assert len(second.json()["items"]) == 1

    async def test_batch_read_over_100_ids_returns_422(self, client: AsyncClient) -> None:
        ids = "&".join(f"ids={uuid.uuid4()}" for _ in range(101))
        resp = await client.get(f"/jobs/batch?{ids}")
        assert resp.status_code == 422

    async def test_update_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.patch(f"/jobs/{uuid.uuid4()}", json={"detail": "x"})
        assert resp.status_code == 404

    async def test_delete_missing_returns_404(self, client: AsyncClient) -> None:
        resp = await client.delete(f"/jobs/{uuid.uuid4()}")
        assert resp.status_code == 404

    async def test_batch_write_missing_id_returns_404(self, client: AsyncClient) -> None:
        batch = {
            "operations": [
                {"op": "delete", "id": str(uuid.uuid4())},
            ]
        }
        resp = await client.post("/jobs/batch", json=batch)
        assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Permission / role-schema parity
# --------------------------------------------------------------------------- #


class TestJobPermissions:
    async def test_creator_permission_to_search_filter_admits_own(
        self, session: AsyncSession
    ) -> None:
        """CreatorPermission with Permitted on_match reduces to a filter that
        admits the creator's own rows and a NoneSearchFilter (deny) for others."""
        import uuid as _uuid

        from openhands.ev2.security.security_models import (
            Action,
            Permitted,
        )

        owner_user = await make_principal(session, email="jpo@example.com", username="jpo")
        perm = CreatorPermission(on_match=Permitted(), on_mismatch=Denied(), on_create=Permitted())
        # READ reduces to the creator-match scope for the owner.
        filt = perm.to_search_filter(owner_user.id, Action.READ)
        # An own row matches; another principal's row does not.
        own = type("J", (), {"creator_id": owner_user.id, "id": _uuid.uuid4()})()
        other = type("J", (), {"creator_id": _uuid.uuid4(), "id": _uuid.uuid4()})()
        assert filt.matches(own) is True
        assert filt.matches(other) is False

    async def test_job_permission_column_exists(self, session: AsyncSession) -> None:
        """The migration added the job_permission JSONB column to roles."""
        col = await session.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'roles' AND column_name = 'job_permission'"
            )
        )
        assert col.scalar_one() == "job_permission"

    async def test_job_permission_round_trips_through_role(self, session: AsyncSession) -> None:
        """A role with job_permission persists and reloads the discriminated union."""
        from openhands.ev2.role.role_models import Role
        from openhands.ev2.security.security_models import Permitted

        user = await make_principal(session, email="jrt@example.com", username="jrt")
        await assign_role(
            session, user.id, {"job_permission": CreatorPermission(on_match=Permitted())}
        )
        await session.flush()
        from sqlalchemy import select

        role = (
            await session.execute(select(Role).where(Role.job_permission.is_not(None)))
        ).scalar_one()
        assert isinstance(role.job_permission, CreatorPermission)
        assert isinstance(role.job_permission.on_match, type(Permitted()))
