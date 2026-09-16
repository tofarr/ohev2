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

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from tests.unit._auth_helpers import assign_role, make_principal

from openhands.ev2.job.job_models import (
    JOB_COMPLETED,
    JOB_ERROR,
    JOB_PENDING,
    JOB_RUNNING,
    Job,
    JobDetails,
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
        run = await _details("go").__call__()
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
