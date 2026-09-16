---
name: testing
description: Hermetic test conventions — embedded PostgreSQL, savepoint transaction isolation, timestamp rules, coverage requirements, and how to run tests efficiently (token/output discipline). Load before writing or modifying tests, and before running the suite.
version: "1.1.0"
---

# Testing

* Unit tests use fixtures and an **embedded PostgreSQL** server (pytest-postgresql),
  never a shared/long-lived DB. Tests must be hermetic and parallelizable.
  A single PG process is started per session; one database is created per xdist
  worker. The schema is built once into the worker DB. Per-test isolation uses
  **savepoint transactions** (not per-test `CREATE DATABASE`): the `engine`
  fixture begins an outer transaction on a fresh connection, and all DB access
  (the `session` fixture, the `app` dependency override, and the module-level
  `get_session_factory()` used by middleware) goes through the same connection
  via `join_transaction_mode="create_savepoint"`. `session.commit()` only
  releases a savepoint — data is visible within the test but rolled back after
  it. The engine uses `NullPool` so connections are never shared across event
  loops.
* `created_at` / `updated_at` columns use `server_default=func.clock_timestamp()`
  (not `func.now()`). `clock_timestamp()` returns the actual wall-clock time per
  statement, not the transaction start time, so rows created in the same
  savepoint transaction get distinct timestamps. This is required for tests that
  filter or sort by `created_at`.
* Test public behavior, not implementation details. Avoid mocks where a real
  dependency (DB, httpx transport) can be used in-process.
* Every public service function needs at least one happy-path and one error-path test.
* E2E tests (Playwright) live in `tests/e2e/` and assert user-visible flows.

## Running tests — output discipline

The default `pytest` invocation (and `pyproject.toml`'s `addopts`) runs **xdist
in parallel** with no coverage gate, which is fast but chatty: the app wires a
JSON stream handler onto the root logger at import time, and SQLAlchemy emits
one INFO line *per mapped column* when mappers configure. That flood is
suppressed at the source by importing the JSON logging setup **before** any
ORM/router import in `app.py` (see `util/logger.py`); if you add a new entry
point that imports models, keep logging configured first or the flood returns.

Even with the flood suppressed, a full-suite xdist run is verbose. For agent
contexts, redirect output to a file and read only the result:

```
uv run python -m pytest tests/unit/ > /tmp/test.log 2>&1
echo "exit $?"
tail -3 /tmp/test.log          # result line + any failures
```

### Iteration: scope to what changed

A full suite run is expensive. For fast feedback during iteration, scope to the
touched files instead of re-running everything:

* `make test-fast ARGS=tests/unit/test_user_service.py` — single-process,
  testmon-scoped, stops on first failure (the Makefile calls this the
  "minimal-token loop").
* `make test-affected` — only tests whose lines the current diff touches.
* `make test-fast ARGS="-k create"` — keyword-filter within a path.

Run the full suite (and the 94% coverage gate via `make test`) **once**, at the
end, before opening the PR — not on every edit.

### Embedded PostgreSQL needs `pg_config` on PATH

The `pytest-postgresql` session fixture shells out to `pg_config` to locate the
server binaries. If `pg_config` is missing from `PATH`, **every** DB-backed test
errors at setup with
`pytest_postgresql.exceptions.ExecutableMissingException: Could not find
pg_config executable` — a wall of identical tracebacks. This is an environment
problem (install `postgresql` / `postgresql-client`, or fix `PATH`), not a test
or code defect: fix the environment once rather than chasing the errors.

Under `-n 0` (single-process, used by `make test` for deterministic coverage)
the embedded server runs in-session; under `-n auto` (xdist, the default) one
server is shared but each worker needs the same `pg_config` on `PATH`.
