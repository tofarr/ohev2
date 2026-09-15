---
name: testing
description: Hermetic test conventions — embedded PostgreSQL, savepoint transaction isolation, timestamp rules, and coverage requirements. Load before writing or modifying tests.
version: "1.0.0"
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
