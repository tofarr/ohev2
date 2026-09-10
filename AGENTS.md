# AGENTS.md — rules for agents and contributors working in `openhands.ev2`

This file is the persistent memory for this repository. Agents (human or AI) must
follow these rules when producing or reviewing code. Rules are grouped by topic.

## 1. Stack & tooling

* Python â‰¥ 3.11, asyncio-first. Never use blocking I/O on the request path.
* Manage dependencies with `uv`. Never hand-edit `uv.lock`; use `uv add/remove/sync`.
* FastAPI for HTTP. Pydantic v2 for all request/response schemas.
* SQLAlchemy 2 async ORM + asyncpg. Alembic for migrations.
* OpenHands SDK + Agent Server for agent execution.
* Quint for formal specs; every behavioral change to a resource must be reflected in
  `specs/` and verified with `quint typecheck` / `quint test`.

## 2. Code quality gates (enforced in CI)

* `ruff check .` and `ruff format --check .` clean.
* `mypy --strict` clean (no `Any` without explicit `# type: ignore` + reason).
* Unit coverage >= 94%. New code without tests blocks merge.
* Quint specs compile and pass.
* Playwright e2e suite green. The full suite runs daily and also on every PR
  (see `.github/workflows/e2e-daily.yml` and the `e2e` job in
  `.github/workflows/ci.yml`).

If a change can't meet a gate, flag it explicitly rather than silently bypassing it.

### 2.1 Pre-PR verification — run locally before opening a PR

Do not push a branch and rely on CI to catch failures. Run these commands
locally and ensure they are green *before* opening (or updating) a pull request:

1. **lint-type-coverage** (mirrors the `lint-type-coverage` CI job):
   ```
   uv run ruff check .
   uv run ruff format --check .
   uv run mypy
   uv run pylint src/openhands/ev2
   make test
   ```
   `make test` runs the full suite with coverage and the 94% gate (xdist
   disabled for deterministic coverage attribution). For fast iteration
   *before* this gate, use `make test-fast ARGS=<path>` (no coverage,
   testmon-scoped, stops on first failure) or `make test-affected` (only
   tests touched by the current diff). A bare `uv run pytest` also runs
   coverage-free and parallelized via xdist, but does not stop early or
   scope to the diff.
   `pylint` runs the McCabe cyclomatic complexity check (threshold 5);
   it must pass — overly complex functions must be refactored.
2. **e2e** (mirrors the `e2e` CI job; requires Docker for the service stack):
   ```
   uv run playwright install --with-deps chromium
   docker compose up -d
   OHE_DB_CONFIG_HOST=localhost OHE_DB_CONFIG_PORT=5432 OHE_DB_CONFIG_DB_NAME=ohev \
   OHE_DB_CONFIG_USERNAME=ohev OHE_DB_CONFIG_PASSWORD=ohev uv run alembic upgrade head
   uv run pytest tests/e2e -q --no-cov
   docker compose down
   ```
3. **specs** (only when behavior changed, per §7):
   ```
   quint typecheck specs/*.qnt
   quint test specs/<spec>.qnt --main=<spec>
   ```

If any step fails, fix it before opening the PR — do not open the PR and
address CI failures reactively. If the environment cannot run a step (e.g.
Docker unavailable), say so explicitly in the PR description rather than
skipping it silently.

## 3. REST API consistency

The REST surface must be uniform. These rules are non-negotiable:

* Collection retrieval is **always** `GET /{resource}` (paginated via `?cursor=&limit=`).
  Never invent `/list`, `/search`, `/all`, `/get` action paths for listing.
* Search is expressed as query params on the collection (`GET /{resource}?q=—¦`), never
  a separate `/search` route.
* Standard verbs only: `GET` (list/retrieve), `POST` (create/action), `PATCH`
  (partial update), `DELETE` (remove). Avoid `PUT` unless full-replace semantics are
  genuinely required and documented.
* Resource-scoped actions use `POST /{resource}/{id}/{action}`.
* Nested resources: `/{parent}/{id}/{child}`.
* Resource names are plural lowercase nouns (`/conversations`, `/sandboxes`).
* Every response is a documented Pydantic schema; no ad-hic dicts.
* Error responses use a single `ProblemDetail` shape (RFC 9457) everywhere.
* Pagination, sorting, and filtering query keys are identical across resources.
* Every CRUD resource exposes both batch endpoints alongside its single-item
  CRUD:
  - Batch read: `GET /{resource}/batch?ids=<uuid>&ids=<uuid>...` returns the
    resources positionally aligned with the requested ids (`null` for
    missing/out-of-scope), capped at 100 ids.
  - Batch write: `POST /{resource}/batch` accepts a list of operations, each a
    create, update, or delete against the same resource, applied in a single
    transaction. Updates target a specific id; deletes target a specific id;
    creates carry the same payload as `POST /{resource}`.
  Batch writes must: (a) authorize each operation against its own action
  (`CREATE`/`UPDATE`/`DELETE`) using the principal's effective permission
  filter, denying the whole batch if any operation is out of scope; (b) commit
  exactly once at the end so a failure of any operation rolls back the entire
  batch (atomic, no partial application); (c) accept a mix of create/update/
  delete in one request. Resources without an update (e.g. immutable link
  tables) omit the `update` op rather than inventing one. The batch response is
  positionally aligned with the operations: the i-th entry is the resulting
  `Read` for a create/update or `null` for a delete.

When reviewing: if two resources use different verbs/names for the same operation,
reject the change. If a CRUD resource ships without its batch read/write
endpoints, reject the change unless the resource is documented as non-CRUD.

## 4. Code structure — reusable & testable

* Methods are short and single-purpose. If a method exceeds ~40 lines or does more
  than one thing, split it into named, individually testable helpers.
* Prefer pure functions for logic; isolate I/O at the edges.
* No business logic in route handlers — handlers validate, call a service, and
  serialize. Services contain logic; repositories contain data access.
* Layering: `routers â†' services â†' repositories â†' models`. Do not skip layers (a router
  must not query the DB directly).
* Shared behavior goes in a common module; do not copy-paste across resources.
  Layering is enforced by import direction, not folder hierarchy.

### File & directory layout

* One flat directory per feature, directly under `src/openhands/ev2/` (e.g. `user/`,
  `security/`). No `models/`/`routes/`/`services/` subfolders.
* Files inside a feature directory are flat and prefixed with the feature name for
  global uniqueness: `user_models.py`, `user_schemas.py`, `user_router.py`,
  `user_service.py`.
* No `__init__.py` unless it performs real package-level work. Default to namespace
  packages — convention over configuration.
* Genuinely shared, cross-cutting code lives in `src/openhands/ev2/util/`, outside the
  per-feature pattern.

## 5. Testing

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

## 6. Comments

* Concise but explicit. Describe only what is not obvious from reading the code.
* Do not restate the code, narrate changes, or describe nearby behavior.
* Valid uses: non-obvious invariants, workarounds, subtle ordering/locking, deliberate
  trade-offs.
* Docstrings: one-line summary for trivial functions; summary + args/returns only when
  types don't make it obvious.

### 6.1 No `__all__` exports lists

Do not add `__all__` to modules. The codebase uses no wildcard imports
(`from x import *`), so an explicit exports list is pure repetition of the
names already defined at module scope. Keep the public API implicit: every
non-underscore-prefixed name is importable, and consumers import the names
they need directly. A `__all__` that merely re-lists the module's public
symbols adds maintenance burden (easy to drift out of sync) without value.

## 7. Formal specs (Quint)

* Every resource/state machine has a `.qnt` spec in `specs/`.
* Invariants (auth, ownership, sandbox lifecycle) are expressed and checked.
* When changing behavior, update the spec first, then implement, then run
  `quint test`.

## 8. Sandboxes

* Sandbox operations go through the `SandboxProvider` interface only.
* A new backend implements the interface and registers via config — no scattering of
  backend-specific calls in services.
* Both ephemeral and persistent sandboxes are supported via the same interface.
* `Sandbox` carries a nullable `last_accessed_at`. The Docker backend derives it
  from the container's agent-server root endpoint (`GET /` → JSON `idle_time`):
  `last_accessed_at = now - idle_time`. Best-effort — `null` when the sandbox is
  not `active`, unreachable, or the payload lacks `idle_time`.
* A background lifecycle sweep enforces the per-template lifespan knobs
  (`idle_pause_seconds`, `paused_delete_seconds`, `max_age_seconds`). The sweep
  runs as an in-process `asyncio` loop started by the sandbox service's
  `__aenter__` (tied to the app lifespan), following the same `= 0` disables /
  external-scheduler-fallback convention as the LLM/MCP usage loops (config:
  `sandbox_lifecycle_interval`). Pause stamps an `io.openhands.sandbox.paused_at`
  container label so the paused-since time survives restarts; resume clears it.

## 9. Auth

* Password hashing via bcrypt (`util.password`). Never log or serialize password hashes.
* Signed cookies for sessions; OAuth flows for federated identity.
* Federated OAuth lives in `auth/`. The project is an OAuth provider to
  first-party clients and an OAuth client to an external IdP. Required config:
  `idp.url`, `idp.client_id`, `idp.client_secret`,
  `idp.expire_drift_tolerance`. Optional OIDC claim overrides:
  `idp.user_id_field`, `idp.email_field`, `idp.role_field`. Roles are NOT
  pulled from scopes.
* IdP refresh tokens are stored encrypted (`encryption_service`) in
  `idp_refresh_tokens`; the IdP access token is stored encrypted in its own
  `idp_access_tokens` table, joined to the refresh row by
  `refresh_token_id`. Both expiries are synced to the IdP response (with the
  drift tolerance subtracted). The IdP access token is never exposed to
  clients - a short-lived local JWE is minted instead. The session cookie
  (cookie flow) carries the access row id + expiry so the auth dependency
  can detect imminent expiry and trigger a server-side refresh.
* Refresh of an IdP token is gated by `SELECT ... FOR UPDATE` with
  `SET LOCAL lock_timeout` (config: `idp_refresh_lock_timeout_seconds`) so
  multiple processes do not refresh the same token at once. On lock timeout
  the cookie path keeps the existing cookie; the explicit `/auth/refresh`
  endpoint returns 409. After acquiring the lock the access row is
  re-checked: if its expiry is now in the future another process already
  refreshed it and the IdP call is skipped.
* Background cleanup of expired IdP refresh tokens: `cleanup_interval` (non-zero)
  runs an in-process `asyncio` loop in the app lifespan; `cleanup_interval = 0`
  disables it and cleanup must be driven by an external scheduler (cron). See
  README "Cleanup processes".
* Background LLM usage management — two more lifespan loops follow the same
  pattern (config `= 0` disables the in-process loop, falling back to an
  external scheduler). See README "LLM usage logging":
  - `llm.usage.partition_interval` (`OHE_LLM_USAGE_PARTITION_INTERVAL`):
    preallocates `llm.usage.preallocate_days` future daily `llm_usage`
    partitions and drops ones older than `llm.usage.retention_days`.
  - `llm.usage.aggregate_interval` (`OHE_LLM_USAGE_AGGREGATE_INTERVAL`):
    rolls finished minutes (at least one behind wall-clock) from `llm_usage`
    into the read-only `llm_aggregated_usage` projection.
* Background MCP usage management — two lifespan loops with the same shape
  and the same `= 0` disables-in-process semantics, configured under
  `mcp.usage` (env `OHE_MCP_USAGE_*`). See README "MCP usage logging":
  - `mcp.usage.partition_interval` (`OHE_MCP_USAGE_PARTITION_INTERVAL`):
    preallocates `mcp.usage.preallocate_days` future daily `mcp_usage`
    partitions and drops ones older than `mcp.usage.retention_days`.
  - `mcp.usage.aggregate_interval` (`OHE_MCP_USAGE_AGGREGATE_INTERVAL`):
    rolls finished minutes (at least one behind wall-clock) from `mcp_usage`
    into the read-only `mcp_aggregated_usage` projection (per-user
    `total_duration_ms` sums + `invocations` counts, gated by
    `mcp_aggregated_usage_permission`).
* Authorization checks live in services (not just routers) — defense in depth.
* **Every route is protected by an auth dependency.** Each registered API route
  must transitively depend on a protecting dependency from `auth_dependencies`
  — `depends_access_token`, `depends_user_id`, `depends_role_ids`,
  `depends_permissions`, or `depends_permissions_or_none`. A route that has
  none of these is anonymous and must be added to
  `PERMISSION_DEPENDENCY_OVERRIDES` in
  `tests/unit/test_route_permissions.py`, with a comment explaining why the
  standard auth dependency does not apply. The override set is audited in
  review and the test fails if an override no longer matches a registered
  route (so stale exemptions are caught). The invariant is mirrored in
  `specs/rest.qnt` (`allRoutesProtected`). Genuinely public routes are few:
  `/health`, OIDC discovery (`.well-known/*`), the OAuth2 flow entry points
  that mint/revoke credentials (`/auth/authorize`, `/auth/callback`,
  `/auth/token`, `/auth/refresh`, `/auth/revoke`, `/auth/logout`), the built-in
  dev IdP (`/auth/dev/*`). The LLM completion forwarder
  (`/llm/completion/{llm_id}/{path}`) and the MCP JSON-RPC proxy
  (`POST|GET|DELETE /mcp/{config_id}`) are **not** exempted: they authenticate
  the caller through the standard permission dependencies (`USE` on the stored
  LLM / MCP server config) and inject the stored upstream provider/MCP
  credential internally — the caller never presents the provider key.

## 11. Roles & per-entity permission columns

* A `Role` (`role/role_models.py`) bundles one explicit `Permission` JSONB
  column **per governed entity** (e.g. `user_permission`, `role_permission`,
  `user_role_permission`, `api_key_permission`, `oauth_client_permission`,
  `cors_origin_permission`). A `NULL` column means "deny" for that entity.
  There is **no** `policies` map and **no** legacy `role_permission`/
  `user_permission` fallback: every governed entity is its own column.
* The canonical list of entity columns is `ROLE_ENTITY_COLUMNS` in
  `role/role_models.py` — each entry is the full column name
  (``<entity>_permission``). Adding a governed entity is a four-step change:
  1. append the ``<entity>_permission`` column name to `ROLE_ENTITY_COLUMNS`;
  2. add the matching column to `Role` (and to the initial migration
     `0001_initial.py`, since the schema is not yet published);
  3. register the resource's ORM model against the column name in
     `auth_dependencies.register_resource_policy(model, "<entity>_permission")`.
  4. add the field to `RoleCreate`/`RoleUpdate`/`RoleRead` in
     `role/role_schemas.py`.
  `register_resource_policy` validates the column is in
  `ROLE_ENTITY_COLUMNS` and raises at import time if not, so a mismatched
  registration fails fast. `RoleService.create`/`update` copy every column in
  `ROLE_ENTITY_COLUMNS` generically, so schemas must stay in sync —
  `tests/unit/test_role_service.py::TestEntityColumnParity` guards all four
  steps (column, model, registry, schemas, service round-trip). A column
  missing from the schemas can never be granted via the API — silently
  denying the entity to everyone except seeds.
* `Role` and `UserRole` live in `role/role_models.py`, **not** in
  `security_models.py`. `security_models.py` only defines the policy types
  (`Permission` and subclasses) and the `PermissionType` JSONB column type.
* The role-to-user link table is `user_roles` (model `UserRole`), plural
  noun-first naming per §3. A user may have multiple roles; there is no
  single `role` column on `User`.
* `seed_db.py` (run via `uv run python -m openhands.ev2.scripts.seed_db`)
  seeds two roles: an `admin` role granting `Permitted()` on every column in
  `ROLE_ENTITY_COLUMNS` (so re-running after adding a new entity backfills the
  missing grant automatically), and a `user` role granting `ApiKeyAccess` on
  `api_key_permission` so a non-admin user can manage their own API keys. It
  also upserts an admin user and (by default) a regular user account.

### 11.1 Link tables are first-class governed resources

Privilege-escalation holes repeatedly come from guarding a link table by the
permission of one of its endpoints. **Every link/join table gets its own
entity column and is authorized through it — never through a parent's
column.**

* `user_roles` → `user_role_permission`: deciding who *holds* a role is not
  implied by `role_permission` (a role-metadata admin must not be able to
  self-assign an admin role — self-service privilege escalation).
* Routers for link tables guard with `depends_permissions(<LinkModel>,
  Action.*)` and pass the resolved filter to the service; the service scopes
  reads via `perm_filter.filter_sql(...)` and rejects out-of-scope creates
  with a scope error (403) — same pattern as the primary resources.
* Auditing rule of thumb: for every endpoint, name the *entity* it mutates
  and confirm the guard checks that entity's column. If the guard checks a
  different entity's column, ask whether that coupling lets a principal gain
  access they were not explicitly granted.

> **Note:** The per-item ACL link tables (`role_secret_permissions`,
> `user_secret_permissions`, `role_mcp_server_config_permissions`,
> `role_sandbox_template_permissions`) and their grant-permission columns
> (`secret_grant_permission`, `mcp_server_config_grant_permission`,
> `sandbox_template_grant_permission`) have been removed. Item-level access
> control is now expressed via the generic `AclPermission` policy stored in
> the role's per-entity JSONB column (e.g. `secret_permission`), which
> enumerates permitted item ids per action. See §12 for the typed-secrets
> projection that still uses `secret_value_permission` for value reveal.

## 10. Review checklist (for agents reviewing PRs)

- [ ] REST verbs/names consistent with §3.
- [ ] No layering violations (§4).
- [ ] Methods short, single-purpose (§4).
- [ ] New code has tests; coverage gate green (§2, §5).
- [ ] ruff + mypy strict clean (§2).
- [ ] e2e suite green locally (§2.1).
- [ ] Spec updated and passing if behavior changed (§7).
- [ ] No secrets/hardcoded credentials (§9).
- [ ] New governed entity: column added to `Role` + `ROLE_ENTITY_COLUMNS` (full `<entity>_permission` name) + migration + registered in `auth_dependencies` + field added to `RoleCreate`/`RoleUpdate`/`RoleRead` (§11; `TestEntityColumnParity` enforces).
- [ ] Link tables guarded by their own entity column, not a parent's (§11.1); every endpoint's guard names the entity it actually mutates.
- [ ] Every router passes the resolved permission filter to its service, and the service scopes SQL with it (§9).
- [ ] Every new route is protected by an auth dependency, or listed (with comment) in `PERMISSION_DEPENDENCY_OVERRIDES` (§9; `test_route_permissions.py` enforces).
- [ ] Comments follow §6.

## 12. Typed secrets & the value-reveal projection

Secrets are typed: the umbrella `secrets` table carries a `type`
discriminator (`SecretType` enum: `static` | `oauth`) and delegates the
sensitive payload to a type-specific detail table. `static_secret_details`
holds the JWE ciphertext for `type='static'` secrets (1:1 with `secrets`,
`ON DELETE CASCADE`). Future `oauth_*` detail tables will hold
access/refresh tokens; only the `OAUTH` enum value exists today so the
type column is forward-compatible (OAuth refresh logic is explicitly out
of scope until those tables land).

### 12.1 Value reveal is a separate projection

The typed secret tables (`secrets`, `static_secret_details`, …) **never**
expose their sensitive values through their own CRUD endpoints. `SecretRead`
omits `value` entirely; `/secrets` returns metadata only.

Decrypted plaintext is revealed solely through the **`/secret-values`**
projection, a read-only umbrella surface (`GET /secret-values`,
`GET /secret-values/batch`, `GET /secret-values/{id}`) backed by
`SecretValueService`. A secret is revealed only when the principal has
**both**:

1. read access to the secret (the `secret_permission` filter — same grant
   logic as `/secrets`), **and**
2. the value-reveal permission (`secret_value_permission`).

`SecretValueService` ANDs the two filters (`AndSearchFilter(filters=[read,
value])`); either being `None`/denying yields 404 (fail-closed — a 404, not
a 403, so existence is not leaked). The Quint spec mirrors this in
`canRevealValue` / `valueRevealRequiresBothPerms` (`specs/secret.qnt`).

### 12.2 `secret_value_permission` is the documented registry exception

`secret_value_permission` is a real entity column in `ROLE_ENTITY_COLUMNS`
(and `Role`, the migration, and `RoleCreate`/`RoleUpdate`/`RoleRead`), so
the admin seed role automatically receives `Permitted()` on it and
`RoleService.create`/`update` copy it generically like every other column.

It is **intentionally NOT registered** via
`register_resource_policy(Secret, "secret_value_permission")`. The
`_RESOURCE_POLICY` registry maps a model type to exactly one column, and
`Secret` is already mapped to `secret_permission`. `secret_value_permission`
governs a cross-type *projection* (`/secret-values`), not a table, so it is
resolved **by column name** via
`resolve_permission_filter_for_column("secret_value_permission", Action.READ,
…)` and the `depends_secret_value_permission()` FastAPI dependency (which
raises 403 when the resolved filter is `None`).

`tests/unit/test_role_service.py::TestEntityColumnParity::test_model_and_registry_cover_every_entity_column`
subtracts a documented `non_registered = {"secret_value_permission"}` set
from the equality assertion and asserts `depends_secret_value_permission`
is callable, so the column cannot be silently ungoverned. This is the only
documented exception to the "every entity column is registered 1:1" rule in
§11; do not add more without updating that test and this section.

### 12.3 OAuth forward-compat

`SecretCreate` rejects `value` when `type == oauth` (model validator) and
requires it when `type == static`. `SecretService.update` raises
`SecretValueTypeError` (→ 422) if a `value` is supplied for an oauth
secret. `SecretValueService` raises `SecretValueNotFoundError` (→ 404) for
an oauth secret with no detail table yet. When OAuth detail tables are
added, the only schema change needed is a new detail table + a branch in
`SecretValueService._decrypt_value` — the type column and projection
surface already exist.
