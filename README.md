# OpenHands Enterprise v2 (openhands.ev2)

A greenfield reimagining of OpenHands Enterprise — written from scratch, unencumbered
by previous expectations, and built to be formally specified, heavily tested, and
consistently structured.

> Status: scaffolding. APIs, data models, and sandboxes are being specified in Quint
> before implementation. See [`specs/`](./specs) and [`docs/`](./docs).

## Goals

* Recreate the core enterprise capabilities of OpenHands (auth, conversations, agent
  execution, sandboxes, MCP tool proxying) on a clean, consistent foundation.
* Specify behavior formally with [Quint](https://github.com/informalsystems/quint)
  so invariants are machine-checkable.
* Enforce quality with ruff, mypy (strict), and ≥ 90% unit-test coverage.
* Provide a single, consistent REST surface with uniform resource naming.
* Keep sandboxes pluggable (Docker, Kubernetes, E2B, …) for both short-lived and
  long-lived runtimes.

## Tech stack

| Concern | Choice |
| --- | --- |
| Language | Python ≥ 3.11, `asyncio`-first |
| Dependency mgmt | [`uv`](https://docs.astral.sh/uv/) |
| Web framework | FastAPI |
| Database | PostgreSQL (async via asyncpg / SQLAlchemy 2 async) |
| Agent runtime | OpenHands SDK + Agent Server |
| Auth | Federated OAuth/OIDC + signed cookies |
| Sandbox | Pluggable: Docker, Kubernetes, E2B |
| Tool proxy | Pluggable MCP tools / REST proxy |
| Formal spec | Quint |
| Lint / types | ruff, mypy (strict) |
| Unit tests | pytest + pytest-asyncio + embedded Postgres fixtures |
| E2E tests | Playwright (runs at least daily) |
| Deploy | docker-compose or Kubernetes |

## Project layout

```
src/openhands/ev2/            Application source (importable as `openhands.ev2`)
specs/               Quint formal specifications
docs/                Architecture and decision records
tests/unit/          Unit tests (≥ 90% coverage enforced)
tests/e2e/           Playwright end-to-end tests
.github/workflows/   CI: lint, typecheck, coverage, spec checks, e2e
```

## REST consistency rules

All resources follow identical patterns. The verb used for collection retrieval is
uniform across the API — there is no mixing of `/list`, `/search`, `/all`, etc.

* `GET    /{resource}`           — list collection (paginated)
* `POST   /{resource}`           — create
* `GET    /{resource}/{id}`      — retrieve one
* `PATCH  /{resource}/{id}`      — partial update
* `DELETE /{resource}/{id}`      — remove
* `POST   /{resource}/{id}/{action}` — resource-scoped action

Nested collections mirror the parent: `GET /{parent}/{id}/{child}`. Query endpoints
that perform search do so via `GET /{resource}?q=…` rather than a bespoke path.

### Batch endpoints

Every CRUD resource also exposes batch read and write endpoints alongside its
single-item CRUD:

* `GET /{resource}/batch?ids=<uuid>&ids=<uuid>...` — batch read. Returns the
  resources positionally aligned with the requested ids (`null` for missing or
  out-of-scope items). Capped at 100 ids.
* `POST /{resource}/batch` — batch write. Accepts a list of operations, each a
  create, update, or delete against the same resource, applied in a single
  transaction.

Batch writes authorize each operation against its own action (`CREATE` /
`UPDATE` / `DELETE`) using the principal's effective permission filter and
deny the whole batch if any operation is out of scope. They commit exactly
once at the end, so a failure of any operation rolls back the entire batch
(atomic, no partial application). Updates target a specific id; deletes target
a specific id; creates carry the same payload as `POST /{resource}`. The
batch response is positionally aligned with the operations: the i-th entry is
the resulting `Read` for a create/update, or `null` for a delete. Resources
without an update (e.g. immutable link tables) omit the `update` op rather
than inventing one.

## Sandbox model

Sandboxes are first-class resources. A `SandboxProvider` interface is implemented by
Docker, Kubernetes, and E2B backends (initially Docker; others stubbed). Sandboxes
are either **ephemeral** (terminated with the request) or **persistent** (lifecycle
managed independently and addressable by id).

## Quality gates

* `ruff check .` and `ruff format --check .` must pass.
* `mypy --strict` must pass.
* Unit coverage ≥ 90% (`--cov-fail-under=90`).
* Quint specs compile (`quint typecheck`) and tests pass (`quint test`).
* Playwright e2e suite runs daily in CI.

## Agent & contributor guidance

See [`AGENTS.md`](./AGENTS.md) for the rules agents and contributors must follow when
working in this repository. The rules cover REST consistency, reusable/testable code,
and comment style.

## Setup

```bash
uv sync --all-extras
uv run playwright install --with-deps chromium
uv run alembic upgrade head
uv run uvicorn openhands.ev2.app:app --reload
```

### Local database (development)

Configuration is loaded from environment variables with the `OHE` prefix
(see `.env.example`). The database connection is configured via the
structured `db_config` fields rather than a single connection string:

| Field | Env var | Default | Purpose |
| --- | --- | --- | --- |
| `db_config.host` | `OHE_DB_CONFIG_HOST` | `localhost` | Database host |
| `db_config.port` | `OHE_DB_CONFIG_PORT` | `5432` | Database port |
| `db_config.db_name` | `OHE_DB_CONFIG_DB_NAME` | `ohe` | Database name |
| `db_config.username` | `OHE_DB_CONFIG_USERNAME` | `ohe` | Database username |
| `db_config.password` | `OHE_DB_CONFIG_PASSWORD` | `ohe` | Database password |

To start a local PostgreSQL instance for development, run (with the same
values you set in your `.env` / environment):

```bash
docker run --name ohe-postgres \
    -e POSTGRES_PASSWORD=$OHE_DB_CONFIG_PASSWORD \
    -e POSTGRES_USER=$OHE_DB_CONFIG_USERNAME \
    -e POSTGRES_DB=$OHE_DB_CONFIG_DB_NAME \
    -p ${OHE_DB_CONFIG_PORT}:5432 \
    -d postgres
```

Then apply migrations:

```bash
uv run alembic upgrade head
```

Seed an admin user (credentials default from `OHE_SEED_ADMIN_*` env vars, or dev
defaults). Idempotent — re-running upserts the user and ensures the `admin` role
grants unrestricted access to every resource type. Also seeds a `user` role
(granting `ApiKeyAccess` on `api_key_permission` so a regular user can manage
their own API keys) and, by default, a regular user account
(`OHE_SEED_USER_*` env vars):

```bash
uv run python -m openhands.ev2.scripts.seed_db
```

Start the app with:

```bash
uv run uvicorn openhands.ev2.app:app --reload
```

## Federated authentication

The `auth` module is the sole authentication layer — a federated OAuth/OIDC
flow in which the project acts as an OAuth **provider** to first-party clients
and as an OAuth **client** to an external identity provider (IdP). API-key and
refresh-token credentials live in the same `auth` package.

Required configuration (environment variables, `OHE` prefix):

| Field | Env var | Purpose |
| --- | --- | --- |
| `idp.url` | `OHE_IDP_URL` | Base URL of the identity provider |
| `idp.client_id` | `OHE_IDP_CLIENT_ID` | Client id registered at the IdP |
| `idp.client_secret` | `OHE_IDP_CLIENT_SECRET` | Client secret registered at the IdP |
| `idp.expire_drift_tolerance` | `OHE_IDP_EXPIRE_DRIFT_TOLERANCE` | Seconds subtracted from IdP `expires_in`/`expires_at` to avoid drift bugs |

Optional OIDC claim overrides: `idp.user_id_field`, `idp.email_field`,
`idp.role_field` (default to the standard `sub`, `email`, and a reserved
role claim). Role→permission mapping is deferred; roles are not pulled from
scopes.

Flow: `GET /auth/authorize` redirects to the IdP (with PKCE), `GET
/auth/callback` exchanges the code and, for `response_type=cookie`, mints a
session cookie (the `code` response type mints an exchangeable code instead),
`POST /auth/token` and `POST /auth/refresh` exchange codes / refresh tokens
for token pairs. OAuth clients are managed via `/auth-clients` (CRUD with
wildcard redirect-URI matching). The IdP `id_token` (or the decoded
refresh-token JWT) supplies the `sub`/email used for JIT user provisioning
(`users.idp_user_id`).

## CORS (cross-origin)

Cross-origin access is governed by a **global**, DB-backed allow-list managed
via `/cors-origins` (CRUD, permission-gated by the `cors_origin` resource
type). The allow-list is **not** tied to an OAuth client — it is a
deployment-level concern. A middleware reads the list (cached, invalidated on
mutation) and, for a permitted request `Origin`, sets
`Access-Control-Allow-Origin` to that exact origin (never `*`) plus
`Access-Control-Allow-Credentials: true`, and answers preflight `OPTIONS`
requests. Disallowed origins receive no CORS headers, so the browser blocks
the cross-origin read.

This is CORS access control (which cross-origin JavaScript may read
responses), not an XSRF defense for cookies — that is handled by the
SameSite=strict session cookie.

## Cleanup processes

Expired IdP refresh tokens are pruned by a background sweep.

* `cleanup_interval` (`OHE_CLEANUP_INTERVAL`, default `300`): seconds between
  sweeps. **Non-zero** runs an `asyncio` loop inside the FastAPI lifespan —
  no external scheduler needed.
* `cleanup_interval = 0` **disables** the in-process loop; drive cleanup with
  an external cron job hitting the same `delete_expired_tokens` service
  function (or a future admin endpoint).
* `idp.delete_expired_seconds` (`OHE_IDP_DELETE_EXPIRED_SECONDS`, default
  `86400`): rows whose `expires_at` is older than this window are deleted.
  `0` deletes any already-expired row regardless of age.

## LLM usage logging

Every LLM completion is recorded to a daily-partitioned `llm_usage` table
(raw, append-only, **not** exposed over REST). Usage queries go through the
`llm_aggregated_usage` projection — per-minute, per-user rollups exposed
read-only at `GET /llm/aggregated-usage` (paginated), `GET /llm/aggregated-usage/{id}`,
`GET /llm/aggregated-usage/batch?ids=…`, and `GET /llm/aggregated-usage/count`.
Access is gated by the `llm_aggregated_usage_permission` role column.

Two background sweeps (same lifespan pattern as the IdP cleanup above) keep
the projection usable:

* **Partition manager** — preallocates `preallocate_days` future daily
  `llm_usage` partitions and drops partitions older than `retention_days`.
  * `llm.usage.partition_interval` (`OHE_LLM_USAGE_PARTITION_INTERVAL`, default
    `300`): seconds between sweeps. **Non-zero** runs an `asyncio` loop in the
    FastAPI lifespan.
  * `llm.usage.partition_interval = 0` **disables** the in-process loop; drive
    partition management with an external scheduler calling
    `LlmUsageService.ensure_partitions`.
  * `llm.usage.preallocate_days` (`OHE_LLM_USAGE_PREALLOCATE_DAYS`, default
    `7`): how many future daily partitions to keep allocated ahead of time.
  * `llm.usage.retention_days` (`OHE_LLM_USAGE_RETENTION_DAYS`, default
    `365`): partitions whose day is older than this are dropped. `0` drops any
    day older than today.

* **Aggregator** — rolls finished minutes from `llm_usage` into
  `llm_aggregated_usage`, at least one minute behind wall-clock time so a
  minute is only rolled once it has finished receiving rows.
  * `llm.usage.aggregate_interval` (`OHE_LLM_USAGE_AGGREGATE_INTERVAL`, default
    `60`): seconds between sweeps. **Non-zero** runs an `asyncio` loop in the
    FastAPI lifespan.
  * `llm.usage.aggregate_interval = 0` **disables** the in-process loop; drive
    aggregation with an external scheduler calling
    `LlmUsageService.aggregate_behind_now`.

A `DEFAULT` partition is created by the initial migration so inserts never
fail before the manager's first sweep (or for out-of-range timestamps).
