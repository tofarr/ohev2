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

Sandboxes are first-class resources. A `SandboxService` interface is implemented by
Docker, Kubernetes, and E2B backends (Docker and Kubernetes available; E2B stubbed).
Sandboxes are either **ephemeral** (terminated with the request) or **persistent**
(lifecycle managed independently and addressable by id).

The active backend is selected via `sandbox_service_class` (env
`OHE_SANDBOX_SERVICE_CLASS`):

* `openhands.ev2.sandbox.docker_sandbox_service.DockerSandboxService` (default) —
  templates are Docker images; sandboxes are containers.
* `openhands.ev2.sandbox.k8s_sandbox_service.K8sSandboxService` — templates are
  ConfigMaps carrying the image reference; sandboxes are Deployments (one pod, one
  container) backed by a PVC and a ClusterIP Service. Snapshots are unsupported.

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
uv sync --all-groups --all-extras   # dev group + dev extra (pytest) both needed; see Testing below
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
their own API keys), an `API key` role (deny-everything; the limited-access role
assigned to the system-minted session keys that sandbox configs carry — its name
is configurable via `sandbox_session_api_key_role` /
`OHE_SANDBOX_SESSION_API_KEY_ROLE`) and, by default, a regular user account
(`OHE_SEED_USER_*` env vars):

```bash
uv run python -m openhands.ev2.scripts.seed_db
```

Start the app with:

```bash
uv run uvicorn openhands.ev2.app:app --reload
```

## Testing

### Unit tests

Unit tests run against an **embedded PostgreSQL** server spawned per session by
the [`pytest-postgresql`](https://pytest-postgresql.readthedocs.io/) plugin
(`postgresql_proc` fixture in `tests/conftest.py`). The fixture resolves the
server binaries (`pg_ctl`, `initdb`, …) via `pg_config --bindir`, so a native
PostgreSQL install providing `pg_config` on your `PATH` is required to run the
unit suite. This is separate from the Docker-based dev database above — the
Docker container is for running the app; the unit tests manage their own
short-lived server process and do not use it.

Install PostgreSQL locally if you haven't already:

```bash
# macOS (Homebrew)
brew install postgresql            # unversioned — links pg_config onto PATH
# or, if a versioned keg-only formula is used:
#   brew install postgresql@17
#   brew link --force postgresql@17   # or export PATH="/opt/homebrew/opt/postgresql@17/bin:$PATH"

# Debian / Ubuntu
sudo apt-get install postgresql
```

Verify `pg_config` is resolvable, then run the suite:

```bash
which pg_config                    # must return a path
uv sync --all-groups --all-extras  # pytest lives in the [project.optional-dependencies] dev extra
uv run pytest                      # or: uv run pytest tests/unit -q
```

A coverage gate of 94% is enforced (`--cov-fail-under=94`).

### E2E tests

Playwright end-to-end tests live in `tests/e2e/` and exercise the app against
the Docker service stack. They require a running database (the Docker dev
database above, or `docker compose up -d`):

```bash
uv run playwright install --with-deps chromium
docker compose up -d
uv run pytest tests/e2e -q --no-cov
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

Expired **system API keys** (e.g. the session keys minted for sandbox
configs) are reaped by a second background sweep. User-minted keys are user
data and are never deleted automatically.

* `api_key_cleanup_interval` (`OHE_API_KEY_CLEANUP_INTERVAL`, default `300`):
  seconds between sweeps. **Non-zero** runs an `asyncio` loop inside the
  FastAPI lifespan — no external scheduler needed.
* `api_key_cleanup_interval = 0` **disables** the in-process loop; drive
  cleanup with an external cron job hitting the same
  `delete_expired_system_keys` service function.

## Proxy endpoints (LLM & MCP)

Both the LLM and MCP features expose a **raw forwarder** that lets an SDK
client route provider traffic through this service without ever holding the
upstream provider credential. The caller authenticates with its own
user-scoped credential (an API key, access token, or session cookie) via the
standard auth dependencies; the service resolves the stored upstream
credential and injects it. The provider/MCP key is **never** sent to the
caller.

### LLM completion forwarder

`POST /llm/completion/{llm_id}/{path}` (not in the OpenAPI schema) is a
provider-agnostic catch-all: the trailing `{path}` captures whatever resource
path the SDK/LiteLLM appended (`chat/completions`, `v1/messages`,
`responses`, …). The endpoint:

1. authenticates the caller via the standard permission dependency
   (`depends_permissions(StoredLLM, Action.USE)` + `depends_user_id`);
2. resolves the stored LLM and its provider connection;
3. decrypts the provider API key and injects it via the correct per-provider
   header — `Authorization: Bearer <key>` for OpenAI-style providers,
   `x-api-key` (+ forwarded `anthropic-version`) for Anthropic;
4. forwards the raw request body to `{connection.base_url}/{path}` and
   streams the response back (SSE or JSON);
5. records `llm_usage` best-effort for OpenAI-shaped responses.

When `enable_proxy` is set on a provider connection, `materialize_llm` hands
the SDK a `base_url` pointing at this forwarder and a **proxy credential**
(the caller's user-scoped token), not the provider key. The provider key is
resolved and injected only inside the forwarder.

### MCP JSON-RPC proxy

`POST|GET|DELETE /mcp/{config_id}` (not in the OpenAPI schema) is a streaming
JSON-RPC proxy for the MCP streamable-http transport. It:

1. authenticates the caller via `depends_permissions(MCPServerConfig,
   Action.USE)` + `depends_user_id`;
2. resolves the stored MCP server config and its encrypted upstream
   auth/headers;
3. injects the stored upstream credentials and forwards the JSON-RPC request,
   passing `mcp-session-id` / `mcp-protocol-version` headers both ways;
4. streams SSE responses back byte-for-byte (POST and GET), and terminates
   the upstream session on DELETE;
5. records `mcp_usage` best-effort for `tools/call` invocations (streaming
   and JSON).

When `enable_proxy` is set on an MCP server config, `materialize_mcp_server`
hands the SDK a `url` pointing at this proxy and a **proxy credential** (the
caller's user-scoped token), not the stored upstream auth/headers.

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

## MCP usage logging

Every proxied MCP `tools/call` invocation is recorded to a daily-partitioned
`mcp_usage` table (raw, append-only, **not** exposed over REST). One row per
call captures the wall-clock `duration_ms` spent inside the proxied upstream
endpoint, the `tool_name`, and a success/error flag, so cumulative duration
and invocation counts can be calculated in aggregation. Usage queries go
through the `mcp_aggregated_usage` projection — per-minute, per-user rollups
(summing `total_duration_ms` and counting `invocations`) exposed read-only at
`GET /mcp-server-configs/aggregated-usage` (paginated),
`GET /mcp-server-configs/aggregated-usage/{id}`,
`GET /mcp-server-configs/aggregated-usage/batch?ids=…`, and
`GET /mcp-server-configs/aggregated-usage/count`. Access is gated by the
`mcp_aggregated_usage_permission` role column.

Two background sweeps (same lifespan pattern as the LLM usage loops above)
keep the projection usable, configured under `mcp.usage` with the same knobs
as `llm.usage`:

* **Partition manager** — preallocates `preallocate_days` future daily
  `mcp_usage` partitions and drops partitions older than `retention_days`.
  * `mcp.usage.partition_interval` (`OHE_MCP_USAGE_PARTITION_INTERVAL`, default
    `300`): seconds between sweeps. **Non-zero** runs an `asyncio` loop in the
    FastAPI lifespan.
  * `mcp.usage.partition_interval = 0` **disables** the in-process loop; drive
    partition management with an external scheduler calling
    `McpUsageService.ensure_partitions`.
  * `mcp.usage.preallocate_days` (`OHE_MCP_USAGE_PREALLOCATE_DAYS`, default
    `7`): how many future daily partitions to keep allocated ahead of time.
  * `mcp.usage.retention_days` (`OHE_MCP_USAGE_RETENTION_DAYS`, default
    `365`): partitions whose day is older than this are dropped.

* **Aggregator** — rolls finished minutes from `mcp_usage` into
  `mcp_aggregated_usage`, at least one minute behind wall-clock time so a
  minute is only rolled once it has finished receiving rows.
  * `mcp.usage.aggregate_interval` (`OHE_MCP_USAGE_AGGREGATE_INTERVAL`, default
    `60`): seconds between sweeps. **Non-zero** runs an `asyncio` loop in the
    FastAPI lifespan.
  * `mcp.usage.aggregate_interval = 0` **disables** the in-process loop; drive
    aggregation with an external scheduler calling
    `McpUsageService.aggregate_behind_now`.

A `DEFAULT` partition is created by the initial migration so inserts never
fail before the manager's first sweep (or for out-of-range timestamps).

## Sandbox lifecycle

Each sandbox carries a nullable `last_accessed_at` timestamp derived from the
agent server running inside the container. The Docker sandbox service probes
the container's `agent_server` exposed port root endpoint (`GET /`), which
returns JSON with an `idle_time` (seconds since last activity); the
last-accessed time is `now - idle_time`. The probe is best-effort: a sandbox
that is not `active`, unreachable, or returns no usable `idle_time` reports
`last_accessed_at = null`. The field is exposed on `SandboxRead` and
filterable via `last_accessed_at__gte/__gt/__lt/__lte` on
`GET /sandbox/sandboxes`.

Template lifespan knobs drive an automatic lifecycle enforced by a background
sweep started when the sandbox service enters its async context (the FastAPI
lifespan). The sweep is configured on the `DockerSandboxService` (env prefix
`OHE_SANDBOX`):

* `sandbox_lifecycle_interval` (`OHE_SANDBOX_LIFECYCLE_INTERVAL`, default
  `60`): seconds between sweeps. **Non-zero** runs an `asyncio` loop tied to
  the app lifespan — no external scheduler needed.
* `sandbox_lifecycle_interval = 0` **disables** the in-process loop; drive
  the sweep with an external scheduler calling
  `DockerSandboxService.sweep_lifecycle`.
* `agent_server_probe_timeout` (`OHE_SANDBOX_AGENT_SERVER_PROBE_TIMEOUT`,
  default `2`): per-sandbox HTTP timeout for the `last_accessed_at` probe.

Each sweep lists every sandbox, resolves its template, and applies the
highest-priority action (a `None` knob is not enforced):

1. **`max_age_seconds`** — delete a sandbox whose `created_at` is older than
   the threshold.
2. **`idle_pause_seconds`** — pause an `active` sandbox whose idle time
   exceeds the threshold (sets `desired_status = inactive`).
3. **`paused_delete_seconds`** — delete an `inactive` sandbox paused longer
   than the threshold. The pause time is read from the
   `io.openhands.sandbox.paused_at` container label, stamped when the sweep
   (or a caller) pauses the sandbox and cleared on resume, so it survives
   restarts.
