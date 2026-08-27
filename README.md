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
| Auth | OAuth + password (bcrypt) + signed cookies |
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

## Federated authentication (auth2)

The `auth2` module is a federated OAuth/OIDC layer that runs alongside the
legacy `auth` module until it is proven and merged. The project acts as an
OAuth **provider** to first-party clients and as an OAuth **client** to an
external identity provider (IdP).

Required configuration (environment variables, `OHEV_` prefix):

| Field | Env var | Purpose |
| --- | --- | --- |
| `idp_url` | `OHEV_IDP_URL` | Base URL of the identity provider |
| `idp_client_id` | `OHEV_IDP_CLIENT_ID` | Client id registered at the IdP |
| `idp_client_secret` | `OHEV_IDP_CLIENT_SECRET` | Client secret registered at the IdP |
| `idp_expire_drift_tolerance` | `OHEV_IDP_EXPIRE_DRIFT_TOLERANCE` | Seconds subtracted from IdP `expires_in`/`expires_at` to avoid drift bugs |

Optional OIDC claim overrides: `idp_user_id_field`, `idp_email_field`,
`idp_role_field` (default to the standard `sub`, `email`, and a reserved
role claim). Role→permission mapping is deferred; roles are not pulled from
scopes.

Flow: `GET /auth2/authorize` redirects to the IdP (with PKCE), `GET
/auth2/callback` exchanges the code and, for `response_type=cookie`, mints a
session cookie (the `code` response type mints an exchangeable code instead),
`POST /auth2/token` and `POST /auth2/refresh` exchange codes / refresh tokens
for token pairs. OAuth clients are managed via `/auth2/clients` (CRUD with
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

* `cleanup_interval` (`OHEV_CLEANUP_INTERVAL`, default `300`): seconds between
  sweeps. **Non-zero** runs an `asyncio` loop inside the FastAPI lifespan —
  no external scheduler needed.
* `cleanup_interval = 0` **disables** the in-process loop; drive cleanup with
  an external cron job hitting the same `delete_expired_tokens` service
  function (or a future admin endpoint).
* `idp_delete_expired_seconds` (`OHEV_IDP_DELETE_EXPIRED_SECONDS`, default
  `86400`): rows whose `expires_at` is older than this window are deleted.
  `0` deletes any already-expired row regardless of age.
