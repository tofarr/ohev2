# OpenHands Enterprise v2 (ohev)

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
src/ohev/            Application source (importable as `ohev`)
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
uv run uvicorn ohev.app:app --reload
```
