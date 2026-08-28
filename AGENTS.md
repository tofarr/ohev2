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
* Unit coverage â‰¥ 90%. New code without tests blocks merge.
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
   uv run pytest -q
   ```
2. **e2e** (mirrors the `e2e` CI job; requires Docker for the service stack):
   ```
   uv run playwright install --with-deps chromium
   docker compose up -d
   OHEV_DATABASE_URL=postgresql+asyncpg://ohev:ohev@localhost:5432/ohev uv run alembic upgrade head
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

When reviewing: if two resources use different verbs/names for the same operation,
reject the change.

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
  `permission/`). No `models/`/`routes/`/`services/` subfolders.
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

## 9. Auth

* Password hashing via bcrypt (`util.password`). Never log or serialize password hashes.
* Signed cookies for sessions; OAuth flows for federated identity.
* Federated OAuth lives in `auth2/` (alongside legacy `auth/` until merged). The
  project is an OAuth provider to first-party clients and an OAuth client to an
  external IdP. Required config: `idp.url`, `idp.client_id`,
  `idp.client_secret`, `idp.expire_drift_tolerance`. Optional OIDC claim
  overrides: `idp.user_id_field`, `idp.email_field`, `idp.role_field`. Roles
  are NOT pulled from scopes.
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
  the cookie path keeps the existing cookie; the explicit `/auth2/refresh`
  endpoint returns 409. After acquiring the lock the access row is
  re-checked: if its expiry is now in the future another process already
  refreshed it and the IdP call is skipped.
* Background cleanup of expired IdP refresh tokens: `cleanup_interval` (non-zero)
  runs an in-process `asyncio` loop in the app lifespan; `cleanup_interval = 0`
  disables it and cleanup must be driven by an external scheduler (cron). See
  README "Cleanup processes".
* Authorization checks live in services (not just routers) — defense in depth.

## 10. Review checklist (for agents reviewing PRs)

- [ ] REST verbs/names consistent with §3.
- [ ] No layering violations (§4).
- [ ] Methods short, single-purpose (§4).
- [ ] New code has tests; coverage gate green (§2, §5).
- [ ] ruff + mypy strict clean (§2).
- [ ] e2e suite green locally (§2.1).
- [ ] Spec updated and passing if behavior changed (§7).
- [ ] No secrets/hardcoded credentials (§9).
- [ ] Comments follow §6.
