# AGENTS.md — rules for agents and contributors working in `ohev`

This file is the persistent memory for this repository. Agents (human or AI) must
follow these rules when producing or reviewing code. Rules are grouped by topic.

## 1. Stack & tooling

* Python ≥ 3.11, asyncio-first. Never use blocking I/O on the request path.
* Manage dependencies with `uv`. Never hand-edit `uv.lock`; use `uv add/remove/sync`.
* FastAPI for HTTP. Pydantic v2 for all request/response schemas.
* SQLAlchemy 2 async ORM + asyncpg. Alembic for migrations.
* OpenHands SDK + Agent Server for agent execution.
* Quint for formal specs; every behavioral change to a resource must be reflected in
  `specs/` and verified with `quint typecheck` / `quint test`.

## 2. Code quality gates (enforced in CI)

* `ruff check .` and `ruff format --check .` clean.
* `mypy --strict` clean (no `Any` without explicit `# type: ignore` + reason).
* Unit coverage ≥ 90%. New code without tests blocks merge.
* Quint specs compile and pass.
* Playwright e2e suite green (runs daily).

If a change can't meet a gate, flag it explicitly rather than silently bypassing it.

## 3. REST API consistency

The REST surface must be uniform. These rules are non-negotiable:

* Collection retrieval is **always** `GET /{resource}` (paginated via `?cursor=&limit=`).
  Never invent `/list`, `/search`, `/all`, `/get` action paths for listing.
* Search is expressed as query params on the collection (`GET /{resource}?q=…`), never
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
* Layering: `routers → services → repositories → models`. Do not skip layers (a router
  must not query the DB directly).
* Shared behavior goes in a common module; do not copy-paste across resources.

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

* Password hashing via bcrypt (passlib). Never log or serialize password hashes.
* Signed cookies for sessions; OAuth flows for federated identity.
* Authorization checks live in services (not just routers) — defense in depth.

## 10. Review checklist (for agents reviewing PRs)

- [ ] REST verbs/names consistent with §3.
- [ ] No layering violations (§4).
- [ ] Methods short, single-purpose (§4).
- [ ] New code has tests; coverage gate green (§2, §5).
- [ ] ruff + mypy strict clean (§2).
- [ ] Spec updated and passing if behavior changed (§7).
- [ ] No secrets/hardcoded credentials (§9).
- [ ] Comments follow §6.
