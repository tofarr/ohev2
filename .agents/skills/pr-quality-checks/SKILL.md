---
name: pr-quality-checks
description: Required lint, type, coverage, and e2e checks to run before opening or updating a pull request. Call this skill before creating or pushing a PR branch.
version: "1.0.0"
---

# Code quality gates (enforced in CI)

* `ruff check .` and `ruff format --check .` clean.
* `mypy --strict` clean (no `Any` without explicit `# type: ignore` + reason).
* Unit coverage >= 94%. New code without tests blocks merge.
* Quint specs compile and pass.
* Playwright e2e suite green. The full suite runs daily and also on every PR
  (see `.github/workflows/e2e-daily.yml` and the `e2e` job in
  `.github/workflows/ci.yml`).

If a change can't meet a gate, flag it explicitly rather than silently bypassing it.

## Pre-PR verification — run locally before opening a PR

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
3. **specs** (only when behavior changed, per the quint-specs skill):
   ```
   quint typecheck specs/*.qnt
   quint test specs/<spec>.qnt --main=<spec>
   ```

If any step fails, fix it before opening the PR — do not open the PR and
address CI failures reactively. If the environment cannot run a step (e.g.
Docker unavailable), say so explicitly in the PR description rather than
skipping it silently.
