.PHONY: test test-fast test-affected test-parallel lint type check

# Full suite with coverage and the 94% gate — run before opening a PR and in CI.
# `-n 0` forces single-process so coverage attribution is deterministic and the
# gate is evaluated against one run (mirrors the CI invocation).
test:
	uv run pytest -q -n 0 --cov=openhands.ev2 --cov-fail-under=94 --cov-report=term-missing --cov-report=xml

# Fast iteration loop: no coverage, stop at the first failure. Scope to a path
# or expression with the ARGS variable, e.g. `make test-fast ARGS=tests/unit/test_user_service.py`
# or `make test-fast ARGS="-k create"`.
test-fast:
	uv run pytest -x -q -p no:cov --testmon $(ARGS)

# Run only tests affected by the current uncommitted diff (testmon tracks the
# line-level mapping). Use after a small edit to re-run exactly what it touches.
test-affected:
	uv run pytest -q -p no:cov --testmon

# Parallel run without coverage — useful when you want the full suite fast but
# don't need the coverage gate.
test-parallel:
	uv run pytest -q -p no:cov

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

check: lint type test
