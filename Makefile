.PHONY: test test-fast test-affected test-parallel lint type check validate validate-specs validate-e2e

# Full suite with coverage and the 94% gate — run before opening a PR and in CI.
# `-n 0` forces single-process so coverage attribution is deterministic and the
# gate is evaluated against one run (mirrors the CI invocation).
test:
	uv run python -m pytest -n 0 -q --cov=openhands.ev2 --cov-fail-under=94 --cov-report=term-missing --cov-report=xml

# Minimal-token loop, exact same semantics as `pytest -q --tb=short -p no:cacheprovider -W
# ignore::UserWarning --no-summary`. Scope to a path or expression with the ARGS
# variable, e.g. `make test-fast ARGS=tests/unit/test_user_service.py`
# or `make test-fast ARGS="-k create"`.
test-fast:
	uv run python -m pytest -n 0 -x -q -p no:cov --testmon -p no:cacheprovider -W ignore::UserWarning --no-summary --tb=short $(ARGS)

# Run only tests affected by the current uncommitted diff (testmon tracks the
# line-level mapping). Use after a small edit to re-run exactly what it touches.
test-affected:
	uv run python -m pytest -n 0 -q -p no:cov --testmon -p no:cacheprovider -W ignore::UserWarning --no-summary --tb=short

# Parallel run without coverage — useful when you want the full suite fast but
# don't need the coverage gate.
test-parallel:
	uv run python -m pytest -n auto -q -p no:cov -p no:cacheprovider -W ignore::UserWarning --no-summary --tb=short

lint:
	uv run ruff check .
	uv run ruff format --check .

type:
	uv run mypy

check: lint type test

# == Pre-PR validation gate (mirrors the `lint-type-coverage` CI job, in order) ==
# Runs ONLY the lightweight gates here; the full unit suite is `make validate-tests`.
# Stops on the first failing gate. Requires `postgres`/`initdb` on PATH for the
# embedded-Postgres unit suite (`tests/conftest.py`).
validate-tests:
	uv run python -m pytest -n 0 -q --no-summary --tb=short --cov=openhands.ev2 --cov-fail-under=94 --cov-report=term-missing --cov-report=xml

validate:
	@echo "== validate: ruff =="
	uv run ruff check .
	@echo "== validate: format =="
	uv run ruff format --check .
	@echo "== validate: mypy =="
	uv run mypy
	@echo "== validate: McCabe (pylint) =="
	uv run pylint src/openhands/ev2
	@echo "== validate: dead code (vulture) =="
	uv run vulture
	@echo "== validate: unit tests + 94% coverage =="
	$(MAKE) validate-tests

# Spec/formal checks — run when `specs/` changed (matches the `specs` CI job).
# Change detection covers uncommitted worktree edits (tracked + untracked) and
# committed branch changes vs upstream (git diff @{upstream}...HEAD). On a
# shallow clone where upstream == HEAD the upstream diff is empty, so only
# worktree edits are seen — push depth or fetch --unshallow for full branch coverage.
validate-specs:
	@upstream=$$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || echo origin/main); \
	if { git diff HEAD --name-only -- specs/; git ls-files --others --exclude-standard -- specs/; } | grep -q . || git diff "$$upstream...HEAD" --name-only -- specs/ | grep -q .; then \
		echo "== validate-specs: change detected under specs/ =="; \
		for f in specs/*.qnt; do echo "::group::typecheck $$f"; quint typecheck "$$f"; echo "::endgroup::"; done; \
		quint test specs/user.qnt --main=user; \
		quint test specs/encryption.qnt --main=encryption; \
		quint test specs/sandbox.qnt --main=sandbox; \
		quint test specs/rest.qnt --main=rest; \
		quint test specs/auth.qnt --main=auth; \
		quint test specs/batch.qnt --main=batch; \
		quint test specs/conversation_record.qnt --main=conversation_record; \
		quint test specs/webhook.qnt --main=webhook; \
		echo "== validate-specs: invariants =="; \
		quint run specs/user.qnt --main=user --invariant=userIdsUnique --max-steps=100; \
		quint run specs/user.qnt --main=user --invariant=userEmailsUnique --max-steps=100; \
		quint run specs/sandbox.qnt --main=sandbox --invariant=statesConsistent --max-steps=100; \
		quint run specs/encryption.qnt --main=encryption --invariant=encryptionKeyInDecryptionKeys --max-steps=100; \
		quint run specs/auth.qnt --main=auth --invariant=codeConsumedOnceInvariant --max-steps=100; \
		quint run specs/auth.qnt --main=auth --invariant=cleanupOnlyExpiredInvariant --max-steps=100; \
		quint run specs/auth.qnt --main=auth --invariant=cookieFlowNeverCodedInvariant --max-steps=100; \
		quint run specs/batch.qnt --main=batch --invariant=batchAtomicity --max-steps=100; \
	else \
		echo "== validate-specs: no specs/ changes — skipping =="; \
	fi

# E2E (mirrors the `e2e` CI job; requires Docker for the service stack).
validate-e2e:
	uv run playwright install --with-deps chromium
	docker compose up -d
	OHE_DB_CONFIG_HOST=localhost OHE_DB_CONFIG_PORT=5432 OHE_DB_CONFIG_DB_NAME=ohev \
	OHE_DB_CONFIG_USERNAME=ohev OHE_DB_CONFIG_PASSWORD=ohev uv run alembic upgrade head
	uv run pytest tests/e2e -q --no-cov
	docker compose down
