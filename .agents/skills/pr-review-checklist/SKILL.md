---
name: pr-review-checklist
description: Checklist for agents reviewing pull requests — REST consistency, layering, tests, coverage, auth guards, link tables, specs, and secrets. Load when reviewing a PR.
version: "1.0.0"
---

# Review checklist (for agents reviewing PRs)

- [ ] REST verbs/names consistent with the rest-api-routes skill.
- [ ] No layering violations (routers → services → repositories → models).
- [ ] Methods short, single-purpose.
- [ ] New code has tests; coverage gate green (94%).
- [ ] ruff + mypy strict clean.
- [ ] e2e suite green locally.
- [ ] Spec updated and passing if behavior changed (quint-specs skill).
- [ ] No secrets/hardcoded credentials.
- [ ] New governed entity: column added to `Role` + `ROLE_ENTITY_COLUMNS` (full `<entity>_permission` name) + migration + registered in `auth_dependencies` + field added to `RoleCreate`/`RoleUpdate`/`RoleRead` (`TestEntityColumnParity` enforces).
- [ ] Link tables guarded by their own entity column, not a parent's; every endpoint's guard names the entity it actually mutates.
- [ ] Every router passes the resolved permission filter to its service, and the service scopes SQL with it.
- [ ] Every new route is protected by an auth dependency, or listed (with comment) in `PERMISSION_DEPENDENCY_OVERRIDES` (`test_route_permissions.py` enforces).
- [ ] Comments follow the comments policy in AGENTS.md.
