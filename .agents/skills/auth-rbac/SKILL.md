---
name: auth-rbac
description: Auth flows, IdP integration, API key role restriction, route protection, per-entity permission columns on Role, and link table authorization. Load when working on auth, roles, permissions, or governed entities.
version: "1.0.0"
---

# Auth

* Password hashing via bcrypt (`util.password`). Never log or serialize password hashes.
* Signed cookies for sessions; OAuth flows for federated identity.
* Federated OAuth lives in `auth/`. The project is an OAuth provider to
  first-party clients and an OAuth client to an external IdP. Required config:
  `idp.url`, `idp.client_id`, `idp.client_secret`,
  `idp.expire_drift_tolerance`. Optional OIDC claim overrides:
  `idp.user_id_field`, `idp.email_field`, `idp.role_field`. Roles are NOT
  pulled from scopes.
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
  the cookie path keeps the existing cookie; the explicit `/auth/refresh`
  endpoint returns 409. After acquiring the lock the access row is
  re-checked: if its expiry is now in the future another process already
  refreshed it and the IdP call is skipped.
* Background cleanup of expired IdP refresh tokens: `cleanup_interval` (non-zero)
  runs an in-process `asyncio` loop in the app lifespan; `cleanup_interval = 0`
  disables it and cleanup must be driven by an external scheduler (cron). See
  README "Cleanup processes".
* Background LLM usage management — two more lifespan loops follow the same
  pattern (config `= 0` disables the in-process loop, falling back to an
  external scheduler). See README "LLM usage logging":
  - `llm.usage.partition_interval` (`OHE_LLM_USAGE_PARTITION_INTERVAL`):
    preallocates `llm.usage.preallocate_days` future daily `llm_usage`
    partitions and drops ones older than `llm.usage.retention_days`.
  - `llm.usage.aggregate_interval` (`OHE_LLM_USAGE_AGGREGATE_INTERVAL`):
    rolls finished minutes (at least one behind wall-clock) from `llm_usage`
    into the read-only `llm_aggregated_usage` projection.
* Background MCP usage management — two lifespan loops with the same shape
  and the same `= 0` disables-in-process semantics, configured under
  `mcp.usage` (env `OHE_MCP_USAGE_*`). See README "MCP usage logging":
  - `mcp.usage.partition_interval` (`OHE_MCP_USAGE_PARTITION_INTERVAL`):
    preallocates `mcp.usage.preallocate_days` future daily `mcp_usage`
    partitions and drops ones older than `mcp.usage.retention_days`.
  - `mcp.usage.aggregate_interval` (`OHE_MCP_USAGE_AGGREGATE_INTERVAL`):
    rolls finished minutes (at least one behind wall-clock) from `mcp_usage`
    into the read-only `mcp_aggregated_usage` projection (per-user
    `total_duration_ms` sums + `invocations` counts, gated by
    `mcp_aggregated_usage_permission`).
* Authorization checks live in services (not just routers) — defense in depth.
* **API key role restriction.** An `ApiKey` carries an optional `role_id` (FK → `roles.id`, `ondelete=SET NULL`). When set, the restricting role's per-entity permission filter is ANDed (intersected) with the principal's user-roles OR filter in `_resolve_column_filter` / `_narrow_with_api_key_role`, so the key can only **narrow** — never widen — the principal's access. A `NULL`/deny policy on the restricting role yields `None` (403, fail-closed). Deleting the restricting role SET NULLs `role_id` so the key widens back to baseline at authenticate time; a rare race (role deleted between authenticate and authz) fails closed (deny). The Quint spec mirrors this in `effectiveFilterWithApiKey` / `andFilters` (`specs/rbac.qnt`).
* **Every route is protected by an auth dependency.** Each registered API route
  must transitively depend on a protecting dependency from `auth_dependencies`
  — `depends_access_token`, `depends_user_id`, `depends_role_ids`,
  `depends_permissions`, or `depends_permissions_or_none`. A route that has
  none of these is anonymous and must be added to
  `PERMISSION_DEPENDENCY_OVERRIDES` in
  `tests/unit/test_route_permissions.py`, with a comment explaining why the
  standard auth dependency does not apply. The override set is audited in
  review and the test fails if an override no longer matches a registered
  route (so stale exemptions are caught). The invariant is mirrored in
  `specs/rest.qnt` (`allRoutesProtected`). Genuinely public routes are few:
  `/health`, OIDC discovery (`.well-known/*`), the OAuth2 flow entry points
  that mint/revoke credentials (`/auth/authorize`, `/auth/callback`,
  `/auth/token`, `/auth/refresh`, `/auth/revoke`, `/auth/logout`), the built-in
  dev IdP (`/auth/dev/*`). The LLM completion forwarder
  (`/llm/completion/{llm_id}/{path}`) and the MCP JSON-RPC proxy
  (`POST|GET|DELETE /mcp/{config_id}`) are **not** exempted: they authenticate
  the caller through the standard permission dependencies (`USE` on the stored
  LLM / MCP server config) and inject the stored upstream provider/MCP
  credential internally — the caller never presents the provider key.

# Roles & per-entity permission columns

* A `Role` (`role/role_models.py`) bundles one explicit `Permission` JSONB
  column **per governed entity** (e.g. `user_permission`, `role_permission`,
  `user_role_permission`, `api_key_permission`, `oauth_client_permission`,
  `cors_origin_permission`). A `NULL` column means "deny" for that entity.
  There is **no** `policies` map and **no** legacy `role_permission`/
  `user_permission` fallback: every governed entity is its own column.
* The canonical list of entity columns is `ROLE_ENTITY_COLUMNS` in
  `role/role_models.py` — each entry is the full column name
  (``<entity>_permission``). Adding a governed entity is a four-step change:
  1. append the ``<entity>_permission`` column name to `ROLE_ENTITY_COLUMNS`;
  2. add the matching column to `Role` (and to the initial migration
     `0001_initial.py`, since the schema is not yet published);
  3. register the resource's ORM model against the column name in
     `auth_dependencies.register_resource_policy(model, "<entity>_permission")`.
  4. add the field to `RoleCreate`/`RoleUpdate`/`RoleRead` in
     `role/role_schemas.py`.
  `register_resource_policy` validates the column is in
  `ROLE_ENTITY_COLUMNS` and raises at import time if not, so a mismatched
  registration fails fast. `RoleService.create`/`update` copy every column in
  `ROLE_ENTITY_COLUMNS` generically, so schemas must stay in sync —
  `tests/unit/test_role_service.py::TestEntityColumnParity` guards all four
  steps (column, model, registry, schemas, service round-trip). A column
  missing from the schemas can never be granted via the API — silently
  denying the entity to everyone except seeds.
* `Role` and `UserRole` live in `role/role_models.py`, **not** in
  `security_models.py`. `security_models.py` only defines the policy types
  (`Permission` and subclasses) and the `PermissionType` JSONB column type.
* The role-to-user link table is `user_roles` (model `UserRole`), plural
  noun-first naming. A user may have multiple roles; there is no
  single `role` column on `User`.
* `seed_db.py` (run via `uv run python -m openhands.ev2.scripts.seed_db`)
  seeds two roles: an `admin` role granting `Permitted()` on every column in
  `ROLE_ENTITY_COLUMNS` (so re-running after adding a new entity backfills the
  missing grant automatically), and a `user` role granting `ApiKeyAccess` on
  `api_key_permission` so a non-admin user can manage their own API keys. It
  also upserts an admin user and (by default) a regular user account.

## Link tables are first-class governed resources

Privilege-escalation holes repeatedly come from guarding a link table by the
permission of one of its endpoints. **Every link/join table gets its own
entity column and is authorized through it — never through a parent's
column.**

* `user_roles` → `user_role_permission`: deciding who *holds* a role is not
  implied by `role_permission` (a role-metadata admin must not be able to
  self-assign an admin role — self-service privilege escalation).
* Routers for link tables guard with `depends_permissions(<LinkModel>,
  Action.*)` and pass the resolved filter to the service; the service scopes
  reads via `perm_filter.filter_sql(...)` and rejects out-of-scope creates
  with a scope error (403) — same pattern as the primary resources.
* Auditing rule of thumb: for every endpoint, name the *entity* it mutates
  and confirm the guard checks that entity's column. If the guard checks a
  different entity's column, ask whether that coupling lets a principal gain
  access they were not explicitly granted.

> **Note:** The per-item ACL link tables (`role_secret_permissions`,
> `user_secret_permissions`, `role_mcp_server_config_permissions`,
> `role_sandbox_template_permissions`) and their grant-permission columns
> (`secret_grant_permission`, `mcp_server_config_grant_permission`,
> `sandbox_template_grant_permission`) have been removed. Item-level access
> control is now expressed via the generic `AclPermission` policy stored in
> the role's per-entity JSONB column (e.g. `secret_provider_permission`),
> which enumerates permitted item ids per action. See the `secrets` skill
> for the secrets projection, which is gated by a single USE permission on
> the parent provider.
