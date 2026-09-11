# Plan: DB as source of truth for sandboxes

## Goal

Move sandbox **templates**, **configs** (durable sandbox intent), and
**snapshots** into the database so they can be updated without a redeploy and
so we stop relying on Docker/K8s inventory for status. The polymorphic
`SandboxService` keeps only the *sandbox* concern: reconciling DB state
against Docker/K8s and reporting live `Sandbox` objects (read-only).

Guiding philosophy: **the DB is the source of truth; the sandbox service
reconciles sandboxes to match it.**

> Terminology: "runtime" is a legacy term we are moving away from. The live
> compute objects are called **sandboxes**. A `SandboxConfig` is the durable
> intent; a `Sandbox` is the live sandbox the provider reports.

## Current state (what changes)

Today `SandboxTemplate`, `Sandbox`, and `SandboxSnapshot` are Pydantic
`DiscriminatedUnionMixin` models whose concrete subclasses
(`DockerSandboxTemplate`, `DockerSandbox`, `DockerSandboxSnapshot`) carry
provider-specific fields. State lives *in the provider*:

- templates = Docker image inventory (id = image name; labels hold lifespan
  knobs); created/deleted only, no updates.
- sandboxes = Docker container inventory; `desired_status` drives pause/resume;
  `status`/`last_accessed_at`/`exposed_urls` are read off the live container.
- snapshots = tarballs on disk enumerated by the provider.

`SandboxService` is an ABC with provider hooks (`_list_templates`,
`_create_sandbox`, …) and generic in-memory CRUD/search/batch on top. Authz
registers the Pydantic types against `sandbox_template_permission` /
`sandbox_permission` / `sandbox_snapshot_permission` in
`auth_dependencies.register_resource_policy`.

## Target state

Three **non-polymorphic** DB-backed resources + one **polymorphic live-sandbox**
read-only surface.

### `SandboxTemplate` (DB, non-polymorphic, governed)

```
id: UUID                                  PK
docker_image_tag: str                     e.g. ghcr.io/openhands/agent-server:latest
delete_after_idle_seconds: int | None     replaces idle_pause_seconds + paused_delete_seconds
                                          (single knob: time idle -> delete)
in_container_user_id: int | None
in_container_group_id: int | None
max_memory: int | None                    works in both Docker and K8s
exposed_ports: list[ExposedPort]          JSONB, max 100 items
env_vars: dict[str, str]                  JSONB, max 4k chars serialized
working_dir: str
snapshot_dirs: list[str]                  JSONB — workspace dirs snapshotted
snapshot_on_deactivate: bool              default false
meta: json object                         provider hints, max 4k chars serialized
created_at: datetime                      server_default clock_timestamp()
updated_at: datetime                      server_default clock_timestamp(), onupdate
```

- Becomes a real ORM model (`sandbox/sandbox_template_models.py`) + a Pydantic
  `SandboxTemplateRead`/`Create`/`Update` schema set.
- **Now mutable** — adds `SandboxTemplateUpdate` + batch `update` op (was
  create/delete only). This is the main win: templates update without redeploy.
- Registered against the existing `sandbox_template_permission` column. The
  model type passed to `register_resource_policy` changes from the Pydantic
  `SandboxTemplate` ABC to the new ORM `SandboxTemplate` — the column name is
  unchanged so roles/seed need no edit.
- Old `DockerSandboxTemplate` is removed; the Docker-specific fields collapse
  into generic columns. `max_memory` is **kept as an optional column** (works
  in both Docker and K8s).

### `SandboxConfig` (DB, non-polymorphic, governed)

Represents the durable *intent* for a sandbox. May not match a live sandbox —
the service reconciles.

```
id: UUID                                  PK
sandbox_template_id: UUID                 FK -> sandbox_templates.id, ON DELETE RESTRICT
                                          (a template in use cannot be deleted)
enabled: bool                             mutable; the service reconciles the live
                                          sandbox to this. Replaces desired_status.
                                          Disabled = stop/pause-or-delete-and-recreate
                                          (provider-dependent, governed by env config);
                                          enabled = (re)create from snapshot if
                                          sandbox_snapshot_id set.
sandbox_snapshot_id: UUID | None          optional; when set, (re)creating the live
                                          sandbox restores this snapshot's workspace
                                          first (analogous to PVC from VolumeSnapshot).
session_api_key: SecretStr                encrypted at rest (JWE, like OAuthClient secret)
expires_at: datetime | None               mutable (a permission may restrict editing).
                                          Derived from the template's
                                          delete_after_idle_seconds by the lifecycle
                                          sweep (set/refreshed as the sandbox idles).
snapshot_on_deactivate: bool              read from template if not set on create
created_at: datetime
updated_at: datetime
```

- `enabled` replaces `desired_status: SandboxState`. Disabling is interpreted
  by the provider:
  - **Docker**: governed by an env var (`OHE_SANDBOX_DEACTIVATE_MODE`), either
    `pause` (freeze in place) or `stop` (delete-and-recreate on re-enable).
  - **Kubernetes**: pausing is not really supported, so disabling = capture a
    snapshot (if `snapshot_on_deactivate`) and delete the deployment;
    re-enabling recreates from `sandbox_snapshot_id`.
- New ORM model `sandbox_config_models.py` + schemas.
- Registered against the existing `sandbox_permission` column (the durable
  governed resource is now `SandboxConfig`, not the live `Sandbox`).
- `session_api_key` is encrypted via `EncryptionService` (same pattern as
  `StoredProviderConnection.api_key` / `OAuthClient.client_secret`).
- The create flow: insert `SandboxConfig` (`enabled=false` by default), then
  the service reconciles to boot the live sandbox when `enabled=true`.

### `Sandbox` (live, polymorphic, **read-only**)

The only non-DB, polymorphic object. Represents the live sandbox as the
provider sees it.

```
id: str                                   docker container name / k8s deployment / ...
sandbox_config_id: UUID                   the durable intent this sandbox serves.
                                          Stored as provider metadata: a Docker
                                          container label on the container, a label/
                                          annotation on the K8s deployment. NOT a DB
                                          column — the service writes it when it boots
                                          the sandbox and reads it back to correlate.
exposed_urls: list[ExposedUrl]            resolved host ports / ingress URLs
env_vars: dict[str, str]                  effective env (template + service-injected)
meta: json object                         live provider hints
created_at: datetime
updated_at: datetime
expires_at: datetime | None               mirrored from config for convenience
```

- Stays a `DiscriminatedUnionMixin` Pydantic model (provider subclasses may add
  fields like `last_accessed_at`, `status_detail`).
- **No CRUD endpoints.** Surfaced read-only via `GET /sandbox/sandboxes` and
  `GET /sandbox/sandboxes/{id}`.
- Correlation: the service stamps `sandbox_config_id` onto the provider object
  (Docker label / K8s annotation) at boot time. To enrich a set of configs
  with their live sandboxes, the service lists sandboxes and returns them
  keyed by the stamped `sandbox_config_id` — **batched**, not one get per
  config.
- Authz: the REST read path authorizes against `SandboxConfig` (the governed
  DB row). The collection is DB-paginated and authz-scoped off
  `SandboxConfig`; each row is enriched with its live `Sandbox` via a single
  batched service call (see Q4).

### `SandboxSnapshot` (DB, non-polymorphic, governed)

```
id: UUID                                  PK
sandbox_template_id: UUID                 FK -> sandbox_templates.id (snapshots are
                                          template-scoped for restore compatibility)
sandbox_id: UUID | None                   nullable; the source sandbox the snapshot was
                                          created from. Null for snapshots imported
                                          from an uploaded file that did not come from
                                          a sandbox.
schema: str                               compatibility tag (e.g. "docker-workspace-tar-v1")
download_url: str                         URL to stream the tarball (relative/signed)
created_at: datetime
```

- Becomes an ORM model `sandbox_snapshot_models.py`. The DB row is the index.
- **Artifact storage is hidden inside the sandbox service.** In Docker it is a
  local file; in K8s it may be an S3 bucket. The service owns storing, reading,
  and deleting the artifact; the DB row only carries the `download_url` the
  service produces. Listing snapshots never enumerates the filesystem/bucket.
- Registered against existing `sandbox_snapshot_permission`.
- `size_bytes` can stay as an optional column; `sandbox_id` is nullable (null
  for file imports).

## Reconciler service shape

`SandboxService` (ABC) shrinks to the live-sandbox concern:

- DB CRUD for templates/configs/snapshots moves to **DB-backed service
  classes** (`SandboxTemplateService`, `SandboxConfigService`,
  `SandboxSnapshotService`) following the `routers → services → repositories
  → models` layering. These are provider-agnostic and own authz scoping via
  `perm_filter.filter_sql(...)`.
- The polymorphic `SandboxService` keeps only:
  - `list_sandboxes(config_ids: list[UUID]) -> dict[UUID, Sandbox]` — report
    live sandboxes for the given configs, batched (one provider scan, keyed by
    the stamped `sandbox_config_id`). Never one-get-per-config.
  - `reconcile(config: SandboxConfig) -> Sandbox | None` — start/stop/pause to
    match `enabled` (and `sandbox_snapshot_id` on enable).
  - `create_sandbox(config, snapshot_id) -> Sandbox` — boot compute for a new
    config, stamping `sandbox_config_id` as provider metadata.
  - `delete_sandbox(config) -> None` — tear down compute.
  - `capture_snapshot(config) -> SnapshotArtifact` / `restore_snapshot(...)`.
  - `stream_snapshot(snapshot_id)` — unchanged.
- On startup the service reads templates from the DB and **pulls images as
  required** (Docker `docker pull`, K8s image preload) instead of scanning
  image inventory. A new template added via API triggers a **background**
  pull — the create response returns 202 and the pull status is surfaced for
  polling.
- The in-process lifecycle sweep reads `SandboxConfig` rows joined to their
  template, derives/refreshes `expires_at` from the template's
  `delete_after_idle_seconds`, and calls `reconcile`/`delete_sandbox` when
  expired or when `snapshot_on_deactivate` applies — no more label-driven sweep.

## Routers

- `/sandbox/sandbox-templates` — full CRUD (now with PATCH update + batch
  update op). Adds `max_memory` column.
- `/sandbox/sandbox-configs` — new resource: CRUD on durable intent. This is
  where "create a sandbox" lives now (POST creates a config; the service
  reconciles to boot the live sandbox when `enabled=true`).
- `/sandbox/sandboxes` — **read-only**, lists `SandboxConfig` rows enriched
  with their live `Sandbox` (batched service call, not one get per config).
  Kept as the user-facing sandbox view.
- `/sandbox/sandbox-snapshots` — CRUD (create stays multipart for file import).

Durable intent (`/sandbox/sandbox-configs`) and the live sandbox view
(`/sandbox/sandboxes`) are **both kept** — they are distinct surfaces and
consolidating would lose the durable-intent separation.

## Migration

Single Alembic revision (schema not yet published, so fold into
`0001_initial.py` per AGENTS.md §11 — "since the schema is not yet
published"):

- `sandbox_templates` table (UUID PK, columns above).
- `sandbox_configs` table (UUID PK, FK to templates, encrypted
  `session_api_key`).
- `sandbox_snapshots` table (UUID PK, FK to templates).
- Add `sandbox_template_permission` / `sandbox_permission` /
  `sandbox_snapshot_permission` already exist on `roles` — no new entity
  columns needed (the governed names are unchanged). Confirm the
  `TestEntityColumnParity` test still passes after swapping the registered
  model type.

## Specs (Quint)

`specs/sandbox.qnt` already models a durable `Sandbox` + `Compute` split. The
plan aligns the implementation with that spec: `SandboxConfig` ≈ the durable
`sandbox` var, `Sandbox` (live) ≈ `Compute`. Update the spec to:

- rename `Sandbox` (durable) → `SandboxConfig` in the spec for clarity,
- drop `providerKind` from the durable record (provider is now a service
  config, not per-row),
- keep `Compute` as the live sandbox attachment,
- replace the `desired_status` reconcile invariant with an `enabled` flag:
  when `enabled` the live sandbox converges to active; when disabled the
  provider applies its deactivation strategy (pause / snapshot-and-delete).

## Tests

- New unit tests for the three DB services (happy + error path, per AGENTS.md
  §5), using the embedded PG + savepoint fixtures.
- Update `tests/unit/test_role_service.py::TestEntityColumnParity` for the
  swapped registered model types.
- Update `tests/unit/test_route_permissions.py` for the new
  `/sandbox/sandbox-configs` routes and the now-read-only
  `/sandbox/sandboxes`.
- E2E (Playwright): the sandbox create flow moves to configs; update flows.
- The embedded-PG fixtures + `clock_timestamp()` timestamps are already in
  place — no infra change.

## Phasing (suggested)

1. **DB models + migration + schemas** for templates/configs/snapshots
   (no behavior change yet; old service still drives live sandboxes).
2. **DB services + routers** for templates (with update) and configs; keep
   live-sandbox calls delegating to the existing `SandboxService` hooks.
3. **Slim `SandboxService`** to the reconciler interface; move Docker/K8s
   implementations onto it; startup image-pull-from-DB; stamp
   `sandbox_config_id` as provider metadata.
4. **Read-only `/sandbox/sandboxes`** enriched from live sandboxes (batched).
5. **Lifecycle sweep** reading from DB.
6. **Spec + test** cleanup.

## Resolved decisions

- **Q1** `max_memory` — kept as an optional column on `SandboxTemplate` (works
  in both Docker and K8s).
- **Q2** `sandbox_configs.sandbox_template_id` FK ondelete — **RESTRICT**
  (don't delete a template in use).
- **Q3** The sandbox id lives on the live `Sandbox`. `sandbox_config_id` is
  stored as provider metadata (Docker container label / K8s deployment
  annotation) by the service — not a DB column.
- **Q4** `GET /sandbox/sandboxes` lists `SandboxConfig` rows (DB-paginated,
  authz-scoped) and enriches them with live `Sandbox` state via **batched**
  service calls (`list_sandboxes(config_ids)`), never one get per config.
- **Q5** Snapshot lineage — **keep `sandbox_id` (source) as a nullable
  column** (null for snapshots imported from an uploaded file that did not
  come from a sandbox). The specifics of managing snapshot artifact files are
  hidden inside the sandbox service: in Docker a local file; in K8s possibly
  an S3 bucket. The DB row is the index; the service owns storage.
- **Q6** Image pull on new template — **background** (create returns 202, the
  pull runs async, status surfaced for polling).
- **Q7** Keep both `/sandbox/sandbox-configs` (durable intent) and
  `/sandbox/sandboxes` (read-only live view) — they are distinct surfaces.
- **Q8** `desired_status` is replaced by an `enabled: bool` flag on
  `SandboxConfig`. Disabling is provider-interpreted: Docker uses
  `OHE_SANDBOX_DEACTIVATE_MODE` (pause vs stop-and-recreate); K8s snapshots
  (if `snapshot_on_deactivate`) and deletes, recreating from
  `sandbox_snapshot_id` on re-enable. `SandboxConfig` carries an optional
  `sandbox_snapshot_id` for restore-on-(re)create.
- **Q9** `delete_after_idle_seconds` stays on the **template**. It translates
  to `expires_at` on `SandboxConfig` (the sweep sets/refreshes `expires_at`
  from the template's `delete_after_idle_seconds`); no per-config override.

## Open questions

None remaining.
