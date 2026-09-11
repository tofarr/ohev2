# Sandbox Subsystem

The sandbox subsystem provides isolated, ephemeral execution environments for
AI agents. It is built around a **database-as-source-of-truth** architecture:
durable intent (templates, configs, snapshots) lives in PostgreSQL as governed,
mutable resources, while the **live sandbox** (Docker container or Kubernetes
deployment) is reconciled to match that intent by a pluggable
`SandboxService` backend.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        REST API                              │
│  /sandbox/sandbox-templates   CRUD + batch + count + search  │
│  /sandbox/sandbox-configs     CRUD + batch + count + search  │
│  /sandbox/sandbox-snapshots   create/read/delete + batch     │
│  /sandbox/sandboxes           live read-only surface (list)  │
└───────────┬──────────────────────────────────┬──────────────┘
            │                                  │
     ┌──────▼──────┐                   ┌───────▼────────┐
     │  DB-backed   │                   │  SandboxService │
     │  services    │                   │  (ABC, pluggable)│
     │  (per-request│                   │  app-scoped     │
     │   session)   │                   │  async CM       │
     └──────┬──────┘                   └───┬────────┬────┘
            │                              │        │
     ┌──────▼──────┐              ┌────────▼┐  ┌───▼──────┐
     │ PostgreSQL  │              │ Docker   │  │ K8s      │
     │             │              │ backend  │  │ backend  │
     │ • templates │              └──────────┘  └──────────┘
     │ • configs   │
     │ • snapshots │
     └─────────────┘
```

## Core Concepts

### SandboxTemplate (`sandbox_templates` table)

A **provider-neutral, mutable** description of how to create a sandbox. It
carries:

- `docker_image_tag` — the image to pull/run (can change without orphaning
  configs, since the PK is a UUID, not the image name).
- Lifecycle knobs: `delete_after_idle_seconds`, `max_memory`,
  `in_container_user_id`, `in_container_group_id`.
- `exposed_ports` — JSONB list of `{name, description, container_port}`.
- `env_vars`, `working_dir` — container environment.
- `snapshot_dirs`, `snapshot_on_deactivate` — snapshot configuration.
- `meta` — JSONB for provider-specific hints (K8s annotations, Docker labels).

Templates are **mutable** — update the image tag or lifecycle knobs through
`PATCH /sandbox/sandbox-templates/{id}` without a redeploy. Deleting a
template referenced by a config returns **409 Conflict** (FK `RESTRICT`).

### SandboxConfig (`sandbox_configs` table)

The **durable intent** for a sandbox. This is the governed entity that drives
the reconciler:

- `sandbox_template_id` (FK → `sandbox_templates`, `ON DELETE RESTRICT`).
- `enabled: bool` — replaces the prior `desired_status`. `true` means the
  reconciler should ensure a live sandbox exists; `false` means it should be
  paused/stopped.
- `sandbox_snapshot_id` — optional snapshot to restore from on creation.
- `expires_at` — derived from the template's `delete_after_idle_seconds` by
  the lifecycle sweep; refreshed as the sandbox idles.
- `snapshot_on_deactivate` — if `true`, the reconciler captures a snapshot
  before deactivating.
- `session_api_key` — **encrypted** (JWE) at rest; never exposed in plaintext
  through the API (`SandboxConfigRead` omits it). The live `Sandbox` carries
  it for agent-server authentication.
- `meta` — JSONB for provider-specific overrides.

### SandboxSnapshot (`sandbox_snapshots` table)

A **DB index row** for a gzip-compressed tarball of a sandbox workspace. The
artifact itself is stored by the sandbox service (local file for Docker, S3
for K8s); the DB row only carries the `download_url`.

- `sandbox_template_id` — scopes the snapshot for restore compatibility.
- `sandbox_id` — nullable (null for snapshots imported from an uploaded file).
- `schema` — compatibility tag (e.g. `docker-workspace-tar-v1`).
- `size_bytes` — tarball size.

Snapshots are **create/read/delete only** (no update). Creating a snapshot
delegates artifact capture to `SandboxService.capture_snapshot()`. Snapshots
round-trip between Docker and K8s providers because the tarball store is
shared.

### Sandbox (live, read-only)

The live sandbox is an in-memory representation of a running (or paused, or
stopped) container/deployment. It is **not** stored in the DB — the
`SandboxService` owns it. The `/sandbox/sandboxes` endpoints are a read-only
live surface (list, get, batch read). Mutations (create/update/delete) go
through `SandboxConfig` — the reconciler brings the live sandbox in line.

## Sandbox Lifecycle States

```
inactive → activating → active → deactivating → inactive
                                    ↓
                                  deleting → (gone)

                  inactive → snapshotting → inactive
```

| State         | Description                                              |
|---------------|----------------------------------------------------------|
| `inactive`    | Not running. Filesystem may persist (paused or stopped). |
| `activating`  | Starting up (container start / K8s deployment create).   |
| `active`      | Running and reachable.                                   |
| `deactivating`| Being paused or stopped.                                 |
| `deleting`    | Being torn down (container/deployment removed).          |
| `snapshotting`| Workspace tarball being captured (quiescent state).      |
| `error`       | Unrecoverable failure.                                   |

## SandboxService (ABC)

The `SandboxService` is an abstract base class (`sandbox_service.py`)
constructed once at startup and held as an **app-scoped async context
manager** tied to the server lifespan. The concrete implementation is
selected via the `sandbox_service_class` config setting (a fully qualified
class name) and instantiated from `OHE_SANDBOX_*` environment variables.

### Backends

| Backend | Module                        | Artifact storage        |
|---------|-------------------------------|-------------------------|
| Docker  | `docker_sandbox_service.py`   | Local filesystem (tar)  |
| K8s     | `k8s_sandbox_service.py`      | S3 bucket (tar)         |

### Reconciler hooks (new)

The ABC defines three hooks that DB-backed services delegate to:

- `capture_snapshot(sandbox_id, template_id)` — captures a workspace tarball
  from a live sandbox and returns the `download_url`.
- `import_snapshot_file(template_id, file)` — imports an uploaded tarball as
  a snapshot.
- `delete_snapshot_artifact(download_url)` — removes the stored tarball.

Base implementations raise `SandboxSnapshotUnsupportedError`.

### Legacy CRUD surface

The ABC still carries the legacy template/sandbox CRUD methods (create, list,
get, update, delete, batch). These are being slimmed down in Phase 3 to a
pure reconciler that accepts `SandboxConfig` filters directly, removing the
transitional `cast()` in `sandbox_router.py`.

## Deactivation Modes (Docker)

The Docker backend supports two deactivation strategies via
`OHE_SANDBOX_DEACTIVATE_MODE`:

| Mode    | Command        | Memory      | Filesystem          |
|---------|----------------|-------------|---------------------|
| `pause` | `docker pause` | Frozen      | Frozen              |
| `stop`  | `docker stop`  | Lost        | Persists (writable) |

`pause` (default) uses the Docker cgroup freezer — memory and filesystem are
frozen in place. `stop` tears down processes (memory lost) but the writable
layer / bind mount persists, giving a fresh restart analogous to scaling a
K8s Deployment to zero.

## Workspace Bind Mount (Docker)

When `OHE_SANDBOX_WORKSPACE_DIR` is set, each sandbox is created with a bind
mount of `<workspace_dir>/<sandbox_id>` onto the container working directory
(`/home/openhands`), giving the sandbox a persistent workspace analogous to a
Kubernetes PVC. When `None`, the container writable layer is ephemeral.

## Lifecycle Sweep

A background `asyncio` loop (started by the service's `__aenter__`, tied to
app lifespan) enforces per-template lifespan knobs:

- `idle_pause_seconds` — pause/stop after this many seconds idle.
- `paused_delete_seconds` — delete after this many seconds paused.
- `max_age_seconds` — hard age limit regardless of activity.

The sweep interval is configured via `sandbox_lifecycle_interval`
(`= 0` disables the in-process loop; an external scheduler must drive it).
Pause stamps an `io.openhands.sandbox.paused_at` container label so the
paused-since time survives restarts; resume clears it.

`last_accessed_at` is derived from the container's agent-server root
endpoint (`GET /` → JSON `idle_time`): `last_accessed_at = now - idle_time`.
Best-effort — `null` when the sandbox is not `active`, unreachable, or the
payload lacks `idle_time`.

## Configuration

| Env var                           | Description                          | Default       |
|-----------------------------------|--------------------------------------|---------------|
| `OHE_SANDBOX_SERVICE_CLASS`       | Fully qualified `SandboxService` subclass | —        |
| `OHE_SANDBOX_DEACTIVATE_MODE`     | `pause` or `stop`                    | `pause`       |
| `OHE_SANDBOX_WORKSPACE_DIR`       | Bind-mount root for persistent workspaces | `None`   |
| `OHE_SANDBOX_SNAPSHOT_DIR`        | Tarball snapshot storage directory   | `~/.openhands/enterprise/snapshots` |
| `OHE_SANDBOX_LIFECYCLE_INTERVAL`  | Sweep loop interval (0 = disabled)   | —             |

All `OHE_SANDBOX_*` env vars are parsed onto the selected `SandboxService`
subclass via `from_env(service_class, "OHE_SANDBOX")`.

## RBAC / Auth

Each governed entity has its own permission column on `Role`
(see AGENTS.md §11):

| Entity           | Permission column              |
|------------------|--------------------------------|
| `SandboxTemplate`| `sandbox_template_permission`  |
| `SandboxConfig`  | `sandbox_permission`           |
| `SandboxSnapshot`| `sandbox_snapshot_permission`  |

`register_resource_policy` maps `SandboxConfig` (not the live `Sandbox`) to
`sandbox_permission` — the DB-backed config is the governed entity. The
`seed_db` admin role auto-grants `Permitted()` on all three columns.

## File Layout

All files are flat in this directory, prefixed with `sandbox_` or the
provider name (per AGENTS.md §4):

```
sandbox/
├── README.md                      ← this file
├── sandbox_models.py              ← Pydantic models (Sandbox, SandboxStatus, ExposedPort)
├── sandbox_schemas.py             ← request/response schemas for live sandboxes
├── sandbox_service.py             ← SandboxService ABC + exceptions
├── sandbox_router.py              ← /sandbox/sandboxes (live read-only)
├── sandbox_template_models.py     ← SandboxTemplate ORM (DB)
├── sandbox_template_schemas.py    ← template request/response schemas
├── sandbox_template_service.py    ← SandboxTemplateService (DB CRUD)
├── sandbox_template_router.py     ← /sandbox/sandbox-templates
├── sandbox_config_models.py       ← SandboxConfig ORM (DB)
├── sandbox_config_schemas.py      ← config request/response schemas
├── sandbox_config_service.py      ← SandboxConfigService (DB CRUD)
├── sandbox_config_router.py       ← /sandbox/sandbox-configs
├── sandbox_snapshot_models.py     ← SandboxSnapshot ORM (DB)
├── sandbox_snapshot_schemas.py    ← snapshot request/response schemas
├── sandbox_snapshot_service.py    ← SandboxSnapshotService (DB CRUD)
├── sandbox_snapshot_router.py     ← /sandbox/sandbox-snapshots
├── docker_sandbox_models.py       ← Docker-specific Pydantic models
├── docker_sandbox_service.py      ← DockerSandboxService implementation
├── k8s_sandbox_models.py          ← K8s-specific Pydantic models
└── k8s_sandbox_service.py         ← K8sSandboxService implementation
```
