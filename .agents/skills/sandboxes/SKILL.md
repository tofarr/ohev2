---
name: sandboxes
description: Sandbox provider interface, lifecycle sweep, deactivation modes, workspace bind mounts, tarball snapshots, and usage polling. Load when working on sandbox code.
version: "1.0.0"
---

# Sandboxes

* Sandbox operations go through the `SandboxProvider` interface only.
* A new backend implements the interface and registers via config — no scattering of
  backend-specific calls in services.
* Both ephemeral and persistent sandboxes are supported via the same interface.
* `Sandbox` carries a nullable `last_accessed_at`. The Docker backend derives it
  from the container's agent-server root endpoint (`GET /` → JSON `idle_time`):
  `last_accessed_at = now - idle_time`. Best-effort — `null` when the sandbox is
  not `active`, unreachable, or the payload lacks `idle_time`.
* A background lifecycle sweep enforces the per-template lifespan knobs
  (`idle_pause_seconds`, `paused_delete_seconds`, `max_age_seconds`). The sweep
  runs as an in-process `asyncio` loop started by the sandbox service's
  `__aenter__` (tied to the app lifespan), following the same `= 0` disables /
  external-scheduler-fallback convention as the LLM/MCP usage loops (config:
  `sandbox_lifecycle_interval`). Pause stamps an `io.openhands.sandbox.paused_at`
  container label so the paused-since time survives restarts; resume clears it.
* **Deactivation mode.** The Docker backend supports two deactivation
  strategies via `deactivate_mode` (env `OHE_SANDBOX_DEACTIVATE_MODE`):
  `pause` (default) uses the Docker cgroup freezer (`docker pause`) — memory
  and filesystem are frozen in place; `stop` uses `docker stop` then
  `docker start` on resume — processes are torn down (memory lost) but the
  writable layer / bind mount persists, giving a fresh restart analogous to
  scaling a Kubernetes Deployment to zero. This addresses the case where
  `docker pause` freezes both the filesystem and internal memory; `stop`
  stores only the filesystem and does a more thorough server restart.
* **Workspace bind mount.** The Docker backend accepts a `workspace_dir`
  (env `OHE_SANDBOX_WORKSPACE_DIR`, default `None`). When set, each sandbox
  is created with a bind mount of `<workspace_dir>/<sandbox_id>` onto the
  container working directory (`/home/openhands`), giving the sandbox a
  persistent workspace analogous to a Kubernetes PVC. When `None` the sandbox
  has no persistent workspace — its container writable layer is ephemeral.
* **Tarball snapshots.** Both the Docker and Kubernetes backends persist
  snapshots as gzip-compressed tarballs of the sandbox workspace directory,
  stored in `snapshot_dir` (env `OHE_SANDBOX_SNAPSHOT_DIR`, default
  `$HOME/.openhands/enterprise/snapshots`), replacing the previous
  `docker commit`-based image snapshots. This mirrors the Kubernetes
  VolumeSnapshot / PVC model: a snapshot is a tarball of the workspace;
  `SandboxCreate.snapshot_id` restores a snapshot's workspace into a new
  sandbox before it starts (analogous to creating a PVC from a
  VolumeSnapshot). Snapshots round-trip between the Docker and Kubernetes
  providers because the tarball store is shared. A new `SNAPSHOTTING`
  `SandboxStatus` covers the quiescent capture window
  (`inactive -> snapshotting -> inactive`). The shared tar/untar logic
  lives in `util/snapshot_store.py`.
* **Usage polling.** A background lifespan loop (config
  `sandbox_usage_interval`, env `OHE_SANDBOX_USAGE_INTERVAL`, default 60s;
  `= 0` disables with the external-scheduler fallback) lists sandboxes from
  the configured `SandboxService` and records one `sandbox_usage` row per
  claimed sandbox via `SandboxUsageService.record_usage`. Rows are keyed by
  `sandbox_config_id` (FK `ON DELETE RESTRICT` — a config with usage rows
  cannot be deleted; usage history outlives the sandbox) — the DB-backed
  config, not the provider sandbox id — so usage associates with the owning
  user and their groups through `sandbox_configs`; unclaimed warm-pool
  sandboxes are skipped. The table mirrors the llm/mcp usage pattern: it is
  range-partitioned by day on `created_at` (with a `DEFAULT` partition) and
  managed by a second lifespan loop (config `sandbox_usage_partition_interval`,
  env `OHE_SANDBOX_USAGE_PARTITION_INTERVAL`, default 300s) calling
  `SandboxUsageService.ensure_partitions`, which pre-creates
  `sandbox_usage_preallocate_days` (default 7) future daily partitions and
  drops partitions older than `sandbox_usage_retention_days` (default 365).
  Unlike llm/mcp there is no aggregated projection / aggregator loop, and
  the table is not exposed over REST; `cpu`/`disk` are nullable floats left
  NULL until `Sandbox` carries resource stats and the providers populate
  them.
