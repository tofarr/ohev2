# Warm Sandboxes

## Goal

Keep a per-template pool of **pre-provisioned** sandbox resources ("warm
sandboxes") so that a `POST /sandbox/sandboxes` with no `snapshot_id` is
served by claiming one of them rather than cold-starting. Creating a new
sandbox from scratch only happens when the warm pool for that template is
empty, or when a `snapshot_id` is supplied (snapshot restore needs a special
create path; fuse-mount bypass is a future enhancement).

## Design principles (confirmed)

1. **`sandbox_config_id` is a required part of sandbox creation**, stored in
   the sandbox's provider metadata (K8s label) or encoded in its name
   (Docker, where labels are immutable), and searchable. Warm resources are
   pre-created from a template **without** a config; at claim time the warm
   marker transitions atomically (K8s label patch / Docker rename) **and**
   the request's `sandbox_config_id` is recorded. So warm matching stays
   per-template, and config association is attached at claim.
2. **Warm resources carry an explicit `warm` marker** in provider metadata
   while in the pool. They are provider resources waiting to be claimed and
   are excluded from `_list_sandboxes` / the public sandbox surface. **At
   claim the marker transitions atomically** — K8s removes the `warm` label
   via a `resourceVersion`-conditional patch and adds `sandbox_config_id`;
   Docker `rename`s the container from `OHE_<sandbox_id>` (warm) to
   `OHE_<sandbox_id>_<sandbox_config_id>` (claimed) — labels are immutable in
   Docker, so the name is the mutable token (any non-`OHE_`-prefixed name is
   foreign and left alone). The same provider resource becomes a normal
   sandbox; they only become a `Sandbox` at claim time.
   - **K8s has no real `inactive` state**: a warm Deployment runs at
     `replicas=1` (running, marked warm) until claimed.
   - **Docker**: warm containers are `paused` while waiting (cheap), then
     `unpause`d at claim.
3. **Per-template pool.** `num_warm` is a per-template target; warm resources
   are template-specific (image/env differ). Not a global pool.
4. **Schema not yet published** → `num_warm` is added directly to
   `0001_initial.py`, not as a new migration file.

## Architecture context (post-merge of `origin/main`)

- `SandboxService` ABC is an **app-scoped singleton, no DB access**, built
  from `OHE_SANDBOX_*` env vars. `create_sandbox` → `_sandbox_from_create`
  (perm-scope check) → `_create_sandbox(snapshot_id)`. It owns a
  self-contained lifecycle sweep loop started in `__aenter__`.
- **Newly merged**: `SandboxService.refresh_templates(image_tags)` (base
  no-op) is called by `__aenter__` and by `SandboxTemplateService` after any
  template mutation. The Docker backend background-pulls referenced images.
  The `SandboxTemplateService` is DB-aware and notifies the (DB-free) service.
- `SandboxTemplate` (DB, source of truth, mutable) has lifecycle knobs. Docker
  reads knobs from image labels; K8s from ConfigMaps.
- Background loops follow the **`= 0` disables** convention
  (`sandbox_lifecycle_interval`, LLM/MCP usage loops in `app.py`).
- `SandboxConfig` is durable intent, not yet linked to the live `Sandbox`.

The warm refresh mirrors the merged `refresh_templates` pattern: a
**DB-driven loop passes targets** to a DB-free service method. Docker
therefore needs no `num_warm` image label and K8s needs no `num_warm`
ConfigMap key — the loop supplies the targets. This avoids touching provider
inventory entirely.

## Changes by file

### 1. `sandbox_template_models.py` + `sandbox_template_schemas.py`

Add `num_warm: int = 0` to `SandboxTemplate` (ORM column,
`server_default="0"`, non-negative, `ge=0`). Add the field to
`SandboxTemplateCreate`, `SandboxTemplateUpdate`, and `SandboxTemplateRead`.
`SandboxTemplateService` copies it generically on create/update (no
special-case needed beyond the field set).

### 2. `alembic/versions/0001_initial.py`

Add the `num_warm` column to the `sandbox_templates` `create_table` block:
`sa.Column("num_warm", sa.Integer(), server_default="0", nullable=False)`.

### 3. `sandbox_schemas.py` + `sandbox_models.py` + `sandbox_service.py` (ABC)

- **`Sandbox` model**: add `sandbox_config_id: str | None = None` (null while
  a warm resource waits in the pool; set at claim. Returned sandboxes always
  have it set because warm resources are filtered out of the public surface).
  Same string-as-UUID convention as `sandbox_template_id`.
- **`SandboxCreate`**: add a **required** `sandbox_config_id: str` field
  (`min_length=1`, `max_length=64`). The sandbox's config association is
  supplied by every create request.
- **`SandboxRead`**: add `sandbox_config_id: str | None`.
- **`SandboxSearchFilter`**: add `sandbox_config_id__eq: str | None`.
- New provider hooks (base implementations are no-ops / return `None` so
  unsupported providers decline cleanly):
  - `async def _claim_warm_sandbox(self, template_id: str, *, config_id: str) -> Sandbox | None`
    — base returns `None` (no warm pool). On success the provider has performed
    its atomic claim transition (K8s: `resourceVersion`-conditional label
    patch; Docker: daemon-serialized `rename`), recorded the `config_id`
    association, activated the resource (Docker unpause; K8s already running),
    and returns it as a `Sandbox` with `sandbox_config_id` set.
  - `async def _count_warm(self, template_id: str) -> int` — base returns `0`.
  - `async def _create_warm(self, template_id: str) -> None` — base no-op.
  - `async def _delete_warm(self, template_id: str) -> None` — base no-op.
    Deletes one warm resource for the template.
- New public method:
  - `async def refresh_warm_sandboxes(self, targets: dict[str, int]) -> str | None`
    — generic over the hooks. For each `(template_id, num_warm)`:
    `count = await self._count_warm(template_id)`; while `count < num_warm`:
    `await self._create_warm(template_id)`; `count += 1`; while
    `count > num_warm`: `await self._delete_warm(template_id)`; `count -= 1`.
    Returns a one-line summary. Idempotent.
- Modify `create_sandbox`: when `payload.snapshot_id is None`, first
  `sandbox = await self._claim_warm_sandbox(payload.sandbox_template_id, config_id=payload.sandbox_config_id)`;
  if non-`None`, return it (perm-scope re-checked against the resulting
  `Sandbox`). If `None`, fall back to the existing
  `_create_sandbox(snapshot_id=None)` path (which must also record
  `sandbox_config_id` per its provider's mechanism — K8s label at create;
  Docker name encoding at create). When `snapshot_id` is set, always take the
  existing special-create path (warm pool bypassed), likewise recording
  `sandbox_config_id`. In both cold paths no `warm` marker is ever set — only
  `_create_warm` sets it.
  - Claim atomicity: provider-specific (see "Claim atomicity"). K8s uses a
    `resourceVersion`-conditional PATCH (true CAS, multi-process safe, no
    in-process lock). Docker uses daemon-serialized `docker rename` as the CAS
    (multi-process safe), with an `asyncio.Lock` only to reduce same-process
    wasted retries on the select-then-rename window.

### 4. `docker_sandbox_service.py`

Docker container labels are **immutable after creation** (no API to change
them); `docker rename` is the atomic claim primitive. See "Claim
atomicity" for the full rationale.

- **Naming convention** (the authoritative ownership + state marker for
  Docker, replacing the earlier `warm` label):
  - Warm: `OHE_<sandbox_id>` (sandbox_id known at warm-create; config not yet).
  - Claimed: `OHE_<sandbox_id>_<sandbox_config_id>` (config_id appended at claim).
  - Both `sandbox_id` and `sandbox_config_id` are UUIDs (use `-`), so the
    name splits unambiguously on `_`: `["OHE", sid]` → warm;
    `["OHE", sid, cid]` → claimed. **Any container whose name does not start
    with `OHE_` is foreign and is left entirely alone** (not listed, not
    claimed, not swept, not deleted).
- Labels:
  - `_TAG_SANDBOX_TEMPLATE_ID` (existing, immutable, set once at create) —
    needed to scope warm candidates by template (the name doesn't carry
    template info).
  - The read-only `_TAG_WARM` label is **dropped**: warm-vs-claimed is now
    encoded in the name, and the name is the single source of truth.
- Warm create (`_create_warm`): run a container from the template image,
  **paused**, named `OHE_<sandbox_id>`, stamped with
  `_TAG_SANDBOX_TEMPLATE_ID`. The sandbox_id is minted at warm-create and is
  stable across the later rename (rename changes the name, not the id); the
  workspace bind-mount dir is keyed by it, so it's unchanged at claim.
- `_claim_warm_sandbox(template_id, *, config_id)`: list paused containers
  with the template label and names matching `OHE_<...>` with a single
  payload segment (warm); for the oldest, `docker rename` it to
  `OHE_<sandbox_id>_<config_id>`. Rename is daemon-serialized; on
  `NotFound`/`Conflict` (lost the race) try the next candidate. Then
  `unpause` and return the `DockerSandbox` with `sandbox_config_id` parsed
  from the name. Returns `None` when no candidate survives.
- `_count_warm`: count containers matching template label + warm name shape.
- `_delete_warm`: remove one warm paused container (force) + its workspace dir.
- Cold `_sync_create_sandbox` (snapshot or empty pool): name the container
  `OHE_<sandbox_id>_<config_id>` directly (claimed shape from the start — no
  warm rename). `config_id` is parsed from the name in both paths for
  consistency.
- `_sync_list_sandboxes` / `_sandbox_from_container_attrs`: keep only names
  of claimed shape (`OHE_<sid>_<cid>`, two payload segments). Filter out
  warm names (`OHE_<sid>`) and all non-`OHE_` names. Parse `sandbox_id` and
  `sandbox_config_id` from the name.
- `_lifecycle_action`: warm and foreign containers are excluded from the
  list, so the sweep only ever sees claimed sandboxes. (Defensive explicit
  skip kept for clarity.)
- Same-process `asyncio.Lock` serializes the select-then-rename window so
  two coroutines don't waste a rename on the same candidate (correctness is
  already guaranteed by the daemon-serialized rename).

### 5. `k8s_sandbox_service.py`

K8s labels **are** mutable and `resourceVersion` gives a true CAS, so the
warm marker is a real label and the claim is a conditional patch (no
in-process lock). See "Claim atomicity" for the full rationale.

- New labels:
  - `_LABEL_WARM = "io.openhands.sandbox/warm"` (value `"true"` while in the
    pool; removed at claim).
  - `_LABEL_SANDBOX_CONFIG_ID = "io.openhands.sandbox/sandbox-config-id"`.
- Warm create (`_create_warm`): create the Deployment at `replicas=1`
  (running, ready to claim), the PVC, and the Service, all stamped with
  `_LABEL_SANDBOX_ID` (minted) + `_LABEL_WARM="true"`. No real inactive state
  — it runs while waiting. No `sandbox-config-id` label yet.
- `_claim_warm_sandbox(template_id, *, config_id)`: list Deployments with
  template + `warm` label; for the oldest candidate, read it to capture
  `resourceVersion=R` and confirm `warm=true`, then `PATCH` (strategic-merge)
  removing `warm` and adding `sandbox-config-id=<config_id>` with the version
  pinned to `R`. On **409 Conflict** (lost the race) try the next candidate.
  The Deployment is already running, so return the `K8sSandbox` with
  `sandbox_config_id` set. Returns `None` when no candidate survives.
- `_count_warm`: count matching warm Deployments.
- `_delete_warm`: delete one warm Deployment + its PVC + Service.
- Cold `_sync_create_sandbox` (snapshot or empty pool): create the Deployment
  with `_LABEL_SANDBOX_CONFIG_ID` set from the create payload (no `warm`
  label).
- `_sync_list_sandboxes` / `_sandbox_from_deployment`: **filter out**
  Deployments carrying the `warm` label. Read `sandbox_config_id` from the
  `_LABEL_SANDBOX_CONFIG_ID` label for the returned `K8sSandbox`.
- `sweep_lifecycle`: warm Deployments are excluded from the list, so the
  sweep never sees them.
- No `asyncio.Lock` — the `resourceVersion` CAS makes claim multi-process
  safe.
- No `num_warm` in `_K8sTemplateSpec` or ConfigMap — the refresh loop passes
  targets.

### 6. `app.py` — warm refresh loop

Add `_warm_sandbox_loop()` alongside the existing lifespan loops, following
the `= 0` disables convention. On each tick it opens a short-lived DB
session, selects `(id, num_warm)` for all `SandboxTemplate`s, builds
`targets = {str(t.id): t.num_warm for t in templates if t.num_warm > 0}`, and
calls `sandbox_service.refresh_warm_sandboxes(targets)`. Failures are logged
and retried next tick (same pattern as the lifecycle sweep).

Config: `sandbox.warm_refresh_interval` (`OHE_SANDBOX_WARM_REFRESH_INTERVAL`,
float seconds, `0` disables → external scheduler must call
`refresh_warm_sandboxes`). Default `60.0` to match
`sandbox_lifecycle_interval`.

Optionally, `SandboxTemplateService` can also trigger a warm refresh after a
template mutation (it already calls `refresh_templates`); out of scope unless
trivial — the loop converges within one interval.

### 7. `specs/sandbox.qnt` (Quint)

- Add a `Warm` marker concept on `Compute` state (or a separate warm pool
  set) and a `claimWarm` action that transitions a warm compute to a sandbox's
  `currentComputeId` and stamps its `sandbox_config_id` (reuse the existing
  `finishActivate` shape but the compute pre-exists with the `warm` marker,
  which is removed at claim).
- Add `refreshWarm(templateId, numWarm)` that ensures the warm-count for a
  template equals `numWarm` (create/delete warm computes).
- Invariant: a warm compute is not subject to `sweepPauseIdle` /
  `sweepDeletePaused` (the sweep only operates on sandboxes with owners).
- Add runs: `claimWarmServesSandbox`, `refreshMaintainsWarmCount`,
  `snapshotBypassesWarm` (createFromSnapshot does not consume a warm compute).

### 8. Tests

Real code paths, no mocks (per repo rules):
- `refresh_warm_sandboxes` idempotency: count up to `num_warm`, no-op when
  already at target, deletes excess down to target.
- `create_sandbox` with no `snapshot_id` claims a warm resource when the pool
  is non-empty; falls back to cold create when empty.
- `create_sandbox` with `snapshot_id` bypasses the warm pool (cold create with
  restore).
- `_list_sandboxes` excludes warm resources and foreign resources (K8s:
  carrying the `warm` label; Docker: name is `OHE_<sid>` warm shape or lacks
  the `OHE_` prefix).
- Lifecycle sweep never touches warm resources (Docker paused warm containers
  / K8s running warm Deployments survive an idle sweep).
- Claim transitions the warm marker atomically and records `sandbox_config_id`;
  the same provider resource then appears in `_list_sandboxes` (K8s: label
  patch; Docker: rename to `OHE_<sid>_<cid>`).
- Provider hook coverage for both Docker and K8s, including claim-race
  coverage: K8s 409-on-conflict retry picks the next candidate; Docker
  rename `NotFound`/`Conflict` retry picks the next candidate; no two
  callers end up claiming the same resource.

### 9. Docs

`src/openhands/ev2/sandbox/README.md` + `AGENTS.md` §8 (Sandboxes):
- Document `num_warm`; the `OHE_` naming convention for Docker (warm
  `OHE_<sid>`, claimed `OHE_<sid>_<cid>`, non-`OHE_` names left alone) and the
  K8s `warm` label semantics; the `sandbox_config_id` create field + search
  filter; the refresh loop and `OHE_SANDBOX_WARM_REFRESH_INTERVAL`; the
  snapshot-bypass rationale; and the fuse-mount future note that will lift the
  snapshot constraint so warm resources can serve snapshot restores too.

## Open questions / future work

- **Fuse-mount bypass is a future change, explicitly out of scope for this
  plan.** Warm resources will not serve `snapshot_id` creates in this work;
  snapshot restores always take the cold-create path. Fuse-based mounts that
  overlay a snapshot onto an already-running warm container would lift this
  constraint later.
- **Multi-process claim safety** — resolved per provider (see "Claim
  atomicity"): K8s uses `resourceVersion`-conditional PATCH (true CAS);
  Docker uses daemon-serialized `rename` (CAS on the container name). Both
  are multi-process safe. The only residual single-process concern is Docker's
  `asyncio.Lock`, used merely to avoid wasted same-process retries — not for
  correctness. No external lock/lease is needed.

## Claim atomicity (the "update if value ==" question)

The goal is a single atomic compare-and-set on the warm marker so two
processes cannot claim the same resource. The answer differs per provider
because of what their API actually lets you mutate:

### Kubernetes — true CAS via `resourceVersion` (multi-process safe)

K8s labels **are** mutable and the API gives a real optimistic-concurrency
primitive. The claim is a conditional patch:

1. `read_namespaced_deployment(warm candidate)` → capture
   `metadata.resourceVersion = R` and confirm `warm=true`.
2. `PATCH` the Deployment (strategic-merge) removing `warm` and adding
   `sandbox-config-id`, passing `resourceVersion=R` (or the
   `V1Patch` with the version pinned). The apiserver rejects the write with
   **409 Conflict** if anything changed the object between the read and the
   write — i.e. another process claimed it.
3. On 409, the candidate lost the race; retry with the next warm candidate.

This is exactly "update if value == <the version I read>, then check the
result", and it is safe across processes without any in-process lock. The
`asyncio.Lock` is therefore **not** needed for K8s claim (refresh-create is
still lock-free: creating a Deployment cannot collide with a claim of an
existing one). We drop the K8s `asyncio.Lock`.

### Docker — no mutable-label API; use `rename` as the CAS

Docker container **labels are immutable after creation** — there is no
`PUT /containers/{id}` and `POST /containers/{id}/update` only changes
resource limits, not labels. (The existing code's
`container.attrs["Config"]["Labels"][...] = ...` mutates the in-memory Python
dict and never persists to the daemon; it is a latent no-op we should flag
and stop relying on.) So "remove the warm label + add a config_id label at
claim" is not expressible against the Docker API.

The atomic primitive Docker *does* offer is **`POST /containers/{id}/rename`**,
which the daemon serializes and which is namespaced-unique: two callers
renaming to the same target name cannot both succeed. So Docker uses the
container **name** as the warm marker, the ownership boundary, and the claim
token. The name follows an `OHE_`-prefixed convention:

- Warm containers are created as `OHE_<sandbox_id>`; claimed containers are
  `OHE_<sandbox_id>_<sandbox_config_id>`. Since the ids are UUIDs (dashes),
  splitting on `_` distinguishes warm (one payload segment) from claimed
  (two). **Any name not starting with `OHE_` is foreign and untouched.**
- Claim = `docker rename OHE_<sandbox_id> OHE_<sandbox_id>_<config_id>`.
  Rename is atomic and daemon-serialized; the losing caller gets `NotFound`
  (the source name is gone — someone else claimed it) or `Conflict` (target
  taken) → try the next warm candidate. `config_id` is then parsed from the
  resulting name, so no mutable label is needed for it. The read-only `_TAG_WARM`
  label is dropped — the name encodes warm-vs-claimed.
  - Because the workspace bind-mount dir is keyed by sandbox id, the warm
    container's id is minted at warm-create and the rename keeps the same id
    (rename changes the *name*, not the id); the workspace dir is unchanged.
- `_count_warm` / `_list_warm` select candidates by the template label (set
  at create) plus the warm name shape (`OHE_<sid>`).

> Net: Docker claim safety is provided by the daemon-serialized `rename`, not
> by an in-process lock. An `asyncio.Lock` is still kept to serialize the
> *select-then-rename* window within a single process so two coroutines in the
> same process don't both attempt the same candidate (the rename would make
> one fail anyway, but the lock avoids needless errors). Multi-process Docker
> is safe via the rename CAS; no external lock is required for correctness
> (only to reduce wasted retries).

### Summary table

| Provider | Warm marker        | Claim atomic op               | Multi-process safe | Needs asyncio.Lock |
|----------|--------------------|-------------------------------|--------------------|--------------------|
| K8s      | `warm` label       | `resourceVersion`-conditional PATCH (409 on race) | yes | no |
| Docker   | `OHE_<sid>` name (1 payload segment; claimed = `OHE_<sid>_<cid>`, 2 segments; non-`OHE_` names ignored) | `docker rename` (daemon-serialized, loser gets NotFound/Conflict) | yes | only to reduce same-process wasted retries |


## Task list

1. `num_warm` on `SandboxTemplate` (model, schema, migration).
2. `sandbox_config_id` on `SandboxCreate` (required) / `Sandbox` /
   `SandboxRead` / `SandboxSearchFilter`; ABC warm hooks +
   `refresh_warm_sandboxes` + `create_sandbox` claim path.
3. Docker backend: `OHE_<sid>` (warm) / `OHE_<sid>_<cid>` (claimed) naming
   convention, `docker rename` CAS claim, warm create/claim/count/delete,
   name-based list filter (non-`OHE_` names ignored), sweep skip,
   same-process lock. Drop the read-only `_TAG_WARM` label. Fix/flag the
   in-memory-only label-mutation no-op in the existing code.
4. K8s backend: `warm` + `sandbox-config-id` labels, `resourceVersion`
   CAS claim (no in-process lock), warm create/claim/count/delete, list
   filter, sweep skip.
5. App-lifespan warm refresh loop + config.
6. Quint spec update.
7. Tests (unit + provider hooks; include claim-race coverage + foreign-name
   isolation coverage).
8. Docs.


