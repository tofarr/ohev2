// Sandbox lifecycle specification.
//
// Models the v2 sandbox split:
//   - Sandbox is durable user-facing state with provider-neutral public states.
//   - Compute is an internal replaceable attachment that may come from a warm pool.
//   - Snapshots are named pins of Fusey filesystem generations.
//
// Public sandbox states are intentionally provider-neutral:
// inactive -> activating -> active -> deactivating -> inactive, with deleting
// and error transitions. Docker/Kubernetes/E2B-specific terms are not exposed.

module sandbox {
  type ProviderKind = Docker | Kubernetes | E2B
  type StorageKind = Fusey | OtherStorage

  type SandboxState = Inactive | Activating | Active | Deactivating | Deleting | Error
  type ComputeState = Warming | Dormant | Claimed | Mounting | Initializing | Serving | Draining | Released | Failed | Deleted
  type SnapshotState = Creating | Ready | SnapshotDeleting | SnapshotError

  type Sandbox = {
    id: str,
    owner: str,
    providerKind: ProviderKind,
    filesystemId: str,
    currentComputeId: str,
    currentSnapshotId: str,
  }

  type Compute = {
    id: str,
    providerKind: ProviderKind,
    sandboxId: str,
    state: ComputeState,
  }

  type Snapshot = {
    id: str,
    filesystemId: str,
    storageKind: StorageKind,
    generation: str,
    state: SnapshotState,
  }

  var sandboxes: Set[Sandbox]
  var states: str -> SandboxState
  var computes: Set[Compute]
  var snapshots: Set[Snapshot]

  action init = all {
    sandboxes' = Set(),
    states' = Map(),
    computes' = Set(),
    snapshots' = Set(),
  }

  def sandboxExists(id: str): bool = sandboxes.exists(s => s.id == id)
  def noSandbox(id: str): bool = not(sandboxExists(id))
  def computeExists(id: str): bool = computes.exists(c => c.id == id)
  def noCompute(id: str): bool = not(computeExists(id))
  def snapshotExists(id: str): bool = snapshots.exists(s => s.id == id)

  action create(s: Sandbox): bool = all {
    noSandbox(s.id),
    s.owner != "",
    s.filesystemId != "",
    s.currentComputeId == "",
    sandboxes' = sandboxes.union(Set(s)),
    states' = states.set(s.id, Inactive),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  action beginActivate(id: str): bool = all {
    states.keys().contains(id),
    states.get(id) == Inactive or states.get(id) == Error,
    sandboxes.exists(s => s.id == id and s.currentComputeId == ""),
    sandboxes' = sandboxes,
    states' = states.set(id, Activating),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  action finishActivate(id: str, computeId: str, providerKind: ProviderKind): bool = all {
    states.keys().contains(id),
    states.get(id) == Activating,
    noCompute(computeId),
    sandboxes.exists(s => s.id == id and s.providerKind == providerKind),
    sandboxes' = sandboxes.map(s =>
      if (s.id == id)
        { id: s.id, owner: s.owner, providerKind: s.providerKind,
          filesystemId: s.filesystemId, currentComputeId: computeId,
          currentSnapshotId: s.currentSnapshotId }
      else
        s),
    states' = states.set(id, Active),
    computes' = computes.union(Set({ id: computeId, providerKind: providerKind, sandboxId: id, state: Serving })),
    snapshots' = snapshots,
    true
  }

  action beginDeactivate(id: str): bool = all {
    states.keys().contains(id),
    states.get(id) == Active or states.get(id) == Error,
    sandboxes.exists(s => s.id == id and s.currentComputeId != ""),
    sandboxes' = sandboxes,
    states' = states.set(id, Deactivating),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  action finishDeactivate(id: str): bool = all {
    states.keys().contains(id),
    states.get(id) == Deactivating,
    sandboxes.exists(s => s.id == id and s.currentComputeId != ""),
    computes' = computes.map(c =>
      if (sandboxes.exists(s => s.id == id and s.currentComputeId == c.id))
        { id: c.id, providerKind: c.providerKind, sandboxId: "", state: Released }
      else
        c),
    sandboxes' = sandboxes.map(s =>
      if (s.id == id)
        { id: s.id, owner: s.owner, providerKind: s.providerKind,
          filesystemId: s.filesystemId, currentComputeId: "",
          currentSnapshotId: s.currentSnapshotId }
      else
        s),
    states' = states.set(id, Inactive),
    snapshots' = snapshots,
    true
  }

  action markError(id: str): bool = all {
    states.keys().contains(id),
    states.get(id) != Deleting,
    sandboxes' = sandboxes,
    states' = states.set(id, Error),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  action beginDelete(id: str): bool = all {
    states.keys().contains(id),
    states.get(id) != Deleting,
    sandboxes' = sandboxes,
    states' = states.set(id, Deleting),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  action finishDelete(id: str): bool = all {
    states.keys().contains(id),
    states.get(id) == Deleting,
    sandboxes' = sandboxes.filter(s => s.id != id),
    states' = states.keys().filter(k => k != id).fold(
      Map(),
      (acc, k) => acc.set(k, states.get(k))
    ),
    computes' = computes.map(c =>
      if (c.sandboxId == id)
        { id: c.id, providerKind: c.providerKind, sandboxId: "", state: Deleted }
      else
        c),
    snapshots' = snapshots,
    true
  }

  action createSnapshot(id: str, snap: Snapshot): bool = all {
    sandboxExists(id),
    not(snapshotExists(snap.id)),
    snap.storageKind == Fusey,
    snap.generation != "",
    sandboxes.exists(s => s.id == id and s.filesystemId == snap.filesystemId),
    snapshots' = snapshots.union(Set(snap)),
    sandboxes' = sandboxes.map(s =>
      if (s.id == id)
        { id: s.id, owner: s.owner, providerKind: s.providerKind,
          filesystemId: s.filesystemId, currentComputeId: s.currentComputeId,
          currentSnapshotId: snap.id }
      else
        s),
    states' = states,
    computes' = computes,
    true
  }

  action noop: bool = all {
    sandboxes' = sandboxes,
    states' = states,
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  action step: bool = noop

  val statesConsistent: bool =
    sandboxes.forall(s => states.keys().contains(s.id))

  val ownershipRequired: bool =
    sandboxes.forall(s => s.owner != "")

  val activeHasServingCompute: bool =
    sandboxes.forall(s =>
      states.get(s.id) == Active implies
        (s.currentComputeId != "" and
          computes.exists(c => c.id == s.currentComputeId and c.sandboxId == s.id and c.state == Serving)))

  val inactiveHasNoCompute: bool =
    sandboxes.forall(s => states.get(s.id) == Inactive implies s.currentComputeId == "")

  val computeAttachedToAtMostOneSandbox: bool =
    computes.forall(c1 => computes.forall(c2 => c1.id == c2.id implies c1 == c2))

  val snapshotsHaveFuseyGeneration: bool =
    snapshots.forall(s => s.storageKind == Fusey and s.generation != "")

  val currentSnapshotValid: bool =
    sandboxes.forall(s =>
      s.currentSnapshotId == "" or
        snapshots.exists(sn => sn.id == s.currentSnapshotId and sn.filesystemId == s.filesystemId))

  run createStartsInactive = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "" }))
      .then(all {
        assert(states.get("sb1") == Inactive),
        noop
      })
  }

  run activateLifecycle = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "" }))
      .then(beginActivate("sb1"))
      .then(all {
        assert(states.get("sb1") == Activating),
        noop
      })
      .then(finishActivate("sb1", "c1", Docker))
      .then(all {
        assert(states.get("sb1") == Active),
        assert(activeHasServingCompute),
        noop
      })
  }

  run deactivateReleasesCompute = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "" }))
      .then(beginActivate("sb1"))
      .then(finishActivate("sb1", "c1", Docker))
      .then(beginDeactivate("sb1"))
      .then(all {
        assert(states.get("sb1") == Deactivating),
        noop
      })
      .then(finishDeactivate("sb1"))
      .then(all {
        assert(states.get("sb1") == Inactive),
        assert(inactiveHasNoCompute),
        assert(computes.exists(c => c.id == "c1" and c.state == Released)),
        noop
      })
  }

  run cannotActivateActiveSandbox = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "" }))
      .then(beginActivate("sb1"))
      .then(finishActivate("sb1", "c1", Docker))
      .then(beginActivate("sb1"))
      .fail()
  }

  run snapshotPinsFuseyGeneration = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "" }))
      .then(createSnapshot("sb1", { id: "sn1", filesystemId: "fs1", storageKind: Fusey,
        generation: "generation-1", state: Ready }))
      .then(all {
        assert(snapshotsHaveFuseyGeneration),
        assert(currentSnapshotValid),
        noop
      })
  }

  run deleteRemovesSandbox = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "" }))
      .then(beginDelete("sb1"))
      .then(all {
        assert(states.get("sb1") == Deleting),
        noop
      })
      .then(finishDelete("sb1"))
      .then(all {
        assert(not(sandboxExists("sb1"))),
        noop
      })
  }
}
