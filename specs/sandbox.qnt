// Sandbox lifecycle specification.
//
// Models the sandbox split:
//   - Sandbox is durable user-facing state with provider-neutral public states.
//   - Compute is an internal replaceable attachment that may come from a warm pool.
//   - Snapshots are gzip tarballs of the sandbox workspace, analogous to a
//     Kubernetes VolumeSnapshot of a PVC. Snapshots round-trip between providers.
//
// Public sandbox states are intentionally provider-neutral:
// inactive -> activating -> active -> deactivating -> inactive, with deleting
// and error transitions. A snapshot capture briefly enters a `snapshotting`
// state (the workspace must be quiescent for a consistent tarball):
// inactive -> snapshotting -> inactive. Docker/Kubernetes/E2B-specific terms
// are not exposed.

module sandbox {
  type ProviderKind = Docker | Kubernetes | E2B
  type StorageKind = TarballStore | OtherStorage

  // Optional epoch-seconds timestamp; Absent when unknown / not applicable.
  type OptInt = Present(int) | Absent

  type SandboxState = Inactive | Activating | Active | Deactivating | Deleting | Snapshotting | Error
  type ComputeState = Warming | Dormant | Claimed | Mounting | Initializing | Serving | Draining | Released | Failed | Deleted
  type SnapshotState = Creating | Ready | SnapshotDeleting | SnapshotError

  type Sandbox = {
    id: str,
    owner: str,
    providerKind: ProviderKind,
    filesystemId: str,
    currentComputeId: str,
    currentSnapshotId: str,
    lastAccessedAt: OptInt,  // Present(epoch) when probed; Absent when unknown
    pausedAt: OptInt,        // Present(epoch) when sweep paused; Absent when active
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
    archivePath: str,
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

  pure def isPresent(o: OptInt): bool =
    match o {
      | Present(_) => true
      | Absent => false
    }
  pure def value(o: OptInt): int =
    match o {
      | Present(v) => v
      | Absent => 0
    }

  action create(s: Sandbox): bool = all {
    noSandbox(s.id),
    s.owner != "",
    s.filesystemId != "",
    s.currentComputeId == "",
    s.lastAccessedAt == Absent,
    s.pausedAt == Absent,
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
          currentSnapshotId: s.currentSnapshotId,
          lastAccessedAt: s.lastAccessedAt, pausedAt: Absent }
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
          currentSnapshotId: s.currentSnapshotId,
          lastAccessedAt: s.lastAccessedAt, pausedAt: s.pausedAt }
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

  // Begin a snapshot capture: the sandbox must be Inactive (workspace
  // quiescent) and transitions to Snapshotting. The snapshot record is added
  // in the Creating state. finishSnapshot moves the snapshot to Ready and the
  // sandbox back to Inactive.
  action beginSnapshot(id: str, snap: Snapshot): bool = all {
    sandboxExists(id),
    not(snapshotExists(snap.id)),
    snap.storageKind == TarballStore,
    snap.archivePath != "",
    sandboxes.exists(s => s.id == id and s.filesystemId == snap.filesystemId),
    states.get(id) == Inactive,
    snapshots' = snapshots.union(Set({ id: snap.id, filesystemId: snap.filesystemId,
      storageKind: snap.storageKind, archivePath: snap.archivePath, state: Creating })),
    sandboxes' = sandboxes.map(s =>
      if (s.id == id)
        { id: s.id, owner: s.owner, providerKind: s.providerKind,
          filesystemId: s.filesystemId, currentComputeId: s.currentComputeId,
          currentSnapshotId: snap.id,
          lastAccessedAt: s.lastAccessedAt, pausedAt: s.pausedAt }
      else
        s),
    states' = states.set(id, Snapshotting),
    computes' = computes,
    true
  }

  action finishSnapshot(id: str, snapId: str): bool = all {
    sandboxExists(id),
    snapshotExists(snapId),
    states.get(id) == Snapshotting,
    snapshots' = snapshots.map(sn =>
      if (sn.id == snapId)
        { id: sn.id, filesystemId: sn.filesystemId, storageKind: sn.storageKind,
          archivePath: sn.archivePath, state: Ready }
      else
        sn),
    states' = states.set(id, Inactive),
    sandboxes' = sandboxes,
    computes' = computes,
    true
  }

  // Create a new sandbox from a snapshot: the snapshot must be Ready, and the
  // new sandbox's filesystemId matches the snapshot's. This is the restore
  // path (analogous to creating a PVC from a VolumeSnapshot).
  action createFromSnapshot(id: str, owner: str, providerKind: ProviderKind,
    filesystemId: str, snapId: str): bool = all {
    not(sandboxExists(id)),
    snapshotExists(snapId),
    snapshots.exists(sn => sn.id == snapId and sn.state == Ready
      and sn.filesystemId == filesystemId),
    sandboxes' = sandboxes.union(Set({ id: id, owner: owner, providerKind: providerKind,
      filesystemId: filesystemId, currentComputeId: "", currentSnapshotId: snapId,
      lastAccessedAt: Absent, pausedAt: Absent })),
    states' = states.set(id, Inactive),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  // Lifecycle sweep: pause an active sandbox that has been idle longer than
  // idlePauseSeconds (lastAccessedAt known and now - lastAccessedAt > threshold),
  // recording pausedAt so a future pausedDeleteSeconds sweep can reap it.
  action sweepPauseIdle(id: str, now: int, idlePauseSeconds: int): bool = all {
    states.keys().contains(id),
    states.get(id) == Active,
    sandboxes.exists(s => s.id == id and isPresent(s.lastAccessedAt)
      and (now - value(s.lastAccessedAt)) > idlePauseSeconds),
    sandboxes' = sandboxes.map(s =>
      if (s.id == id)
        { id: s.id, owner: s.owner, providerKind: s.providerKind,
          filesystemId: s.filesystemId, currentComputeId: s.currentComputeId,
          currentSnapshotId: s.currentSnapshotId,
          lastAccessedAt: s.lastAccessedAt, pausedAt: Present(now) }
      else
        s),
    states' = states.set(id, Deactivating),
    computes' = computes,
    snapshots' = snapshots,
    true
  }

  // Lifecycle sweep: delete an inactive sandbox paused longer than
  // pausedDeleteSeconds (pausedAt known and now - pausedAt > threshold).
  action sweepDeletePaused(id: str, now: int, pausedDeleteSeconds: int): bool = all {
    states.keys().contains(id),
    states.get(id) == Inactive,
    sandboxes.exists(s => s.id == id and isPresent(s.pausedAt)
      and (now - value(s.pausedAt)) > pausedDeleteSeconds),
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

  // Lifecycle sweep: delete a sandbox older than maxAgeSeconds (now - created > threshold).
  // `created` is passed in because the spec does not model a created timestamp on Sandbox.
  action sweepDeleteMaxAge(id: str, now: int, created: int, maxAgeSeconds: int): bool = all {
    states.keys().contains(id),
    (now - created) > maxAgeSeconds,
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

  val snapshotsHaveArchivePath: bool =
    snapshots.forall(s => s.storageKind == TarballStore and s.archivePath != "")

  val currentSnapshotValid: bool =
    sandboxes.forall(s =>
      s.currentSnapshotId == "" or
        snapshots.exists(sn => sn.id == s.currentSnapshotId and sn.filesystemId == s.filesystemId))

  // pausedAt is recorded only for sandboxes the sweep has paused (not Active);
  // an Active sandbox must not carry a pausedAt timestamp.
  val pausedAtConsistent: bool =
    sandboxes.forall(s =>
      states.get(s.id) == Active implies s.pausedAt == Absent)

  run createStartsInactive = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
      .then(all {
        assert(states.get("sb1") == Inactive),
        noop
      })
  }

  run activateLifecycle = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
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
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
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
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
      .then(beginActivate("sb1"))
      .then(finishActivate("sb1", "c1", Docker))
      .then(beginActivate("sb1"))
      .fail()
  }

  run snapshotCapturesTarball = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
      .then(beginSnapshot("sb1", { id: "sn1", filesystemId: "fs1", storageKind: TarballStore,
        archivePath: "/snapshots/sn1.tar.gz", state: Ready }))
      .then(all {
        assert(states.get("sb1") == Snapshotting),
        assert(snapshots.exists(s => s.id == "sn1" and s.state == Creating)),
        noop
      })
      .then(finishSnapshot("sb1", "sn1"))
      .then(all {
        assert(states.get("sb1") == Inactive),
        assert(snapshotsHaveArchivePath),
        assert(snapshots.exists(s => s.id == "sn1" and s.state == Ready)),
        assert(currentSnapshotValid),
        noop
      })
  }

  run createFromSnapshotRestoresWorkspace = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
      .then(beginSnapshot("sb1", { id: "sn1", filesystemId: "fs1", storageKind: TarballStore,
        archivePath: "/snapshots/sn1.tar.gz", state: Ready }))
      .then(finishSnapshot("sb1", "sn1"))
      .then(createFromSnapshot("sb2", "u2", Kubernetes, "fs1", "sn1"))
      .then(all {
        assert(sandboxExists("sb2")),
        assert(states.get("sb2") == Inactive),
        assert(sandboxes.exists(s => s.id == "sb2" and s.currentSnapshotId == "sn1")),
        noop
      })
  }

  run deleteRemovesSandbox = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
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

  run sweepPausesIdleSandbox = {
    init.then(create({ id: "sb1", owner: "u1", providerKind: Docker,
      filesystemId: "fs1", currentComputeId: "", currentSnapshotId: "", lastAccessedAt: Absent, pausedAt: Absent }))
      .then(beginActivate("sb1"))
      .then(finishActivate("sb1", "c1", Docker))
      // lastAccessedAt is set by the agent-server probe; model it as 100s ago.
      .then(all {
        sandboxes' = sandboxes.map(s =>
          if (s.id == "sb1")
            { id: s.id, owner: s.owner, providerKind: s.providerKind,
              filesystemId: s.filesystemId, currentComputeId: s.currentComputeId,
              currentSnapshotId: s.currentSnapshotId,
              lastAccessedAt: Present(100), pausedAt: s.pausedAt }
          else
            s),
        states' = states,
        computes' = computes,
        snapshots' = snapshots,
        true
      })
      .then(sweepPauseIdle("sb1", 200, 50))
      .then(all {
        assert(states.get("sb1") == Deactivating),
        assert(sandboxes.exists(s => s.id == "sb1" and s.pausedAt == Present(200))),
        assert(pausedAtConsistent),
        noop
      })
  }
}
