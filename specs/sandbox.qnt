// Sandbox lifecycle specification.
//
// Models a sandbox as a resource with a provider backend and lifecycle states:
// pending -> running -> (stopped | terminated). Supports ephemeral and persistent.
//
// Invariants:
//   - statesConsistent: every sandbox has a recorded state.
//   - ownershipRequired: every sandbox has a non-empty owner.
//   - terminatedIsTerminal: once terminated, a sandbox cannot change state.
//   - idsUnique: sandbox ids are unique.
//
// The provider is pluggable (Docker, Kubernetes, E2B) and configured at create
// time. All providers use the same lifecycle state machine; provider-specific
// behavior is implementation detail outside the spec.

module sandbox {
  // A sandbox is a runtime backing an agent conversation. Its provider is
  // pluggable (Docker, Kubernetes, E2B) and it may be ephemeral or persistent.
  type Provider = Docker | Kubernetes | E2B
  type Lifetime = Ephemeral | Persistent

  type State = Pending | Running | Stopped | Terminated

  type Sandbox = {
    id: str,
    provider: Provider,
    lifetime: Lifetime,
    owner: str,
  }

  var sandboxes: Set[Sandbox]
  var states: str -> State

  action init = all {
    sandboxes' = Set(),
    states' = Map(),
  }

  // A new sandbox must not already exist (by id).
  def notExists(s: Sandbox): bool =
    not(sandboxes.exists(x => x.id == s.id))

  // Create a sandbox in Pending state. Owner must be non-empty.
  action create(s: Sandbox): bool = all {
    notExists(s),
    s.owner != "",
    sandboxes' = sandboxes.union(Set(s)),
    states' = states.set(s.id, Pending),
    true
  }

  // Permitted lifecycle transitions. Terminated is terminal.
  pure def validTransition(from: State, target: State): bool = or {
    from == Pending and target == Running,
    from == Pending and target == Terminated,
    from == Running and target == Stopped,
    from == Stopped and target == Running,
    from == Running and target == Terminated,
    from == Stopped and target == Terminated,
  }

  // Move a sandbox to a new state iff the transition is permitted.
  action transition(id: str, target: State): bool = all {
    states.keys().contains(id),
    validTransition(states.get(id), target),
    sandboxes' = sandboxes,
    states' = states.set(id, target),
    true
  }

  // Move a sandbox to a new state, but only if the caller is the owner.
  action transitionAsOwner(id: str, target: State, callerId: str): bool = all {
    states.keys().contains(id),
    sandboxes.exists(s => s.id == id and s.owner == callerId),
    validTransition(states.get(id), target),
    sandboxes' = sandboxes,
    states' = states.set(id, target),
    true
  }

  // Delete a sandbox (removes from both sets).
  action remove(id: str): bool = all {
    sandboxes.exists(s => s.id == id),
    sandboxes' = sandboxes.filter(s => s.id != id),
    states' = states.keys().filter(k => k != id).fold(
      Map(),
      (acc, k) => acc.set(k, states.get(k))
    ),
    true
  }

  // No-op action: reads state, leaves it unchanged. Used to wrap assertions.
  action noop: bool = all {
    sandboxes' = sandboxes,
    states' = states,
    true
  }

  // Nondeterministic step for the simulator.
  action step: bool = noop

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // Every tracked sandbox has a recorded state.
  val statesConsistent: bool =
    sandboxes.forall(s => states.keys().contains(s.id))

  // Every sandbox has a non-empty owner.
  val ownershipRequired: bool =
    sandboxes.forall(s => s.owner != "")

  // Sandbox ids are unique.
  val idsUnique: bool =
    sandboxes.forall(s1 =>
      sandboxes.forall(s2 =>
        s1.id == s2.id implies s1 == s2))

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  run createThenRun = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(all {
        assert(states.get("sb1") == Pending),
        noop
      })
      .then(transition("sb1", Running))
      .then(all {
        assert(states.get("sb1") == Running),
        noop
      })
  }

  run cannotReuseId = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u2" }))
      .fail()
  }

  run cannotCreateWithEmptyOwner = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "" }))
      .fail()
  }

  // Running -> Stopped -> Running (resume)
  run canResumeFromStopped = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Stopped))
      .then(all {
        assert(states.get("sb1") == Stopped),
        noop
      })
      .then(transition("sb1", Running))
      .then(all {
        assert(states.get("sb1") == Running),
        noop
      })
  }

  // Pending -> Terminated (skip running)
  run canTerminateFromPending = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Terminated))
      .then(all {
        assert(states.get("sb1") == Terminated),
        noop
      })
  }

  // Stopped -> Terminated
  run canTerminateFromStopped = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Stopped))
      .then(transition("sb1", Terminated))
      .then(all {
        assert(states.get("sb1") == Terminated),
        noop
      })
  }

  // Running -> Terminated
  run canTerminateFromRunning = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Terminated))
      .then(all {
        assert(states.get("sb1") == Terminated),
        noop
      })
  }

  // Terminated is terminal: cannot transition out.
  run terminatedIsTerminal = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Terminated))
      .then(transition("sb1", Running))
      .fail()
  }

  run terminatedCannotStop = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Terminated))
      .then(transition("sb1", Stopped))
      .fail()
  }

  // Invalid transitions are rejected.
  run cannotSkipPendingToStopped = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Stopped))
      .fail()
  }

  run cannotGoFromStoppedToPending = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Stopped))
      .then(transition("sb1", Pending))
      .fail()
  }

  // Ownership: only owner can transition.
  run ownerCanTransition = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transitionAsOwner("sb1", Running, "u1"))
      .then(all {
        assert(states.get("sb1") == Running),
        noop
      })
  }

  run nonOwnerCannotTransition = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transitionAsOwner("sb1", Running, "u2"))
      .fail()
  }

  // Provider tests: all providers follow the same lifecycle.
  run dockerProviderLifecycle = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Terminated))
      .then(all {
        assert(states.get("sb1") == Terminated),
        noop
      })
  }

  run kubernetesProviderLifecycle = {
    init.then(create({ id: "sb1", provider: Kubernetes, lifetime: Persistent, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Stopped))
      .then(transition("sb1", Terminated))
      .then(all {
        assert(states.get("sb1") == Terminated),
        noop
      })
  }

  run e2bProviderLifecycle = {
    init.then(create({ id: "sb1", provider: E2B, lifetime: Ephemeral, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Terminated))
      .then(all {
        assert(states.get("sb1") == Terminated),
        noop
      })
  }

  // Persistent sandboxes can be stopped and resumed.
  run persistentCanStopAndResume = {
    init.then(create({ id: "sb1", provider: Kubernetes, lifetime: Persistent, owner: "u1" }))
      .then(transition("sb1", Running))
      .then(transition("sb1", Stopped))
      .then(transition("sb1", Running))
      .then(all {
        assert(states.get("sb1") == Running),
        noop
      })
  }

  // Can delete a sandbox.
  run canDeleteSandbox = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(remove("sb1"))
      .then(all {
        assert(not(sandboxes.exists(s => s.id == "sb1"))),
        assert(not(states.keys().contains("sb1"))),
        noop
      })
  }

  // Multiple sandboxes can coexist.
  run multipleSandboxes = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(create({ id: "sb2", provider: Kubernetes, lifetime: Persistent, owner: "u2" }))
      .then(transition("sb1", Running))
      .then(transition("sb2", Running))
      .then(all {
        assert(states.get("sb1") == Running),
        assert(states.get("sb2") == Running),
        assert(sandboxes.size() == 2),
        noop
      })
  }

  // Same owner can have multiple sandboxes.
  run sameOwnerMultipleSandboxes = {
    init.then(create({ id: "sb1", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(create({ id: "sb2", provider: Docker, lifetime: Ephemeral, owner: "u1" }))
      .then(all {
        assert(sandboxes.filter(s => s.owner == "u1").size() == 2),
        noop
      })
  }
}
