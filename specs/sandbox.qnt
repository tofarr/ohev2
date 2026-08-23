// Sandbox lifecycle specification.
//
// Models a sandbox as a resource with a provider backend and lifecycle states:
// pending -> running -> (stopped | terminated). Supports ephemeral and persistent.

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

  // A new sandbox must not already exist.
  def notExists(s: Sandbox): bool =
    not(sandboxes.contains(s))

  // Create a sandbox in Pending state.
  action create(s: Sandbox): bool = all {
    notExists(s),
    sandboxes' = sandboxes.union(Set(s)),
    states' = states.set(s.id, Pending),
    true
  }

  // Permitted lifecycle transitions. Terminated is terminal.
  pure def validTransition(from: State, target: State): bool = or {
    from == Pending and target == Running,
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

  // No-op action: reads state, leaves it unchanged. Used to wrap assertions.
  action noop: bool = all {
    sandboxes' = sandboxes,
    states' = states,
    true
  }

  // Nondeterministic step for the simulator.
  action step: bool = noop

  // Every tracked sandbox has a recorded state.
  val statesConsistent: bool =
    sandboxes.forall(s => states.keys().contains(s.id))

  // Tests

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
}
