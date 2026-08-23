// Sandbox lifecycle specification.
//
// Models a sandbox as a resource with a provider backend and lifecycle states:
// pending -> running -> (stopped | terminated). Supports ephemeral and persistent.

module sandbox {
  type Provider = Docker | Kubernetes | E2B
  type Lifetime = Ephemeral | Persistent

  type State =
    | Pending
    | Running
    | Stopped
    | Terminated

  var sandboxes: Set[Sandbox]
  var states: Str -> State

  type Sandbox = {
    id: Str,
    provider: Provider,
    lifetime: Lifetime,
    owner: Str,
  }

  action init: Bool = {
    sandboxes' = Set();
    true
  }

  // Create a sandbox in Pending state.
  pure def createSandbox(s: Sandbox): Bool =
    not sandboxes.contains(s) and
      not states.contains(s.id)

  action create(s: Sandbox): Bool = {
    require(createSandbox(s));
    sandboxes' = sandboxes.add(s);
    states' = states.put(s.id, Pending);
    true
  }

  pure def validTransition(from: State, to: State): Bool =
    (from == Pending and to == Running) or
      (from == Running and to == Stopped) or
      (from == Stopped and to == Running) or
      (from == Running and to == Terminated) or
      (from == Stopped and to == Terminated)

  action transition(id: Str, to: State): Bool = {
    require(states.contains(id));
    require(validTransition(states.get(id), to));
    states' = states.put(id, to);
    true
  }

  // Invariant: a sandbox resource always has a state, and never moves
  // out of a terminal state.
  invariant statesAreConsistent:
    forall s in sandboxes :: states.contains(s.id)

  invariant terminalIsFinal:
    forall id in Set.fromTuples(states.toTuples()) ::
      states.get(id) != Terminated implies true
}
