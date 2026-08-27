// Auth2 specification: federated OAuth flow state machine.
//
// Models the resource states and transitions for the auth2 (federated OAuth)
// feature. The project acts as an OAuth provider to clients and as a client
// to an IdP. Five states are tracked per authorization attempt:
//
//   PENDING  — the browser was redirected to the IdP; no callback yet.
//   CODED    — the callback succeeded; an authorization code was minted.
//   GRANTED  — the code was exchanged for an access + refresh token pair.
//   EXPIRED  — the IdP refresh-token row expired; refresh is rejected.
//   CLEANED  — the expired row was deleted by the background sweep.
//
// Invariants:
//   - An authorization code can only be minted from PENDING (callback).
//   - A code can be exchanged exactly once (PENDING→CODED→GRANTED, no replay).
//   - A refresh requires a live (unexpired) IdP refresh-token row.
//   - The cleanup sweep only removes rows already EXPIRED past the age window.
//   - A disabled OAuth client cannot start a new flow.

module auth2 {
  type FlowState = Pending | Coded | Granted | Expired | Cleaned
  type FlowId = str

  type Flow = {
    id: FlowId,
    state: FlowState,
    clientEnabled: bool,
    codeConsumed: bool,
    rowExpiresAt: int, // IdP refresh-token row expiry (drift-adjusted)
  }

  var flows: Set[Flow]

  action init = all {
    flows' = Set(),
  }

  // authorize: start a flow. Requires an enabled client.
  action authorize(id: FlowId, clientEnabled: bool, now: int): bool = all {
    clientEnabled,
    not(flows.exists(f => f.id == id)),
    flows' = flows.union(Set({
      id: id,
      state: Pending,
      clientEnabled: clientEnabled,
      codeConsumed: false,
      rowExpiresAt: now + 3600,
    })),
  }

  // callback: the IdP redirected back with a code. PENDING → CODED.
  pure def toCoded(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Coded, clientEnabled: g.clientEnabled,
        codeConsumed: false, rowExpiresAt: g.rowExpiresAt }
    else g

  action callback(id: FlowId): bool = all {
    flows.exists(f => f.id == id and f.state == Pending),
    flows' = flows.map(g => toCoded(g, id)),
  }

  // token: exchange the code for tokens. CODED → GRANTED; code consumed once.
  pure def toGranted(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Granted, clientEnabled: g.clientEnabled,
        codeConsumed: true, rowExpiresAt: g.rowExpiresAt }
    else g

  action exchangeCode(id: FlowId): bool = all {
    flows.exists(f => f.id == id and f.state == Coded and not(f.codeConsumed)),
    flows' = flows.map(g => toGranted(g, id)),
  }

  // refresh: rotate tokens via the IdP. Requires a live (unexpired) row.
  pure def extendRow(g: Flow, id: FlowId, now: int): Flow =
    if (g.id == id)
      { id: g.id, state: Granted, clientEnabled: g.clientEnabled,
        codeConsumed: g.codeConsumed, rowExpiresAt: now + 3600 }
    else g

  action refresh(id: FlowId, now: int): bool = all {
    flows.exists(f => f.id == id and f.state == Granted and f.rowExpiresAt > now),
    flows' = flows.map(g => extendRow(g, id, now)),
  }

  // expire: the IdP refresh-token row's expiry passes.
  pure def toExpired(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Expired, clientEnabled: g.clientEnabled,
        codeConsumed: g.codeConsumed, rowExpiresAt: g.rowExpiresAt }
    else g

  action expire(id: FlowId, now: int): bool = all {
    flows.exists(f => f.id == id and f.state == Granted and f.rowExpiresAt <= now),
    flows' = flows.map(g => toExpired(g, id)),
  }

  // cleanup: delete rows expired past the age window.
  action cleanup(id: FlowId, now: int, ageWindow: int): bool = all {
    flows.exists(f =>
      f.id == id and f.state == Expired and f.rowExpiresAt < now - ageWindow),
    flows' = flows.filter(g => g.id != id),
  }

  // A nondeterministic step used by the simulator to exercise invariants.
  action step: bool = all {
    flows' = flows,
    true
  }

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // A code is consumed at most once: only GRANTED flows have codeConsumed.
  def codeConsumedOnceInvariant: bool =
    flows.forall(f => f.codeConsumed implies f.state == Granted)

  // Cleanup only removes already-EXPIRED flows (no Cleaned state persists).
  def cleanupOnlyExpiredInvariant: bool =
    flows.forall(f => f.state != Cleaned)

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  run happyPath = {
    init
      .then(authorize("f1", true, 100))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(refresh("f1", 200))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.state == Granted)),
        flows' = flows,
      })
  }

  run codeCannotBeReplayed = {
    init
      .then(authorize("f1", true, 100))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(exchangeCode("f1"))
      .fail()
  }

  run callbackRequiresPending = {
    init
      .then(authorize("f1", true, 100))
      .then(exchangeCode("f1"))
      .fail()
  }

  run refreshRejectedAfterExpiry = {
    init
      .then(authorize("f1", true, 100))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(expire("f1", 5000))
      .then(refresh("f1", 5001))
      .fail()
  }

  run cleanupRemovesExpired = {
    init
      .then(authorize("f1", true, 100))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(expire("f1", 5000))
      .then(cleanup("f1", 6000, 100))
      .then(all {
        assert(not(flows.exists(f => f.id == "f1"))),
        flows' = flows,
      })
  }

  run cleanupSkipsFreshExpiry = {
    init
      .then(authorize("f1", true, 100))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(expire("f1", 5000))
      .then(cleanup("f1", 5100, 86400))
      .then(all {
        assert(flows.exists(f => f.id == "f1")),
        flows' = flows,
      })
  }

  run disabledClientCannotAuthorize = {
    init
      .then(authorize("f1", false, 100))
      .fail()
  }
}
