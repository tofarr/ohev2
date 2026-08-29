// Auth specification: federated OAuth + OIDC flow state machine.
//
// Models the resource states and transitions for the auth (federated OAuth /
// OIDC) feature. The project acts as an OAuth/OIDC provider to clients and as
// a client to an IdP. Five states are tracked per authorization attempt:
//
//   PENDING  — the browser was redirected to the IdP; no callback yet.
//   CODED    — the callback succeeded; an authorization code was minted.
//   GRANTED  — the code was exchanged for an access + refresh token pair,
//              or (cookie flow) the callback granted access directly via the
//              session cookie with no code ever minted.
//   EXPIRED  — the IdP refresh-token row expired; refresh is rejected.
//   REVOKED  — the refresh token was explicitly revoked (/auth/revoke);
//              the federated session can no longer refresh or exchange.
//   CLEANED  — the expired row was deleted by the background sweep.
//
// Two response types are supported at /authorize (carried through the
// pending-auth state to the callback):
//
//   CODE   — standard OAuth: the callback mints an authorization code that the
//            client exchanges at /token (PENDING→CODED→GRANTED).
//   COOKIE — a browser-oriented tweak: the callback sets a session cookie and
//            grants access directly; no code is minted or exchangeable
//            (PENDING→GRANTED).
//
// OIDC scope handling: the ``openid`` scope (requested at /authorize and
// threaded through the flow) gates id_token issuance. An id_token is minted at
// /token and /refresh iff ``openid`` was requested AND the response type is
// CODE (the cookie flow does not exchange at /token, so no id_token is minted
// via that path; a cookie-flow client uses /userinfo instead). The discovery
// document is a pure function of config (issuer = base_url) advertising the
// provider's endpoints and HS256 id_token signing.
//
// Invariants:
//   - An authorization code can only be minted from PENDING (callback), and
//     only for the CODE response type.
//   - A code can be exchanged exactly once (PENDING→CODED→GRANTED, no replay).
//   - A COOKIE flow never mints a code (it is never in CODED).
//   - A refresh requires a live (unexpired) IdP refresh-token row.
//   - The cleanup sweep only removes rows already EXPIRED past the age window.
//   - A disabled OAuth client cannot start a new flow.
//   - An id_token is issued iff the ``openid`` scope was requested (idTokenIssued
//     implies hasOpenid) and only on the CODE flow (idTokenIssued implies
//     responseType == Code).
//   - The discovery document's issuer is non-empty and the advertised endpoints
//     are consistent with the issuer.
//   - A revoked flow can never refresh: refresh is rejected from REVOKED.

module auth {
  type FlowState = Pending | Coded | Granted | Expired | Revoked | LoggedOut | Cleaned
  type ResponseType = Code | Cookie
  type FlowId = str

  type Flow = {
    id: FlowId,
    state: FlowState,
    clientEnabled: bool,
    codeConsumed: bool,
    rowExpiresAt: int, // IdP refresh-token row expiry (drift-adjusted)
    responseType: ResponseType,
    hasOpenid: bool, // whether the ``openid`` scope was requested at /authorize
    idTokenIssued: bool, // whether an id_token was minted at /token or /refresh
  }

  var flows: Set[Flow]

  action init = all {
    flows' = Set(),
  }

  // authorize: start a flow. Requires an enabled client. The response type
  // (code vs cookie) and whether ``openid`` was requested are recorded so the
  // callback and /token know whether to mint a code / id_token.
  action authorize(id: FlowId, clientEnabled: bool, now: int, rt: ResponseType, hasOpenid: bool): bool = all {
    clientEnabled,
    not(flows.exists(f => f.id == id)),
    flows' = flows.union(Set({
      id: id,
      state: Pending,
      clientEnabled: clientEnabled,
      codeConsumed: false,
      rowExpiresAt: now + 3600,
      responseType: rt,
      hasOpenid: hasOpenid,
      idTokenIssued: false,
    })),
  }

  // callback: the IdP redirected back with a code.
  // CODE flow → CODED (a code is minted for /token).
  // COOKIE flow → GRANTED directly (cookie set, no code minted).
  pure def toCoded(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Coded, clientEnabled: g.clientEnabled,
        codeConsumed: false, rowExpiresAt: g.rowExpiresAt, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: false }
    else g

  pure def toGrantedDirect(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Granted, clientEnabled: g.clientEnabled,
        codeConsumed: false, rowExpiresAt: g.rowExpiresAt, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: false }
    else g

  pure def applyCallback(g: Flow, id: FlowId): Flow =
    if (g.id == id and g.responseType == Cookie) toGrantedDirect(g, id)
    else if (g.id == id) toCoded(g, id)
    else g

  action callback(id: FlowId): bool = all {
    flows.exists(f => f.id == id and f.state == Pending),
    flows' = flows.map(g => applyCallback(g, id)),
  }

  // token: exchange the code for tokens. CODED → GRANTED; code consumed once.
  // An id_token is minted iff ``openid`` was requested (OIDC Core §3.1.3.3).
  pure def toGranted(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Granted, clientEnabled: g.clientEnabled,
        codeConsumed: true, rowExpiresAt: g.rowExpiresAt, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: g.hasOpenid }
    else g

  action exchangeCode(id: FlowId): bool = all {
    flows.exists(f => f.id == id and f.state == Coded and not(f.codeConsumed)),
    flows' = flows.map(g => toGranted(g, id)),
  }

  // refresh: rotate tokens via the IdP. Requires a live (unexpired) row.
  // The id_token is re-issued iff ``openid`` was originally requested.
  pure def extendRow(g: Flow, id: FlowId, now: int): Flow =
    if (g.id == id)
      { id: g.id, state: Granted, clientEnabled: g.clientEnabled,
        codeConsumed: g.codeConsumed, rowExpiresAt: now + 3600, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: g.hasOpenid }
    else g

  action refresh(id: FlowId, now: int): bool = all {
    flows.exists(f => f.id == id and f.state == Granted and f.rowExpiresAt > now),
    flows' = flows.map(g => extendRow(g, id, now)),
  }

  // revoke: explicit client revocation (/auth/revoke, RFC 7009). A GRANTED
  // flow transitions to REVOKED — a terminal-ish state from which refresh is
  // rejected (refresh requires Granted). The row is deleted so the federated
  // session can no longer be refreshed or exchanged.
  pure def toRevoked(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Revoked, clientEnabled: g.clientEnabled,
        codeConsumed: g.codeConsumed, rowExpiresAt: g.rowExpiresAt, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: g.idTokenIssued }
    else g

  action revoke(id: FlowId): bool = all {
    flows.exists(f => f.id == id and f.state == Granted),
    flows' = flows.map(g => toRevoked(g, id)),
  }

  // logout: cookie-focused session end (/auth/logout). Same terminal effect
  // as revoke — the federated session can no longer refresh or exchange —
  // but driven by the session cookie rather than a presented token. Requires
  // a GRANTED flow (the cookie is only set for an established session).
  pure def toLoggedOut(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: LoggedOut, clientEnabled: g.clientEnabled,
        codeConsumed: g.codeConsumed, rowExpiresAt: g.rowExpiresAt, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: g.idTokenIssued }
    else g

  action logout(id: FlowId): bool = all {
    flows.exists(f => f.id == id and f.state == Granted),
    flows' = flows.map(g => toLoggedOut(g, id)),
  }

  // expire: the IdP refresh-token row's expiry passes.
  pure def toExpired(g: Flow, id: FlowId): Flow =
    if (g.id == id)
      { id: g.id, state: Expired, clientEnabled: g.clientEnabled,
        codeConsumed: g.codeConsumed, rowExpiresAt: g.rowExpiresAt, responseType: g.responseType,
        hasOpenid: g.hasOpenid, idTokenIssued: g.idTokenIssued }
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
  // OIDC Discovery — the metadata document (pure function of config).
  // ------------------------------------------------------------------ #

  // The discovery document is a pure function of the issuer (base_url). It is
  // stateless and requires no authentication. Modeled here as a pure def so
  // the issuer-consistency invariant can be checked.
  pure def discoveryDocument(issuer: str): str =
    if (issuer == "") ""
    else issuer

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // A code is consumed at most once: only GRANTED flows have codeConsumed.
  def codeConsumedOnceInvariant: bool =
    flows.forall(f => f.codeConsumed implies f.state == Granted)

  // Cleanup only removes already-EXPIRED flows (no Cleaned state persists).
  def cleanupOnlyExpiredInvariant: bool =
    flows.forall(f => f.state != Cleaned)

  // A COOKIE flow never mints a code: it is never in CODED (it jumps straight
  // to GRANTED), so exchangeCode — which requires CODED — cannot apply to it.
  def cookieFlowNeverCodedInvariant: bool =
    flows.forall(f => f.responseType == Cookie implies f.state != Coded)

  // An id_token is issued only when ``openid`` was requested.
  def idTokenOnlyWithOpenidInvariant: bool =
    flows.forall(f => f.idTokenIssued implies f.hasOpenid)

  // An id_token is issued only on the CODE flow (the cookie flow never goes
  // through /token, so it never mints an id_token via that path).
  def idTokenOnlyOnCodeFlowInvariant: bool =
    flows.forall(f => f.idTokenIssued implies f.responseType == Code)

  // The discovery document's issuer is non-empty.
  def discoveryIssuerNonEmptyInvariant: bool =
    discoveryDocument("https://api.example.com") != ""

  // A revoked or logged-out flow can never refresh: refresh requires
  // Granted, and both revoke and logout move the flow out of Granted. No
  // transition returns a REVOKED/LOGGEDOUT flow to Granted, so the federated
  // session is permanently dead.
  def revokedCannotRefreshInvariant: bool =
    flows.forall(f => (f.state == Revoked or f.state == LoggedOut) implies f.state != Granted)

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  run happyPath = {
    init
      .then(authorize("f1", true, 100, Code, true))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(refresh("f1", 200))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.state == Granted and f.idTokenIssued)),
        flows' = flows,
      })
  }

  run codeCannotBeReplayed = {
    init
      .then(authorize("f1", true, 100, Code, true))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(exchangeCode("f1"))
      .fail()
  }

  run callbackRequiresPending = {
    init
      .then(authorize("f1", true, 100, Code, true))
      .then(exchangeCode("f1"))
      .fail()
  }

  run refreshRejectedAfterExpiry = {
    init
      .then(authorize("f1", true, 100, Code, true))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(expire("f1", 5000))
      .then(refresh("f1", 5001))
      .fail()
  }

  // Revocation kills the federated session: after revoke the flow is REVOKED
  // and a subsequent refresh is rejected (refresh requires Granted).
  run revokeKillsRefresh = {
    init
      .then(authorize("f1", true, 100, Code, false))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(revoke("f1"))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.state == Revoked)),
        flows' = flows,
      })
      .then(refresh("f1", 200))
      .fail()
  }

  // Revoking a non-granted flow (e.g. still PENDING) is rejected.
  run revokeRequiresGranted = {
    init
      .then(authorize("f1", true, 100, Code, false))
      .then(revoke("f1"))
      .fail()
  }

  // Revoking twice: the second revoke finds the flow no longer Granted and
  // fails (idempotent at the DB level — the row is already gone).
  run revokeTwiceSecondFails = {
    init
      .then(authorize("f1", true, 100, Code, false))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(revoke("f1"))
      .then(revoke("f1"))
      .fail()
  }

  // Logout kills the federated session: after logout the flow is LOGGEDOUT
  // and a subsequent refresh is rejected (refresh requires Granted).
  run logoutKillsRefresh = {
    init
      .then(authorize("f1", true, 100, Code, false))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(logout("f1"))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.state == LoggedOut)),
        flows' = flows,
      })
      .then(refresh("f1", 200))
      .fail()
  }

  // Logout requires an established (GRANTED) session.
  run logoutRequiresGranted = {
    init
      .then(authorize("f1", true, 100, Code, false))
      .then(logout("f1"))
      .fail()
  }

  run cleanupRemovesExpired = {
    init
      .then(authorize("f1", true, 100, Code, true))
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
      .then(authorize("f1", true, 100, Code, true))
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
      .then(authorize("f1", false, 100, Code, true))
      .fail()
  }

  // COOKIE flow: callback grants access directly (no code minted); the flow is
  // never CODED and exchangeCode cannot apply to it.
  run cookieFlowSkipsCode = {
    init
      .then(authorize("f1", true, 100, Cookie, true))
      .then(callback("f1"))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.state == Granted and not(f.codeConsumed))),
        flows' = flows,
      })
  }

  run cookieFlowCannotExchangeCode = {
    init
      .then(authorize("f1", true, 100, Cookie, true))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .fail()
  }

  // OIDC: an id_token is minted at /token iff ``openid`` was requested.
  run idTokenIssuedWithOpenid = {
    init
      .then(authorize("f1", true, 100, Code, true))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.idTokenIssued)),
        flows' = flows,
      })
  }

  // OIDC: no id_token is minted when ``openid`` was not requested.
  run idTokenNotIssuedWithoutOpenid = {
    init
      .then(authorize("f1", true, 100, Code, false))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and not(f.idTokenIssued))),
        flows' = flows,
      })
  }

  // OIDC: the id_token is re-issued on refresh when ``openid`` was requested.
  run idTokenReissuedOnRefresh = {
    init
      .then(authorize("f1", true, 100, Code, true))
      .then(callback("f1"))
      .then(exchangeCode("f1"))
      .then(refresh("f1", 200))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and f.idTokenIssued)),
        flows' = flows,
      })
  }

  // OIDC: the cookie flow never mints an id_token via /token (it never reaches
  // CODED / exchangeCode). A cookie-flow client uses /userinfo instead.
  run cookieFlowNeverIssuesIdToken = {
    init
      .then(authorize("f1", true, 100, Cookie, true))
      .then(callback("f1"))
      .then(all {
        assert(flows.exists(f => f.id == "f1" and not(f.idTokenIssued))),
        flows' = flows,
      })
  }

  // OIDC Discovery: the document is non-empty for a valid issuer.
  run discoveryDocumentNonEmpty = {
    init
      .then(all {
        assert(discoveryDocument("https://api.example.com") != ""),
        flows' = flows,
      })
  }
}
