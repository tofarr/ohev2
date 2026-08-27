// Auth specification: token types, validity, and ownership invariants.
//
// Four token types share a single JWE-encoded shape but differ in how their
// validity is established:
//   COOKIE        — short-lived; validity = user.enabled (sliding re-mint).
//   ACCESS_TOKEN  — short-lived OAuth2 access token; validity = user.enabled.
//   API_KEY       — long-lived; validity = a live api_keys row AND user.enabled.
//   REFRESH_TOKEN — sliding OAuth2 refresh token; validity = a live
//                   refresh_tokens row AND user.enabled; rotation disables the
//                   old row and mints a successor with a fresh jti.

module auth {
  type TokenType = str
  type TokenId = str

  type Token = {
    id: TokenId,        // jti; shared with DB rows where present
    userId: str,        // sub
    expiresAt: int,     // exp
    tokenType: TokenType,
    enabled: bool,      // user.enabled (and row.enabled for API_KEY/REFRESH_TOKEN)
  }

  // DB-backed backing rows (API_KEY, REFRESH_TOKEN). A token whose jti has no
  // live row is invalid even if the JWE itself is decryptable and unexpired.
  type Row = {
    jti: TokenId,
    userId: str,
    enabled: bool,
    expiresAt: int,
  }

  var rows: Set[Row]

  action init = all {
    rows' = Set(),
  }

  // A refresh-token jti must be unique across rows.
  def jtiUnique(r1: Row, r2: Row): bool =
    r1.jti == r2.jti implies r1 == r2

  // A row is live iff it is enabled and unexpired.
  pure def isLive(r: Row, now: int): bool =
    r.enabled and r.expiresAt > now

  // Create a backing row (mint an API key / refresh token).
  action createRow(r: Row): bool = all {
    not(rows.contains(r)),
    rows' = rows.union(Set(r)),
    true
  }

  // The row with matching jti, disabled; other rows unchanged.
  pure def disableIfMatching(r: Row, jti: TokenId): Row =
    if (r.jti == jti)
      { jti: r.jti, userId: r.userId, enabled: false, expiresAt: r.expiresAt }
    else
      r

  // Revoke a row (disable). Idempotent on a missing row.
  action revokeRow(jti: TokenId): bool = all {
    rows' = rows.map(r => disableIfMatching(r, jti)),
    true
  }

  // Rotate a refresh token: disable the old row and create a successor with a
  // fresh jti whose expiry is min(now + sliding, cap).
  action rotate(oldJti: TokenId, successor: Row, now: int, sliding: int, cap: int): bool = all {
    rows.exists(r => r.jti == oldJti and isLive(r, now)),
    not(rows.contains(successor)),
    successor.expiresAt == if (now + sliding < cap) now + sliding else cap,
    rows' = rows
      .map(r => disableIfMatching(r, oldJti))
      .union(Set(successor)),
    true
  }

  action step: bool = all {
    rows' = rows,
    true
  }

  // A token is authenticatable iff: its jti (for DB-backed types) has a live
  // row, and its user is enabled. COOKIE/ACCESS_TOKEN have no row.
  pure def valid(t: Token, now: int): bool =
    t.enabled and t.expiresAt > now

  // A token belongs to a user; ownership check for authorization.
  pure def owns(tokenUser: str, resourceOwner: str): bool =
    tokenUser == resourceOwner

  // Invariant: refresh-token jtis are unique.
  val jtiUniqueInvariant: bool =
    rows.forall(r1 =>
      rows.forall(r2 => jtiUnique(r1, r2)))

  // Tests

  run createRowSucceeds = {
    init.then(createRow({ jti: "k1", userId: "u1", enabled: true, expiresAt: 100 }))
      .then(all {
        assert(rows.contains({ jti: "k1", userId: "u1", enabled: true, expiresAt: 100 })),
        rows' = rows,
      })
  }

  run cannotReuseJti = {
    init.then(createRow({ jti: "k1", userId: "u1", enabled: true, expiresAt: 100 }))
      .then(createRow({ jti: "k1", userId: "u2", enabled: true, expiresAt: 200 }))
      .fail()
  }

  run revokeDisablesRow = {
    init.then(createRow({ jti: "k1", userId: "u1", enabled: true, expiresAt: 100 }))
      .then(revokeRow("k1"))
      .then(all {
        assert(rows.contains({ jti: "k1", userId: "u1", enabled: false, expiresAt: 100 })),
        rows' = rows,
      })
  }

  run revokeMissingRowIsNoop = {
    init.then(revokeRow("nope"))
      .then(all {
        assert(rows == Set()),
        rows' = rows,
      })
  }

  run rotateCreatesSuccessorAndDisablesOld = {
    init.then(createRow({ jti: "old", userId: "u1", enabled: true, expiresAt: 1000 }))
      .then(rotate("old", { jti: "new", userId: "u1", enabled: true, expiresAt: 110 }, 10, 100, 1000))
      .then(all {
        assert(rows.contains({ jti: "old", userId: "u1", enabled: false, expiresAt: 1000 })),
        assert(rows.contains({ jti: "new", userId: "u1", enabled: true, expiresAt: 110 })),
        rows' = rows,
      })
  }

  run rotateRejectsRevokedRow = {
    init.then(createRow({ jti: "old", userId: "u1", enabled: true, expiresAt: 1000 }))
      .then(revokeRow("old"))
      .then(rotate("old", { jti: "new", userId: "u1", enabled: true, expiresAt: 110 }, 10, 100, 1000))
      .fail()
  }
}

