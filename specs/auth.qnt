// Auth specification: session and ownership invariants.

module auth {
  type Session = {
    id: str,
    userId: str,
    expiresAt: int,
  }

  var sessions: Set[Session]

  action init = all {
    sessions' = Set(),
  }

  // Session ids must be unique.
  def idUnique(s1: Session, s2: Session): bool =
    s1.id == s2.id implies s1 == s2

  // Create a session.
  action create(s: Session): bool = all {
    not(sessions.contains(s)),
    sessions' = sessions.union(Set(s)),
    true
  }

  action step: bool = all {
    sessions' = sessions,
    true
  }

  // Destroy a session (logout). Idempotent: removing a non-existent session is a no-op.
  action destroy(sessionId: str): bool = all {
    sessions' = sessions.filter(s => s.id != sessionId),
    true
  }

  // A session belongs to a user; ownership check for authorization.
  pure def owns(sessionUser: str, resourceOwner: str): bool =
    sessionUser == resourceOwner

  // Invariant: session ids are unique.
  val sessionIdsUnique: bool =
    sessions.forall(s1 =>
      sessions.forall(s2 => idUnique(s1, s2)))

  // Tests

  run createSession = {
    init.then(create({ id: "s1", userId: "u1", expiresAt: 100 }))
      .then(all {
        assert(sessions.contains({ id: "s1", userId: "u1", expiresAt: 100 })),
        sessions' = sessions,
      })
  }

  run cannotReuseSessionId = {
    init.then(create({ id: "s1", userId: "u1", expiresAt: 100 }))
      .then(create({ id: "s1", userId: "u2", expiresAt: 200 }))
      .fail()
  }

  run destroyRemovesSession = {
    init.then(create({ id: "s1", userId: "u1", expiresAt: 100 }))
      .then(destroy("s1"))
      .then(all {
        assert(not(sessions.contains({ id: "s1", userId: "u1", expiresAt: 100 }))),
        sessions' = sessions,
      })
  }

  run destroyMissingSessionIsNoop = {
    init.then(destroy("nope"))
      .then(all {
        assert(sessions == Set()),
        sessions' = sessions,
      })
  }
}
