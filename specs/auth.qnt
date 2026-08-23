// Auth specification: session and ownership invariants.

module auth {
  type Session = {
    id: Str,
    userId: Str,
    expiresAt: Int,
  }

  var sessions: Set[Session]

  action init: Bool = {
    sessions' = Set();
    true
  }

  pure def owns(sessionUser: Str, resourceOwner: Str): Bool =
    sessionUser == resourceOwner

  // Invariant: session ids are unique.
  invariant sessionIdsUnique:
    forall s1 in sessions :: forall s2 in sessions ::
      s1.id == s2.id implies s1 == s2
}
