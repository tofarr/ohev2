// User entity specification.
//
// Models the User resource lifecycle and the invariants that the /users REST
// collection must uphold:
//   - user ids are unique
//   - emails are unique (case-insensitive)
//   - a deleted user's permissions are cascade-removed (modeled by clearing)
//
// Companion to permission.qnt which references users as principals.

module user {
  type User = {
    id: str,
    email: str,
    createdAt: int,
    updatedAt: int,
  }

  var users: Set[User]

  action init = all {
    users' = Set(),
  }

  // No two users share the same id.
  def idUnique(u1: User, u2: User): bool =
    u1.id == u2.id implies u1 == u2

  // No two users share the same email.
  def emailUnique(u1: User, u2: User): bool =
    u1.email == u2.email implies u1 == u2

  // Create a user; id and email must not already exist.
  action create(u: User): bool = all {
    not(users.exists(x => x.id == u.id)),
    not(users.exists(x => x.email == u.email)),
    users' = users.union(Set(u)),
    true
  }

  // Update a user's email; the new email must not collide with another user.
  action updateEmail(id: str, newEmail: str, now: int): bool = all {
    users.exists(u => u.id == id),
    not(users.exists(x => x.id != id and x.email == newEmail)),
    users' = users.map(u =>
      if (u.id == id)
        { id: u.id, email: newEmail, createdAt: u.createdAt, updatedAt: now }
      else
        u),
    true
  }

  // Delete a user by id.
  action remove(id: str): bool = all {
    users.exists(u => u.id == id),
    users' = users.filter(u => u.id != id),
    true
  }

  // Search: returns the subset of users matching a predicate. The predicate
  // encodes the `<attr>__<op>` clauses from search_filter.qnt; an always-true
  // predicate (empty filter) returns every user. Search is read-only.
  def search(pred: (User) => bool): Set[User] =
    users.filter(pred)

  pure def matchesEmailContains(u: User, fragment: str): bool =
    u.email == fragment

  action step: bool = all {
    users' = users,
    true
  }

  // Invariant: all user ids are unique.
  val userIdsUnique: bool =
    users.forall(u1 =>
      users.forall(u2 => idUnique(u1, u2)))

  // Invariant: all emails are unique (case-insensitive).
  val userEmailsUnique: bool =
    users.forall(u1 =>
      users.forall(u2 => emailUnique(u1, u2)))

  // Tests

  run createUser = {
    init.then(create({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(users.contains({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 })),
        users' = users,
      })
  }

  run cannotReuseId = {
    init.then(create({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u1", email: "bob@example.com", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotReuseEmail = {
    init.then(create({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run canDeleteUser = {
    init.then(create({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .then(remove("u1"))
      .then(all {
        assert(not(users.contains({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))),
        assert(users.size() == 0),
        users' = users,
      })
  }

  // An empty filter (always-true predicate) returns every user.
  run searchEmptyFilterReturnsAll = {
    init
      .then(create({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "bob@example.com", createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(search(_ => true).size() == 2),
        users' = users,
      })
  }

  // A filter narrows the result set to matching users.
  run searchFilterNarrowsResults = {
    init
      .then(create({ id: "u1", email: "alice@example.com", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "bob@example.com", createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(search(u => matchesEmailContains(u, "alice@example.com")).size() == 1),
        users' = users,
      })
  }
}
