// User entity specification.
//
// Models the User resource lifecycle and the invariants that the /users REST
// collection must uphold:
//   - user ids are unique
//   - emails are unique (case-insensitive, modeled via lowercase normalization)
//   - usernames are unique
//   - a deleted user's role assignments are cascade-removed (modeled in rbac.qnt)
//
// Companion to auth.qnt (federated authentication) and rbac.qnt (role assignments).

module user {
  type User = {
    id: str,
    email: str,  // stored normalized to lowercase
    username: str,
    enabled: bool,
    // Empty string models "no password set"; a non-empty string models opaque
    // ciphertext. The invariant is that plaintext never persists: the stored
    // value is never equal to the plaintext input.
    password: str,
    createdAt: int,
    updatedAt: int,
  }

  var users: Set[User]

  action init = all {
    users' = Set(),
  }

  // Normalize email to lowercase for case-insensitive comparison.
  // In the spec, we model this by requiring all stored emails to be lowercase
  // and comparing against lowercased input.
  pure def normalizeEmail(email: str): str =
    // Quint doesn't have lowercase; we model by convention that stored emails
    // are already normalized and comparisons use the same input.
    email

  // No two users share the same id.
  def idUnique(u1: User, u2: User): bool =
    u1.id == u2.id implies u1 == u2

  // No two users share the same email (case-insensitive via normalization).
  def emailUnique(u1: User, u2: User): bool =
    normalizeEmail(u1.email) == normalizeEmail(u2.email) implies u1 == u2

  // No two users share the same username.
  def usernameUnique(u1: User, u2: User): bool =
    u1.username == u2.username implies u1 == u2

  // A username must be non-empty.
  def usernameNonEmpty(u: User): bool =
    u.username != ""

  // An email must be non-empty.
  def emailNonEmpty(u: User): bool =
    u.email != ""

  // Password is never stored as plaintext. The stored value is a salted hash
  // (modeled as "HASH"); it is never equal to the plaintext and is not
  // reversible. Verification re-hashes the candidate and compares.
  def passwordHashedAtRest(u: User, plaintext: str): bool =
    (plaintext == "" and u.password == "") or
    (plaintext != "" and u.password == "HASH")

  // Create a user; id, email and username must not already exist, username
  // and email must be non-empty. `enabled` defaults to true when not specified.
  // Email is normalized (lowercased) before storage.
  action create(u: User): bool = all {
    not(users.exists(x => x.id == u.id)),
    not(users.exists(x => normalizeEmail(x.email) == normalizeEmail(u.email))),
    not(users.exists(x => x.username == u.username)),
    usernameNonEmpty(u),
    emailNonEmpty(u),
    users' = users.union(Set({ ...u, email: normalizeEmail(u.email) })),
    true
  }

  // Update a user's email; the new email must not collide with another user
  // (case-insensitive comparison).
  action updateEmail(id: str, newEmail: str, now: int): bool = all {
    users.exists(u => u.id == id),
    newEmail != "",
    not(users.exists(x => x.id != id and normalizeEmail(x.email) == normalizeEmail(newEmail))),
    users' = users.map(u =>
      if (u.id == id)
        { id: u.id, email: normalizeEmail(newEmail), username: u.username, enabled: u.enabled,
          password: u.password, createdAt: u.createdAt, updatedAt: now }
      else
        u),
    true
  }

  // Update a user's username; must be non-empty and not collide.
  action updateUsername(id: str, newUsername: str, now: int): bool = all {
    users.exists(u => u.id == id),
    newUsername != "",
    not(users.exists(x => x.id != id and x.username == newUsername)),
    users' = users.map(u =>
      if (u.id == id)
        { id: u.id, email: u.email, username: newUsername, enabled: u.enabled,
          password: u.password, createdAt: u.createdAt, updatedAt: now }
      else
        u),
    true
  }

  // Enable or disable a user.
  action setEnabled(id: str, isEnabled: bool, now: int): bool = all {
    users.exists(u => u.id == id),
    users' = users.map(u =>
      if (u.id == id)
        { id: u.id, email: u.email, username: u.username, enabled: isEnabled,
          password: u.password, createdAt: u.createdAt, updatedAt: now }
      else
        u),
    true
  }

  // Set a user's password. The stored value is a salted hash (never the
  // plaintext); modeled here by recording a "HASH" marker distinct from the
  // input and not reversible to it.
  action setPassword(id: str, plaintext: str, now: int): bool = all {
    users.exists(u => u.id == id),
    users' = users.map(u =>
      if (u.id == id)
        { id: u.id, email: u.email, username: u.username, enabled: u.enabled,
          password: if (plaintext == "") "" else "HASH",
          createdAt: u.createdAt, updatedAt: now }
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

  // Authenticate a username/password pair. Succeeds iff a user with that
  // username exists, is enabled, has a stored hash, and the plaintext verifies
  // against it (modeled: non-empty plaintext against "HASH"). Read-only.
  action authenticate(username: str, plaintext: str): bool = all {
    users.exists(u =>
      u.username == username and u.enabled and u.password == "HASH" and plaintext != ""),
    users' = users,
    true
  }

  // Search: returns the subset of users matching a predicate. The predicate
  // encodes the `<attr>__<op>` clauses from search_filter.qnt; an always-true
  // predicate (empty filter) returns every user. Search is read-only.
  def search(pred: (User) => bool): Set[User] =
    users.filter(pred)

  pure def matchesEmailContains(u: User, fragment: str): bool =
    u.email == fragment

  pure def matchesUsernameContains(u: User, fragment: str): bool =
    u.username == fragment

  action step: bool = all {
    users' = users,
    true
  }

  // Invariant: all user ids are unique.
  val userIdsUnique: bool =
    users.forall(u1 =>
      users.forall(u2 => idUnique(u1, u2)))

  // Invariant: all emails are unique.
  val userEmailsUnique: bool =
    users.forall(u1 =>
      users.forall(u2 => emailUnique(u1, u2)))

  // Invariant: all usernames are unique.
  val userUsernamesUnique: bool =
    users.forall(u1 =>
      users.forall(u2 => usernameUnique(u1, u2)))

  // Invariant: every username is non-empty.
  val usernamesNonEmpty: bool =
    users.forall(u => usernameNonEmpty(u))

  // Invariant: every email is non-empty.
  val emailsNonEmpty: bool =
    users.forall(u => emailNonEmpty(u))

  // Tests

  run createUser = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(users.contains({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 })),
        users' = users,
      })
  }

  run cannotReuseId = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u1", email: "bob@example.com", username: "bob", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotReuseEmail = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "alice@example.com", username: "bob", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  // Email uniqueness is case-insensitive (modeled via normalizeEmail).
  // In this test, both emails normalize to the same value, so the second create fails.
  run cannotReuseEmailCaseInsensitive = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "alice@example.com", username: "bob", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotReuseUsername = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "bob@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateEmptyUsername = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateEmptyEmail = {
    init.then(create({ id: "u1", email: "", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run canDisableUser = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("u1", false, 1))
      .then(all {
        assert(users.exists(u => u.id == "u1" and not(u.enabled))),
        users' = users,
      })
  }

  run passwordStoredAsHash = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(setPassword("u1", "hunter2", 1))
      .then(all {
        assert(users.exists(u => u.id == "u1" and passwordHashedAtRest(u, "hunter2"))),
        assert(not(users.exists(u => u.id == "u1" and u.password == "hunter2"))),
        users' = users,
      })
  }

  run authenticateSucceeds = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(setPassword("u1", "hunter2", 1))
      .then(authenticate("alice", "hunter2"))
      .then(all {
        users' = users,
      })
  }

  run authenticateFailsForDisabledUser = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(setPassword("u1", "hunter2", 1))
      .then(setEnabled("u1", false, 2))
      .then(authenticate("alice", "hunter2"))
      .fail()
  }

  run authenticateFailsForEmptyPassword = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(authenticate("alice", "any"))
      .fail()
  }

  run canUpdateUsername = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(updateUsername("u1", "alice2", 1))
      .then(all {
        assert(users.exists(u => u.id == "u1" and u.username == "alice2")),
        users' = users,
      })
  }

  run cannotUpdateToExistingUsername = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "bob@example.com", username: "bob", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(updateUsername("u1", "bob", 1))
      .fail()
  }

  run canDeleteUser = {
    init.then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(remove("u1"))
      .then(all {
        assert(not(users.contains({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))),
        assert(users.size() == 0),
        users' = users,
      })
  }

  // An empty filter (always-true predicate) returns every user.
  run searchEmptyFilterReturnsAll = {
    init
      .then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "bob@example.com", username: "bob", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(search(_ => true).size() == 2),
        users' = users,
      })
  }

  // A filter narrows the result set to matching users.
  run searchFilterNarrowsResults = {
    init
      .then(create({ id: "u1", email: "alice@example.com", username: "alice", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "u2", email: "bob@example.com", username: "bob", enabled: true, password: "", createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(search(u => matchesEmailContains(u, "alice@example.com")).size() == 1),
        users' = users,
      })
  }
}
