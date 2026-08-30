// API key entity specification.
//
// Models the ApiKey resource lifecycle and the invariants that the /api-keys
// REST collection must uphold:
//
//   - api key ids are unique
//   - every api key has an owner (user_id)
//   - the prefix (first 8 chars of the key) is stored for identification
//   - the key hash is stored, never the raw key
//   - api keys can be enabled/disabled (revocation)
//   - a deleted user's api keys are cascade-removed
//
// The raw key value (oh_...) is returned exactly once at creation time. After
// that, only the prefix and hash are available. Authentication verifies the
// presented key against the stored hash.
//
// Companion to user.qnt (api keys belong to users) and rbac.qnt (api key
// permissions are governed by the api_key_permission column on Role).

module api_key {
  type ApiKey = {
    id: str,
    userId: str,  // owner
    name: str,
    prefix: str,  // first 8 chars of the raw key, for identification
    keyHash: str, // bcrypt hash of the raw key
    enabled: bool,
    createdAt: int,
    updatedAt: int,
  }

  var apiKeys: Set[ApiKey]

  action init = all {
    apiKeys' = Set(),
  }

  // No two api keys share the same id.
  def idUnique(k1: ApiKey, k2: ApiKey): bool =
    k1.id == k2.id implies k1 == k2

  // Every api key has a non-empty owner.
  def hasOwner(k: ApiKey): bool =
    k.userId != ""

  // Every api key has a non-empty name.
  def hasName(k: ApiKey): bool =
    k.name != ""

  // The key hash is never the raw key (modeled: hash is always "HASH").
  def keyHashedAtRest(k: ApiKey): bool =
    k.keyHash == "HASH"

  // Create an api key. The raw key is generated and returned once; the stored
  // key has the hash. Modeled: we store "HASH" as the hash value.
  action create(k: ApiKey): bool = all {
    not(apiKeys.exists(x => x.id == k.id)),
    hasOwner(k),
    hasName(k),
    k.keyHash == "HASH",  // must be hashed before storage
    apiKeys' = apiKeys.union(Set(k)),
    true
  }

  // Update an api key's name.
  action updateName(id: str, newName: str, now: int): bool = all {
    apiKeys.exists(k => k.id == id),
    newName != "",
    apiKeys' = apiKeys.map(k =>
      if (k.id == id)
        { ...k, name: newName, updatedAt: now }
      else
        k),
    true
  }

  // Enable or disable an api key (revocation).
  action setEnabled(id: str, isEnabled: bool, now: int): bool = all {
    apiKeys.exists(k => k.id == id),
    apiKeys' = apiKeys.map(k =>
      if (k.id == id)
        { ...k, enabled: isEnabled, updatedAt: now }
      else
        k),
    true
  }

  // Delete an api key by id.
  action remove(id: str): bool = all {
    apiKeys.exists(k => k.id == id),
    apiKeys' = apiKeys.filter(k => k.id != id),
    true
  }

  // Delete all api keys owned by a user (cascade delete).
  action removeByUser(userId: str): bool = all {
    apiKeys' = apiKeys.filter(k => k.userId != userId),
    true
  }

  // Authenticate with an api key. Succeeds iff an enabled key exists with
  // a matching hash. Modeled: the presented raw key hashes to "HASH" iff it's
  // non-empty (any non-empty key verifies against "HASH" for simplicity).
  action authenticate(keyId: str, rawKey: str): bool = all {
    rawKey != "",
    apiKeys.exists(k => k.id == keyId and k.enabled and k.keyHash == "HASH"),
    apiKeys' = apiKeys,
    true
  }

  action step: bool = all {
    apiKeys' = apiKeys,
    true
  }

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // All api key ids are unique.
  val idsUnique: bool =
    apiKeys.forall(k1 =>
      apiKeys.forall(k2 => idUnique(k1, k2)))

  // Every api key has an owner.
  val allHaveOwner: bool =
    apiKeys.forall(k => hasOwner(k))

  // Every api key has a name.
  val allHaveName: bool =
    apiKeys.forall(k => hasName(k))

  // Every api key's hash is valid (not plaintext).
  val allHashedAtRest: bool =
    apiKeys.forall(k => keyHashedAtRest(k))

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  run createApiKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.userId == "u1")),
        apiKeys' = apiKeys,
      })
  }

  run cannotReuseId = {
    init.then(create({ id: "k1", userId: "u1", name: "key1", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k1", userId: "u2", name: "key2", prefix: "oh_def34", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateWithoutOwner = {
    init.then(create({ id: "k1", userId: "", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateWithoutName = {
    init.then(create({ id: "k1", userId: "u1", name: "", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateWithPlaintextKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "oh_abc123456789", enabled: true, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run canDisableApiKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("k1", false, 1))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and not(k.enabled))),
        apiKeys' = apiKeys,
      })
  }

  run canReenableApiKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("k1", false, 1))
      .then(setEnabled("k1", true, 2))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.enabled)),
        apiKeys' = apiKeys,
      })
  }

  run authenticateSucceeds = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(authenticate("k1", "oh_abc123456789"))
      .then(all {
        apiKeys' = apiKeys,
      })
  }

  run authenticateFailsForDisabledKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("k1", false, 1))
      .then(authenticate("k1", "oh_abc123456789"))
      .fail()
  }

  run authenticateFailsForEmptyKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(authenticate("k1", ""))
      .fail()
  }

  run authenticateFailsForNonexistentKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(authenticate("k2", "oh_abc123456789"))
      .fail()
  }

  run canDeleteApiKey = {
    init.then(create({ id: "k1", userId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(remove("k1"))
      .then(all {
        assert(not(apiKeys.exists(k => k.id == "k1"))),
        assert(apiKeys.size() == 0),
        apiKeys' = apiKeys,
      })
  }

  run cascadeDeleteByUser = {
    init.then(create({ id: "k1", userId: "u1", name: "key1", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k2", userId: "u1", name: "key2", prefix: "oh_def34", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k3", userId: "u2", name: "key3", prefix: "oh_ghi56", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(removeByUser("u1"))
      .then(all {
        assert(not(apiKeys.exists(k => k.userId == "u1"))),
        assert(apiKeys.exists(k => k.userId == "u2")),
        assert(apiKeys.size() == 1),
        apiKeys' = apiKeys,
      })
  }

  run canUpdateName = {
    init.then(create({ id: "k1", userId: "u1", name: "old-name", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(updateName("k1", "new-name", 1))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.name == "new-name")),
        apiKeys' = apiKeys,
      })
  }

  run sameUserMultipleKeys = {
    init.then(create({ id: "k1", userId: "u1", name: "key1", prefix: "oh_abc12", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k2", userId: "u1", name: "key2", prefix: "oh_def34", keyHash: "HASH", enabled: true, createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(apiKeys.filter(k => k.userId == "u1").size() == 2),
        apiKeys' = apiKeys,
      })
  }
}
