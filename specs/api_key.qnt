// API key entity specification.
//
// Models the ApiKey resource lifecycle and the invariants that the /api-keys
// REST collection must uphold:
//
//   - api key ids are unique
//   - every api key has an owner (creator_id)
//   - the prefix (first 8 chars of the key) is stored for identification
//   - the key hash is stored, never the raw key
//   - api keys can be enabled/disabled (revocation)
//   - a deleted user's api keys are cascade-removed
//   - system-minted keys (e.g. sandbox session keys) are flagged for
//     filtering, and only they are reaped by the expired-key cleanup sweep
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
    creatorId: str,  // owner
    name: str,
    prefix: str,  // first 8 chars of the raw key, for identification
    keyHash: str, // bcrypt hash of the raw key
    enabled: bool,
    system: bool, // true for system-minted keys (e.g. sandbox session keys)
    expiresAt: int, // expiry timestamp; 0 means the key never expires
    roleId: str,  // optional restricting role id; "" means no restriction
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
    k.creatorId != ""

  // Every api key has a non-empty name.
  def hasName(k: ApiKey): bool =
    k.name != ""

  // The key hash is never the raw key (modeled: hash is always "HASH").
  def keyHashedAtRest(k: ApiKey): bool =
    k.keyHash == "HASH"

  // Create an api key. The raw key is generated and returned once; the stored
  // key has the hash. Modeled: we store "HASH" as the hash value. An optional
  // roleId restricts the key's effective permissions (ANDed with the user's
  // roles at authz time); "" means no restriction.
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

  // Set the restricting role id on an api key. An empty roleId clears the
  // restriction (reverts to the principal's baseline roles).
  action setRoleId(id: str, roleId: str, now: int): bool = all {
    apiKeys.exists(k => k.id == id),
    apiKeys' = apiKeys.map(k =>
      if (k.id == id)
        { ...k, roleId: roleId, updatedAt: now }
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
  action removeByUser(creatorId: str): bool = all {
    apiKeys' = apiKeys.filter(k => k.creatorId != creatorId),
    true
  }

  // When a role is deleted, the FK on api_keys.role_id is SET NULL, widening
  // the key back to the principal's baseline permissions (modeled: roleId -> "").
  action removeRole(roleId: str): bool = all {
    apiKeys' = apiKeys.map(k =>
      if (k.roleId == roleId)
        { ...k, roleId: "" }
      else
        k),
    true
  }

  // The expired-key cleanup sweep: removes system keys whose expiry is at or
  // before `now`. User-minted (non-system) keys are never swept — they are
  // user data. Keys with expiresAt == 0 never expire.
  action removeExpiredSystem(now: int): bool = all {
    apiKeys' = apiKeys.filter(k =>
      not(k.system and k.expiresAt != 0 and k.expiresAt <= now)),
    true
  }

  // Authenticate with an api key. Succeeds iff an enabled key exists with
  // a matching hash. Modeled: the presented raw key hashes to "HASH" iff it's
  // non-empty (any non-empty key verifies against "HASH" for simplicity).
  // The authenticated principal carries the key's roleId so authz can AND it
  // with the user's roles (see rbac.qnt effectiveFilterWithApiKey).
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
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.creatorId == "u1")),
        apiKeys' = apiKeys,
      })
  }

  run cannotReuseId = {
    init.then(create({ id: "k1", creatorId: "u1", name: "key1", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k1", creatorId: "u2", name: "key2", prefix: "oh_def34", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateWithoutOwner = {
    init.then(create({ id: "k1", creatorId: "", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateWithoutName = {
    init.then(create({ id: "k1", creatorId: "u1", name: "", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateWithPlaintextKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "oh_abc123456789", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run canDisableApiKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("k1", false, 1))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and not(k.enabled))),
        apiKeys' = apiKeys,
      })
  }

  run canReenableApiKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("k1", false, 1))
      .then(setEnabled("k1", true, 2))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.enabled)),
        apiKeys' = apiKeys,
      })
  }

  run authenticateSucceeds = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(authenticate("k1", "oh_abc123456789"))
      .then(all {
        apiKeys' = apiKeys,
      })
  }

  run authenticateFailsForDisabledKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(setEnabled("k1", false, 1))
      .then(authenticate("k1", "oh_abc123456789"))
      .fail()
  }

  run authenticateFailsForEmptyKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(authenticate("k1", ""))
      .fail()
  }

  run authenticateFailsForNonexistentKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(authenticate("k2", "oh_abc123456789"))
      .fail()
  }

  run canDeleteApiKey = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(remove("k1"))
      .then(all {
        assert(not(apiKeys.exists(k => k.id == "k1"))),
        assert(apiKeys.size() == 0),
        apiKeys' = apiKeys,
      })
  }

  run cascadeDeleteByUser = {
    init.then(create({ id: "k1", creatorId: "u1", name: "key1", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k2", creatorId: "u1", name: "key2", prefix: "oh_def34", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k3", creatorId: "u2", name: "key3", prefix: "oh_ghi56", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(removeByUser("u1"))
      .then(all {
        assert(not(apiKeys.exists(k => k.creatorId == "u1"))),
        assert(apiKeys.exists(k => k.creatorId == "u2")),
        assert(apiKeys.size() == 1),
        apiKeys' = apiKeys,
      })
  }

  run canUpdateName = {
    init.then(create({ id: "k1", creatorId: "u1", name: "old-name", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(updateName("k1", "new-name", 1))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.name == "new-name")),
        apiKeys' = apiKeys,
      })
  }

  run sameUserMultipleKeys = {
    init.then(create({ id: "k1", creatorId: "u1", name: "key1", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k2", creatorId: "u1", name: "key2", prefix: "oh_def34", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(apiKeys.filter(k => k.creatorId == "u1").size() == 2),
        apiKeys' = apiKeys,
      })
  }

  run canSetRoleId = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(setRoleId("k1", "r1", 1))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.roleId == "r1")),
        apiKeys' = apiKeys,
      })
  }

  run canClearRoleId = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "r1", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(setRoleId("k1", "", 1))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.roleId == "")),
        apiKeys' = apiKeys,
      })
  }

  // Deleting a role SET NULLs the roleId on keys that referenced it.
  run deleteRoleClearsKeyId = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "r1", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "k2", creatorId: "u1", name: "other", prefix: "oh_def34", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(removeRole("r1"))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.roleId == "")),
        assert(apiKeys.exists(k => k.id == "k2" and k.roleId == "")),
        apiKeys' = apiKeys,
      })
  }

  run canCreateWithRoleId = {
    init.then(create({ id: "k1", creatorId: "u1", name: "my-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "r1", system: false, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1" and k.roleId == "r1")),
        apiKeys' = apiKeys,
      })
  }

  // The cleanup sweep removes a system key whose expiry is in the past.
  run expiredSystemKeysAreSwept = {
    init.then(create({ id: "k1", creatorId: "u1", name: "Sandbox s1 API key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "r-api-key", system: true, expiresAt: 5, createdAt: 0, updatedAt: 0 }))
      .then(removeExpiredSystem(10))
      .then(all {
        assert(not(apiKeys.exists(k => k.id == "k1"))),
        apiKeys' = apiKeys,
      })
  }

  // An expired user-minted key survives the sweep: user keys are user data.
  run expiredUserKeysAreNeverSwept = {
    init.then(create({ id: "k1", creatorId: "u1", name: "user-key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "", system: false, expiresAt: 5, createdAt: 0, updatedAt: 0 }))
      .then(removeExpiredSystem(10))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1")),
        apiKeys' = apiKeys,
      })
  }

  // A system key whose expiry is still in the future survives the sweep.
  run unexpiredSystemKeysSurvive = {
    init.then(create({ id: "k1", creatorId: "u1", name: "Sandbox s1 API key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "r-api-key", system: true, expiresAt: 100, createdAt: 0, updatedAt: 0 }))
      .then(removeExpiredSystem(10))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1")),
        apiKeys' = apiKeys,
      })
  }

  // A system key with no expiry (expiresAt == 0) never expires.
  run neverExpiringSystemKeysSurvive = {
    init.then(create({ id: "k1", creatorId: "u1", name: "Sandbox s1 API key", prefix: "oh_abc12", keyHash: "HASH", enabled: true, roleId: "r-api-key", system: true, expiresAt: 0, createdAt: 0, updatedAt: 0 }))
      .then(removeExpiredSystem(10))
      .then(all {
        assert(apiKeys.exists(k => k.id == "k1")),
        apiKeys' = apiKeys,
      })
  }
}
