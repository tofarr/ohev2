// Secret specification: secrets are permissioned resources with optional ownership.
//
// A Secret carries an optional creator_id owner (the creating principal). Access
// is governed by the generic AclPermission policy stored in the role's
// secret_permission JSONB column — the per-secret link tables have been removed.
//
// The sensitive payload lives in a separate detail table (not modelled here
// beyond its existence). The /secrets surface returns metadata only; decrypted
// plaintext is revealed solely through the /secret-values projection, which
// requires membership in both the read-grant set and the SecretValuePermission
// set (defense in depth).

module secret {
  type Secret = { id: str, code: str }

  type RoleSecretPermission = {
    roleId: str,
    secretId: str,
    readEnabled: bool,
    updateEnabled: bool,
    deleteEnabled: bool,
  }

  type UserSecretPermission = {
    userId: str,
    secretId: str,
    readEnabled: bool,
    updateEnabled: bool,
    deleteEnabled: bool,
  }

  var secrets: Set[Secret]
  var roleSecretPermissions: Set[RoleSecretPermission]
  var userSecretPermissions: Set[UserSecretPermission]
  var secretValuePermissions: Set[str]

  action init = all {
    secrets' = Set(),
    roleSecretPermissions' = Set(),
    userSecretPermissions' = Set(),
    secretValuePermissions' = Set(),
  }

  pure def flagAllows(readEnabled: bool, updateEnabled: bool, deleteEnabled: bool, act: str): bool =
    if (act == "read" or act == "search") readEnabled
    else if (act == "update") updateEnabled
    else if (act == "delete") deleteEnabled
    else false

  pure def roleGrantAllows(grant: RoleSecretPermission, act: str): bool =
    flagAllows(grant.readEnabled, grant.updateEnabled, grant.deleteEnabled, act)

  pure def userGrantAllows(grant: UserSecretPermission, act: str): bool =
    flagAllows(grant.readEnabled, grant.updateEnabled, grant.deleteEnabled, act)

  pure def canAccessSecret(
    userId: str,
    roleIds: Set[str],
    secretId: str,
    act: str,
    directGrants: Set[UserSecretPermission],
    roleGrants: Set[RoleSecretPermission],
  ): bool =
    if (act == "create") true
    else directGrants.exists(grant =>
      grant.userId == userId and grant.secretId == secretId and userGrantAllows(grant, act))
      or roleGrants.exists(grant =>
        roleIds.contains(grant.roleId)
          and grant.secretId == secretId
          and roleGrantAllows(grant, act))

  pure def canReadSecret(
    userId: str,
    roleIds: Set[str],
    secretId: str,
    directGrants: Set[UserSecretPermission],
    roleGrants: Set[RoleSecretPermission],
  ): bool =
    canAccessSecret(userId, roleIds, secretId, "read", directGrants, roleGrants)

  pure def canRevealValue(
    userId: str,
    roleIds: Set[str],
    secretId: str,
    directGrants: Set[UserSecretPermission],
    roleGrants: Set[RoleSecretPermission],
    valuePermittedUsers: Set[str],
  ): bool =
    canReadSecret(userId, roleIds, secretId, directGrants, roleGrants)
      and valuePermittedUsers.contains(userId)

  action createSecret(userId: str, newSecret: Secret): bool = all {
    not(secrets.exists(secret => secret.id == newSecret.id)),
    not(secrets.exists(secret => secret.code == newSecret.code)),
    secrets' = secrets.union(Set(newSecret)),
    roleSecretPermissions' = roleSecretPermissions,
    userSecretPermissions' = userSecretPermissions.union(Set({
      userId: userId,
      secretId: newSecret.id,
      readEnabled: true,
      updateEnabled: true,
      deleteEnabled: true,
    })),
    secretValuePermissions' = secretValuePermissions,
    true,
  }

  action grantUserSecretPermission(grant: UserSecretPermission): bool = all {
    secrets.exists(secret => secret.id == grant.secretId),
    not(userSecretPermissions.exists(existing =>
      existing.userId == grant.userId and existing.secretId == grant.secretId)),
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions,
    userSecretPermissions' = userSecretPermissions.union(Set(grant)),
    secretValuePermissions' = secretValuePermissions,
    true,
  }

  action grantRoleSecretPermission(grant: RoleSecretPermission): bool = all {
    secrets.exists(secret => secret.id == grant.secretId),
    not(roleSecretPermissions.exists(existing =>
      existing.roleId == grant.roleId and existing.secretId == grant.secretId)),
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions.union(Set(grant)),
    userSecretPermissions' = userSecretPermissions,
    secretValuePermissions' = secretValuePermissions,
    true,
  }

  action grantSecretValuePermission(userId: str): bool = all {
    not(secretValuePermissions.contains(userId)),
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions,
    userSecretPermissions' = userSecretPermissions,
    secretValuePermissions' = secretValuePermissions.union(Set(userId)),
    true,
  }

  action deleteSecret(secretId: str): bool = all {
    secrets.exists(secret => secret.id == secretId),
    secrets' = secrets.filter(secret => secret.id != secretId),
    roleSecretPermissions' = roleSecretPermissions.filter(grant => grant.secretId != secretId),
    userSecretPermissions' = userSecretPermissions.filter(grant => grant.secretId != secretId),
    secretValuePermissions' = secretValuePermissions,
    true,
  }

  action deleteUser(userId: str): bool = all {
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions,
    userSecretPermissions' = userSecretPermissions.filter(grant => grant.userId != userId),
    secretValuePermissions' = secretValuePermissions.filter(u => u != userId),
    true,
  }

  val secretCodesUnique: bool =
    secrets.forall(a => secrets.forall(b => (a.code == b.code) implies a.id == b.id))

  val userSecretPermissionsUnique: bool =
    userSecretPermissions.forall(a => userSecretPermissions.forall(b =>
      (a.userId == b.userId and a.secretId == b.secretId) implies a == b))

  val userSecretPermissionsReferenceSecret: bool =
    userSecretPermissions.forall(grant => secrets.exists(secret => secret.id == grant.secretId))

  val roleSecretPermissionsReferenceSecret: bool =
    roleSecretPermissions.forall(grant => secrets.exists(secret => secret.id == grant.secretId))

  run creatorReceivesDirectGrant = {
    init
      .then(createSecret("u1", { id: "s1", code: "API_KEY" }))
      .then(all {
        assert(canAccessSecret("u1", Set(), "s1", "read", userSecretPermissions, roleSecretPermissions)),
        assert(canAccessSecret("u1", Set(), "s1", "update", userSecretPermissions, roleSecretPermissions)),
        assert(canAccessSecret("u1", Set(), "s1", "delete", userSecretPermissions, roleSecretPermissions)),
        secrets' = secrets,
        roleSecretPermissions' = roleSecretPermissions,
        userSecretPermissions' = userSecretPermissions,
        secretValuePermissions' = secretValuePermissions,
      })
  }

  run directUserGrantAllowsRead = {
    init
      .then(createSecret("creator", { id: "s1", code: "API_KEY" }))
      .then(grantUserSecretPermission({
        userId: "u2",
        secretId: "s1",
        readEnabled: true,
        updateEnabled: false,
        deleteEnabled: false,
      }))
      .then(all {
        assert(canAccessSecret("u2", Set(), "s1", "read", userSecretPermissions, roleSecretPermissions)),
        assert(not(canAccessSecret("u2", Set(), "s1", "update", userSecretPermissions, roleSecretPermissions))),
        secrets' = secrets,
        roleSecretPermissions' = roleSecretPermissions,
        userSecretPermissions' = userSecretPermissions,
        secretValuePermissions' = secretValuePermissions,
      })
  }

  run roleGrantAllowsRead = {
    init
      .then(createSecret("creator", { id: "s1", code: "API_KEY" }))
      .then(grantRoleSecretPermission({
        roleId: "r1",
        secretId: "s1",
        readEnabled: true,
        updateEnabled: false,
        deleteEnabled: false,
      }))
      .then(all {
        assert(canAccessSecret("u2", Set("r1"), "s1", "read", userSecretPermissions, roleSecretPermissions)),
        assert(not(canAccessSecret("u2", Set("r1"), "s1", "delete", userSecretPermissions, roleSecretPermissions))),
        secrets' = secrets,
        roleSecretPermissions' = roleSecretPermissions,
        userSecretPermissions' = userSecretPermissions,
        secretValuePermissions' = secretValuePermissions,
      })
  }

  run secretHasNoSingularOwner = {
    init
      .then(createSecret("u1", { id: "s1", code: "API_KEY" }))
      .then(deleteUser("u1"))
      .then(all {
        assert(secrets.exists(secret => secret.id == "s1")),
        assert(not(userSecretPermissions.exists(grant => grant.userId == "u1"))),
        secrets' = secrets,
        roleSecretPermissions' = roleSecretPermissions,
        userSecretPermissions' = userSecretPermissions,
        secretValuePermissions' = secretValuePermissions,
      })
  }

  run valueRevealRequiresBothPerms = {
    init
      .then(createSecret("creator", { id: "s1", code: "API_KEY" }))
      .then(grantUserSecretPermission({
        userId: "u2",
        secretId: "s1",
        readEnabled: true,
        updateEnabled: false,
        deleteEnabled: false,
      }))
      .then(all {
        // u2 can read the secret metadata...
        assert(canReadSecret("u2", Set(), "s1", userSecretPermissions, roleSecretPermissions)),
        // ...but cannot reveal the value without the value-reveal permission.
        assert(not(canRevealValue("u2", Set(), "s1", userSecretPermissions, roleSecretPermissions, secretValuePermissions))),
        secrets' = secrets,
        roleSecretPermissions' = roleSecretPermissions,
        userSecretPermissions' = userSecretPermissions,
        secretValuePermissions' = secretValuePermissions,
      })
      .then(grantSecretValuePermission("u2"))
      .then(all {
        // Now u2 can reveal (both read access and value permission).
        assert(canRevealValue("u2", Set(), "s1", userSecretPermissions, roleSecretPermissions, secretValuePermissions)),
        secrets' = secrets,
        roleSecretPermissions' = roleSecretPermissions,
        userSecretPermissions' = userSecretPermissions,
        secretValuePermissions' = secretValuePermissions,
      })
  }
}
