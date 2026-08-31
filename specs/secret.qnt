// Secret specification: secrets are permissioned resources without singular ownership.
//
// A Secret has no user_id owner. Access is granted by either a direct
// user_secret_permissions row or a role_secret_permissions row whose role is held
// by the principal. Creating a secret also creates a full direct user grant for
// the creator so they can manage the secret without making the secret row owned
// by that user.

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

  action init = all {
    secrets' = Set(),
    roleSecretPermissions' = Set(),
    userSecretPermissions' = Set(),
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
    true,
  }

  action grantUserSecretPermission(grant: UserSecretPermission): bool = all {
    secrets.exists(secret => secret.id == grant.secretId),
    not(userSecretPermissions.exists(existing =>
      existing.userId == grant.userId and existing.secretId == grant.secretId)),
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions,
    userSecretPermissions' = userSecretPermissions.union(Set(grant)),
    true,
  }

  action grantRoleSecretPermission(grant: RoleSecretPermission): bool = all {
    secrets.exists(secret => secret.id == grant.secretId),
    not(roleSecretPermissions.exists(existing =>
      existing.roleId == grant.roleId and existing.secretId == grant.secretId)),
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions.union(Set(grant)),
    userSecretPermissions' = userSecretPermissions,
    true,
  }

  action deleteSecret(secretId: str): bool = all {
    secrets.exists(secret => secret.id == secretId),
    secrets' = secrets.filter(secret => secret.id != secretId),
    roleSecretPermissions' = roleSecretPermissions.filter(grant => grant.secretId != secretId),
    userSecretPermissions' = userSecretPermissions.filter(grant => grant.secretId != secretId),
    true,
  }

  action deleteUser(userId: str): bool = all {
    secrets' = secrets,
    roleSecretPermissions' = roleSecretPermissions,
    userSecretPermissions' = userSecretPermissions.filter(grant => grant.userId != userId),
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
      })
  }
}
