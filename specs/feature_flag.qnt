// Feature flag assignment specification.
//
// Models feature flags plus role- and user-specific assignment rows. A flag is
// enabled for a principal when it is globally enabled, assigned to one of the
// principal's roles, or assigned directly to the principal's user id.
//
// Assignment creation is authorized against both the assignment resource and the
// related resources: the actor must be able to read the feature flag and must be
// able to read the target role or target user respectively.

module feature_flag {
  type ResourceKind = FlagResource | RoleResource | UserResource

  type FeatureFlag = {
    id: str,
    enabled: bool,
  }

  type UserRole = {
    userId: str,
    roleId: str,
  }

  type RoleAssignment = {
    flagId: str,
    roleId: str,
  }

  type UserAssignment = {
    flagId: str,
    userId: str,
  }

  type ReadGrant = {
    actorId: str,
    kind: ResourceKind,
    resourceId: str,
  }

  var flags: Set[FeatureFlag]
  var users: Set[str]
  var roles: Set[str]
  var userRoles: Set[UserRole]
  var roleAssignments: Set[RoleAssignment]
  var userAssignments: Set[UserAssignment]
  var readGrants: Set[ReadGrant]

  action init = all {
    flags' = Set(),
    users' = Set(),
    roles' = Set(),
    userRoles' = Set(),
    roleAssignments' = Set(),
    userAssignments' = Set(),
    readGrants' = Set(),
  }

  pure def flagExists(flagId: str, fs: Set[FeatureFlag]): bool =
    fs.exists(f => f.id == flagId)

  pure def canRead(actorId: str, kind: ResourceKind, resourceId: str, grants: Set[ReadGrant]): bool =
    grants.exists(g => g.actorId == actorId and g.kind == kind and g.resourceId == resourceId)

  pure def heldRoles(userId: str, urs: Set[UserRole]): Set[str] =
    urs.filter(ur => ur.userId == userId).map(ur => ur.roleId)

  pure def globallyEnabled(fs: Set[FeatureFlag]): Set[str] =
    fs.filter(f => f.enabled).map(f => f.id)

  pure def roleEnabled(userId: str, urs: Set[UserRole], ras: Set[RoleAssignment]): Set[str] = {
    val roleIds = heldRoles(userId, urs)
    ras.filter(ra => roleIds.contains(ra.roleId)).map(ra => ra.flagId)
  }

  pure def directlyEnabled(userId: str, uas: Set[UserAssignment]): Set[str] =
    uas.filter(ua => ua.userId == userId).map(ua => ua.flagId)

  pure def enabledFor(
    userId: str,
    fs: Set[FeatureFlag],
    urs: Set[UserRole],
    ras: Set[RoleAssignment],
    uas: Set[UserAssignment]
  ): Set[str] =
    globallyEnabled(fs).union(roleEnabled(userId, urs, ras)).union(directlyEnabled(userId, uas))

  action createFlag(id: str, isEnabled: bool): bool = all {
    not(flagExists(id, flags)),
    flags' = flags.union(Set({ id: id, enabled: isEnabled })),
    users' = users,
    roles' = roles,
    userRoles' = userRoles,
    roleAssignments' = roleAssignments,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  action createUser(id: str): bool = all {
    not(users.contains(id)),
    users' = users.union(Set(id)),
    flags' = flags,
    roles' = roles,
    userRoles' = userRoles,
    roleAssignments' = roleAssignments,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  action createRole(id: str): bool = all {
    not(roles.contains(id)),
    roles' = roles.union(Set(id)),
    flags' = flags,
    users' = users,
    userRoles' = userRoles,
    roleAssignments' = roleAssignments,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  action assignRoleToUser(userId: str, roleId: str): bool = all {
    users.contains(userId),
    roles.contains(roleId),
    not(userRoles.exists(ur => ur.userId == userId and ur.roleId == roleId)),
    userRoles' = userRoles.union(Set({ userId: userId, roleId: roleId })),
    flags' = flags,
    users' = users,
    roles' = roles,
    roleAssignments' = roleAssignments,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  action grantRead(actorId: str, kind: ResourceKind, resourceId: str): bool = all {
    readGrants' = readGrants.union(Set({ actorId: actorId, kind: kind, resourceId: resourceId })),
    flags' = flags,
    users' = users,
    roles' = roles,
    userRoles' = userRoles,
    roleAssignments' = roleAssignments,
    userAssignments' = userAssignments,
  }

  action createRoleAssignment(actorId: str, flagId: str, roleId: str): bool = all {
    canRead(actorId, FlagResource, flagId, readGrants),
    canRead(actorId, RoleResource, roleId, readGrants),
    flagExists(flagId, flags),
    roles.contains(roleId),
    not(roleAssignments.exists(ra => ra.flagId == flagId and ra.roleId == roleId)),
    roleAssignments' = roleAssignments.union(Set({ flagId: flagId, roleId: roleId })),
    flags' = flags,
    users' = users,
    roles' = roles,
    userRoles' = userRoles,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  action createUserAssignment(actorId: str, flagId: str, userId: str): bool = all {
    canRead(actorId, FlagResource, flagId, readGrants),
    canRead(actorId, UserResource, userId, readGrants),
    flagExists(flagId, flags),
    users.contains(userId),
    not(userAssignments.exists(ua => ua.flagId == flagId and ua.userId == userId)),
    userAssignments' = userAssignments.union(Set({ flagId: flagId, userId: userId })),
    flags' = flags,
    users' = users,
    roles' = roles,
    userRoles' = userRoles,
    roleAssignments' = roleAssignments,
    readGrants' = readGrants,
  }

  action deleteFlag(flagId: str): bool = all {
    flagExists(flagId, flags),
    flags' = flags.filter(f => f.id != flagId),
    roleAssignments' = roleAssignments.filter(ra => ra.flagId != flagId),
    userAssignments' = userAssignments.filter(ua => ua.flagId != flagId),
    users' = users,
    roles' = roles,
    userRoles' = userRoles,
    readGrants' = readGrants,
  }

  action deleteUser(userId: str): bool = all {
    users.contains(userId),
    users' = users.filter(u => u != userId),
    userRoles' = userRoles.filter(ur => ur.userId != userId),
    userAssignments' = userAssignments.filter(ua => ua.userId != userId),
    flags' = flags,
    roles' = roles,
    roleAssignments' = roleAssignments,
    readGrants' = readGrants,
  }

  action deleteRole(roleId: str): bool = all {
    roles.contains(roleId),
    roles' = roles.filter(r => r != roleId),
    userRoles' = userRoles.filter(ur => ur.roleId != roleId),
    roleAssignments' = roleAssignments.filter(ra => ra.roleId != roleId),
    flags' = flags,
    users' = users,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  action step: bool = all {
    flags' = flags,
    users' = users,
    roles' = roles,
    userRoles' = userRoles,
    roleAssignments' = roleAssignments,
    userAssignments' = userAssignments,
    readGrants' = readGrants,
  }

  val roleAssignmentsUnique: bool =
    roleAssignments.forall(a =>
      roleAssignments.forall(b =>
        (a.flagId == b.flagId and a.roleId == b.roleId) implies a == b))

  val userAssignmentsUnique: bool =
    userAssignments.forall(a =>
      userAssignments.forall(b =>
        (a.flagId == b.flagId and a.userId == b.userId) implies a == b))

  val roleAssignmentsReferenceExisting: bool =
    roleAssignments.forall(ra => flagExists(ra.flagId, flags) and roles.contains(ra.roleId))

  val userAssignmentsReferenceExisting: bool =
    userAssignments.forall(ua => flagExists(ua.flagId, flags) and users.contains(ua.userId))

  run globallyEnabledFlagIsReturned = {
    init
      .then(createUser("u1"))
      .then(createFlag("f1", true))
      .then(all {
        assert(enabledFor("u1", flags, userRoles, roleAssignments, userAssignments).contains("f1")),
        step
      })
  }

  run roleAssignmentEnablesFlagForRoleHolder = {
    init
      .then(createUser("actor"))
      .then(createUser("u1"))
      .then(createRole("r1"))
      .then(createFlag("f1", false))
      .then(grantRead("actor", FlagResource, "f1"))
      .then(grantRead("actor", RoleResource, "r1"))
      .then(assignRoleToUser("u1", "r1"))
      .then(createRoleAssignment("actor", "f1", "r1"))
      .then(all {
        assert(enabledFor("u1", flags, userRoles, roleAssignments, userAssignments).contains("f1")),
        step
      })
  }

  run userAssignmentEnablesFlagForOnlyThatUser = {
    init
      .then(createUser("actor"))
      .then(createUser("u1"))
      .then(createUser("u2"))
      .then(createFlag("f1", false))
      .then(grantRead("actor", FlagResource, "f1"))
      .then(grantRead("actor", UserResource, "u1"))
      .then(createUserAssignment("actor", "f1", "u1"))
      .then(all {
        assert(enabledFor("u1", flags, userRoles, roleAssignments, userAssignments).contains("f1")),
        assert(not(enabledFor("u2", flags, userRoles, roleAssignments, userAssignments).contains("f1"))),
        step
      })
  }

  run roleAssignmentRequiresFlagRead = {
    init
      .then(createUser("actor"))
      .then(createRole("r1"))
      .then(createFlag("f1", false))
      .then(grantRead("actor", RoleResource, "r1"))
      .then(createRoleAssignment("actor", "f1", "r1"))
      .fail()
  }

  run roleAssignmentRequiresRoleRead = {
    init
      .then(createUser("actor"))
      .then(createRole("r1"))
      .then(createFlag("f1", false))
      .then(grantRead("actor", FlagResource, "f1"))
      .then(createRoleAssignment("actor", "f1", "r1"))
      .fail()
  }

  run userAssignmentRequiresFlagRead = {
    init
      .then(createUser("actor"))
      .then(createUser("u1"))
      .then(createFlag("f1", false))
      .then(grantRead("actor", UserResource, "u1"))
      .then(createUserAssignment("actor", "f1", "u1"))
      .fail()
  }

  run userAssignmentRequiresUserRead = {
    init
      .then(createUser("actor"))
      .then(createUser("u1"))
      .then(createFlag("f1", false))
      .then(grantRead("actor", FlagResource, "f1"))
      .then(createUserAssignment("actor", "f1", "u1"))
      .fail()
  }
}
