// RBAC specification: role-based access control evaluation.
//
// Models how a principal's effective permissions are computed from their
// assigned roles (AGENTS.md §11). The core invariants:
//
//   - A principal's effective filter for an entity/action is the disjunction
//     (OR) of all filters from their assigned roles.
//   - If any role grants Permitted, the effective filter is All (full access).
//   - If all roles grant Denied (or the principal has no roles), the effective
//     filter is None (no access).
//   - ReadOnly grants access for read/search actions only.
//
// The model uses simplified filter types: All (matches everything), None
// (matches nothing), and Custom (a non-trivial filter). The real implementation
// uses SearchFilter[T] with SQL predicates; the spec abstracts to these three
// cases for tractability.
//
// UserRole assignments are modeled as a set of (user_id, role_id) pairs with
// a uniqueness constraint. Cascade-delete on user/role removal is modeled.

module rbac {
  // Simplified permission policies (mirrors role.qnt).
  type Permission = Permitted | Denied | ReadOnly

  // Simplified search filter results.
  type Filter = All | None | Custom

  // A role with per-entity permissions.
  type Role = {
    id: str,
    permissions: str -> Permission,
  }

  // A user-role assignment.
  type UserRole = {
    userId: str,
    roleId: str,
  }

  var roles: Set[Role]
  var userRoles: Set[UserRole]

  action init = all {
    roles' = Set(),
    userRoles' = Set(),
  }

  // Get the permission for an entity from a role, defaulting to Denied.
  pure def getPermission(r: Role, entity: str): Permission =
    if (r.permissions.keys().contains(entity))
      r.permissions.get(entity)
    else
      Denied

  // Convert a permission to a filter for a given action.
  pure def permissionToFilter(p: Permission, act: str): Filter =
    match p {
      | Permitted => All
      | Denied => None
      | ReadOnly =>
          if (act == "read" or act == "search") All
          else None
    }

  // Combine two filters with OR semantics (disjunction).
  // All OR x = All; None OR x = x; Custom OR Custom = Custom
  pure def orFilters(f1: Filter, f2: Filter): Filter =
    match f1 {
      | All => All
      | None => f2
      | Custom => match f2 {
          | All => All
          | None => Custom
          | Custom => Custom
        }
    }

  // Get all roles assigned to a user.
  pure def rolesForUser(userId: str, rs: Set[Role], urs: Set[UserRole]): Set[Role] =
    rs.filter(r => urs.exists(ur => ur.userId == userId and ur.roleId == r.id))

  // Compute the effective filter for a user on an entity/action.
  // This is the OR of all filters from the user's assigned roles.
  pure def effectiveFilter(userId: str, entity: str, act: str,
                           rs: Set[Role], urs: Set[UserRole]): Filter =
    rolesForUser(userId, rs, urs).fold(None, (acc, r) =>
      orFilters(acc, permissionToFilter(getPermission(r, entity), act))
    )

  // Create a role.
  action createRole(r: Role): bool = all {
    not(roles.exists(x => x.id == r.id)),
    roles' = roles.union(Set(r)),
    userRoles' = userRoles,
    true
  }

  // Delete a role (cascades to user-role assignments).
  action deleteRole(roleId: str): bool = all {
    roles.exists(r => r.id == roleId),
    roles' = roles.filter(r => r.id != roleId),
    userRoles' = userRoles.filter(ur => ur.roleId != roleId),
    true
  }

  // Assign a role to a user. The (userId, roleId) pair must be unique.
  action assignRole(userId: str, roleId: str): bool = all {
    roles.exists(r => r.id == roleId),
    not(userRoles.exists(ur => ur.userId == userId and ur.roleId == roleId)),
    roles' = roles,
    userRoles' = userRoles.union(Set({ userId: userId, roleId: roleId })),
    true
  }

  // Unassign a role from a user.
  action unassignRole(userId: str, roleId: str): bool = all {
    userRoles.exists(ur => ur.userId == userId and ur.roleId == roleId),
    roles' = roles,
    userRoles' = userRoles.filter(ur => not(ur.userId == userId and ur.roleId == roleId)),
    true
  }

  // Delete a user (cascades to user-role assignments).
  action deleteUser(userId: str): bool = all {
    roles' = roles,
    userRoles' = userRoles.filter(ur => ur.userId != userId),
    true
  }

  action step: bool = all {
    roles' = roles,
    userRoles' = userRoles,
    true
  }

  // Invariant: user-role assignments are unique on (userId, roleId).
  val userRoleUnique: bool =
    userRoles.forall(ur1 =>
      userRoles.forall(ur2 =>
        (ur1.userId == ur2.userId and ur1.roleId == ur2.roleId) implies ur1 == ur2))

  // Invariant: every user-role references an existing role.
  val userRoleReferencesExistingRole: bool =
    userRoles.forall(ur => roles.exists(r => r.id == ur.roleId))

  // Tests

  run noRolesMeansNoAccess = {
    init
      .then(all {
        assert(effectiveFilter("u1", "user", "read", roles, userRoles) == None),
        assert(effectiveFilter("u1", "user", "create", roles, userRoles) == None),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  run permittedGrantsAll = {
    init
      .then(createRole({ id: "r1", permissions: Map().set("user", Permitted) }))
      .then(assignRole("u1", "r1"))
      .then(all {
        assert(effectiveFilter("u1", "user", "read", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "create", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "delete", roles, userRoles) == All),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  run deniedGrantsNone = {
    init
      .then(createRole({ id: "r1", permissions: Map().set("user", Denied) }))
      .then(assignRole("u1", "r1"))
      .then(all {
        assert(effectiveFilter("u1", "user", "read", roles, userRoles) == None),
        assert(effectiveFilter("u1", "user", "create", roles, userRoles) == None),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  run readOnlyGrantsReadAndSearch = {
    init
      .then(createRole({ id: "r1", permissions: Map().set("user", ReadOnly) }))
      .then(assignRole("u1", "r1"))
      .then(all {
        assert(effectiveFilter("u1", "user", "read", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "search", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "create", roles, userRoles) == None),
        assert(effectiveFilter("u1", "user", "update", roles, userRoles) == None),
        assert(effectiveFilter("u1", "user", "delete", roles, userRoles) == None),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // Union semantics: if one role grants Permitted, the effective filter is All.
  run unionPermittedWins = {
    init
      .then(createRole({ id: "r1", permissions: Map().set("user", Denied) }))
      .then(createRole({ id: "r2", permissions: Map().set("user", Permitted) }))
      .then(assignRole("u1", "r1"))
      .then(assignRole("u1", "r2"))
      .then(all {
        assert(effectiveFilter("u1", "user", "read", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "create", roles, userRoles) == All),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // Union semantics: ReadOnly + Denied = ReadOnly behavior.
  run unionReadOnlyOverridesDenied = {
    init
      .then(createRole({ id: "r1", permissions: Map().set("user", Denied) }))
      .then(createRole({ id: "r2", permissions: Map().set("user", ReadOnly) }))
      .then(assignRole("u1", "r1"))
      .then(assignRole("u1", "r2"))
      .then(all {
        assert(effectiveFilter("u1", "user", "read", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "search", roles, userRoles) == All),
        assert(effectiveFilter("u1", "user", "create", roles, userRoles) == None),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // Missing entity permission defaults to Denied.
  run missingEntityPermissionIsDenied = {
    init
      .then(createRole({ id: "r1", permissions: Map().set("user", Permitted) }))
      .then(assignRole("u1", "r1"))
      .then(all {
        // "api_key" not in the role's permissions map
        assert(effectiveFilter("u1", "api_key", "read", roles, userRoles) == None),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // User-role uniqueness: cannot assign the same role twice.
  run cannotAssignRoleTwice = {
    init
      .then(createRole({ id: "r1", permissions: Map() }))
      .then(assignRole("u1", "r1"))
      .then(assignRole("u1", "r1"))
      .fail()
  }

  // Cannot assign a non-existent role.
  run cannotAssignNonExistentRole = {
    init
      .then(assignRole("u1", "r1"))
      .fail()
  }

  // Cascade delete: deleting a role removes its user-role assignments.
  run deleteRoleCascadesToUserRoles = {
    init
      .then(createRole({ id: "r1", permissions: Map() }))
      .then(assignRole("u1", "r1"))
      .then(deleteRole("r1"))
      .then(all {
        assert(not(userRoles.exists(ur => ur.roleId == "r1"))),
        assert(userRoles.size() == 0),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // Cascade delete: deleting a user removes their role assignments.
  run deleteUserCascadesToUserRoles = {
    init
      .then(createRole({ id: "r1", permissions: Map() }))
      .then(assignRole("u1", "r1"))
      .then(assignRole("u2", "r1"))
      .then(deleteUser("u1"))
      .then(all {
        assert(not(userRoles.exists(ur => ur.userId == "u1"))),
        assert(userRoles.exists(ur => ur.userId == "u2")),
        assert(userRoles.size() == 1),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // Unassign role.
  run canUnassignRole = {
    init
      .then(createRole({ id: "r1", permissions: Map() }))
      .then(assignRole("u1", "r1"))
      .then(unassignRole("u1", "r1"))
      .then(all {
        assert(not(userRoles.exists(ur => ur.userId == "u1" and ur.roleId == "r1"))),
        assert(userRoles.size() == 0),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // A user can have multiple roles.
  run userCanHaveMultipleRoles = {
    init
      .then(createRole({ id: "r1", permissions: Map() }))
      .then(createRole({ id: "r2", permissions: Map() }))
      .then(assignRole("u1", "r1"))
      .then(assignRole("u1", "r2"))
      .then(all {
        assert(userRoles.filter(ur => ur.userId == "u1").size() == 2),
        roles' = roles,
        userRoles' = userRoles,
      })
  }

  // Different users can have the same role.
  run multipleUsersCanShareRole = {
    init
      .then(createRole({ id: "r1", permissions: Map() }))
      .then(assignRole("u1", "r1"))
      .then(assignRole("u2", "r1"))
      .then(all {
        assert(userRoles.filter(ur => ur.roleId == "r1").size() == 2),
        roles' = roles,
        userRoles' = userRoles,
      })
  }
}
