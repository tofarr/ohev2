// Role entity specification.
//
// Models the Role resource lifecycle and the invariants that the /roles REST
// collection must uphold (AGENTS.md §11):
//
//   - role names are unique
//   - a NULL permission column means "deny" for that entity
//   - deleting a role cascades to UserRole assignments
//
// The per-entity permission columns are modeled as a map from entity name to
// an optional Permission. The real implementation uses explicit columns; the
// spec abstracts over the column set for tractability.
//
// Companion to user.qnt (users hold roles via UserRole) and rbac.qnt (which
// models the permission-union semantics).

module role {
  // Permission policies. Mirrors security_models.py: Permitted grants all,
  // Denied grants none, ReadOnly grants read/search only.
  type Permission = Permitted | Denied | ReadOnly

  // A role bundles a name and per-entity permission policies.
  // The map keys are entity names (e.g. "user", "role", "api_key").
  // A missing key or None value means "deny" for that entity.
  type Role = {
    id: str,
    name: str,
    permissions: str -> Permission,
    createdAt: int,
    updatedAt: int,
  }

  var roles: Set[Role]

  action init = all {
    roles' = Set(),
  }

  // No two roles share the same id.
  def idUnique(r1: Role, r2: Role): bool =
    r1.id == r2.id implies r1 == r2

  // No two roles share the same name.
  def nameUnique(r1: Role, r2: Role): bool =
    r1.name == r2.name implies r1 == r2

  // A role name must be non-empty.
  def nameNonEmpty(r: Role): bool =
    r.name != ""

  // Get the permission for an entity, defaulting to Denied if not present.
  pure def getPermission(r: Role, entity: str): Permission =
    if (r.permissions.keys().contains(entity))
      r.permissions.get(entity)
    else
      Denied

  // Whether a permission grants access for a given action.
  // Actions: "create", "read", "update", "delete", "search", "use"
  pure def permissionGrants(p: Permission, act: str): bool =
    match p {
      | Permitted => true
      | Denied => false
      | ReadOnly => act == "read" or act == "search"
    }

  // Create a role; id and name must not already exist, name must be non-empty.
  action create(r: Role): bool = all {
    not(roles.exists(x => x.id == r.id)),
    not(roles.exists(x => x.name == r.name)),
    nameNonEmpty(r),
    roles' = roles.union(Set(r)),
    true
  }

  // Update a role's name; the new name must not collide with another role.
  action updateName(id: str, newName: str, now: int): bool = all {
    roles.exists(r => r.id == id),
    newName != "",
    not(roles.exists(x => x.id != id and x.name == newName)),
    roles' = roles.map(r =>
      if (r.id == id)
        { id: r.id, name: newName, permissions: r.permissions,
          createdAt: r.createdAt, updatedAt: now }
      else
        r),
    true
  }

  // Set a permission for an entity on a role.
  action setPermission(id: str, entity: str, perm: Permission, now: int): bool = all {
    roles.exists(r => r.id == id),
    roles' = roles.map(r =>
      if (r.id == id)
        { id: r.id, name: r.name,
          permissions: r.permissions.set(entity, perm),
          createdAt: r.createdAt, updatedAt: now }
      else
        r),
    true
  }

  // Clear a permission for an entity (reverts to deny).
  action clearPermission(id: str, entity: str, now: int): bool = all {
    roles.exists(r => r.id == id),
    roles' = roles.map(r =>
      if (r.id == id)
        { id: r.id, name: r.name,
          permissions: r.permissions.keys().filter(k => k != entity).fold(
            Map(),
            (acc, k) => acc.set(k, r.permissions.get(k))
          ),
          createdAt: r.createdAt, updatedAt: now }
      else
        r),
    true
  }

  // Delete a role by id.
  action remove(id: str): bool = all {
    roles.exists(r => r.id == id),
    roles' = roles.filter(r => r.id != id),
    true
  }

  action step: bool = all {
    roles' = roles,
    true
  }

  // Invariant: all role ids are unique.
  val roleIdsUnique: bool =
    roles.forall(r1 =>
      roles.forall(r2 => idUnique(r1, r2)))

  // Invariant: all role names are unique.
  val roleNamesUnique: bool =
    roles.forall(r1 =>
      roles.forall(r2 => nameUnique(r1, r2)))

  // Invariant: every role name is non-empty.
  val roleNamesNonEmpty: bool =
    roles.forall(r => nameNonEmpty(r))

  // Tests

  run createRole = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(roles.exists(r => r.id == "r1" and r.name == "admin")),
        roles' = roles,
      })
  }

  run cannotReuseId = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "r1", name: "user", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotReuseName = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "r2", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run cannotCreateEmptyName = {
    init.then(create({ id: "r1", name: "", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .fail()
  }

  run canUpdateName = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(updateName("r1", "superadmin", 1))
      .then(all {
        assert(roles.exists(r => r.id == "r1" and r.name == "superadmin")),
        roles' = roles,
      })
  }

  run cannotUpdateToExistingName = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(create({ id: "r2", name: "user", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(updateName("r1", "user", 1))
      .fail()
  }

  run canSetPermission = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(setPermission("r1", "user", Permitted, 1))
      .then(all {
        assert(roles.exists(r => r.id == "r1" and getPermission(r, "user") == Permitted)),
        roles' = roles,
      })
  }

  run missingPermissionIsDenied = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(all {
        assert(roles.exists(r => r.id == "r1" and getPermission(r, "api_key") == Denied)),
        roles' = roles,
      })
  }

  run readOnlyGrantsReadAndSearch = {
    init.then(all {
      assert(permissionGrants(ReadOnly, "read")),
      assert(permissionGrants(ReadOnly, "search")),
      assert(not(permissionGrants(ReadOnly, "create"))),
      assert(not(permissionGrants(ReadOnly, "update"))),
      assert(not(permissionGrants(ReadOnly, "delete"))),
      roles' = roles,
    })
  }

  run permittedGrantsAll = {
    init.then(all {
      assert(permissionGrants(Permitted, "create")),
      assert(permissionGrants(Permitted, "read")),
      assert(permissionGrants(Permitted, "update")),
      assert(permissionGrants(Permitted, "delete")),
      assert(permissionGrants(Permitted, "search")),
      assert(permissionGrants(Permitted, "use")),
      roles' = roles,
    })
  }

  run deniedGrantsNothing = {
    init.then(all {
      assert(not(permissionGrants(Denied, "create"))),
      assert(not(permissionGrants(Denied, "read"))),
      assert(not(permissionGrants(Denied, "update"))),
      assert(not(permissionGrants(Denied, "delete"))),
      assert(not(permissionGrants(Denied, "search"))),
      assert(not(permissionGrants(Denied, "use"))),
      roles' = roles,
    })
  }

  run canClearPermission = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(setPermission("r1", "user", Permitted, 1))
      .then(clearPermission("r1", "user", 2))
      .then(all {
        assert(roles.exists(r => r.id == "r1" and getPermission(r, "user") == Denied)),
        roles' = roles,
      })
  }

  run canDeleteRole = {
    init.then(create({ id: "r1", name: "admin", permissions: Map(), createdAt: 0, updatedAt: 0 }))
      .then(remove("r1"))
      .then(all {
        assert(not(roles.exists(r => r.id == "r1"))),
        assert(roles.size() == 0),
        roles' = roles,
      })
  }
}
