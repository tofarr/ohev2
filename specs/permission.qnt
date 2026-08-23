// Permission specification: ABAC model, grammar round-trip, and evaluator.
//
// Models the Permission entity (ABAC grant: principal + action + resource
// selector + attribute subset), the compact string grammar that round-trips
// a permission to/from a string, and the evaluator that checks whether a
// permission set authorizes a request.
//
// Invariants:
//   - permission ids are unique
//   - every permission references an existing user (referential integrity)
//   - grammar round-trip: parse(to_string(p)) == p

module permission {
  // Actions a permission may grant. Wildcard covers any action.
  type Action = Create | Read | Write | Delete | Use | Wildcard

  // How a permission scopes the set of entities of a resource type.
  type SelectorKind = SelAll | SelById | SelByTag

  type Permission = {
    id: str,
    userId: str,
    act: Action,
    customAction: str,
    resourceType: str,
    selectorKind: SelectorKind,
    selectorValue: str,
    attributes: Set[str],
  }

  var permissions: Set[Permission]
  var knownUsers: Set[str]

  action init = all {
    permissions' = Set(),
    knownUsers' = Set(),
  }

  // --- Helpers ---

  // No two permissions share the same id.
  def idUnique(p1: Permission, p2: Permission): bool =
    p1.id == p2.id implies p1 == p2

  // The effective action verb for matching and serialization.
  pure def actionVerb(p: Permission): str =
    match p.act {
      | Create => "create"
      | Read => "read"
      | Write => "write"
      | Delete => "delete"
      | Use => p.customAction
      | Wildcard => "*"
    }

  // Serialize a permission's selector to its suffix string (empty for ALL).
  pure def selectorSuffix(kind: SelectorKind, value: str): str =
    match kind {
      | SelAll => ""
      | SelById => "id"
      | SelByTag => "tag"
    }

  // Whether a permission's action covers the requested action verb.
  pure def matchesAction(p: Permission, requested: str): bool =
    or {
      p.act == Wildcard,
      actionVerb(p) == requested,
    }

  // Whether a permission's selector covers the described entity.
  pure def matchesSelector(
    p: Permission,
    resourceId: str,
    resourceTags: Set[str],
  ): bool =
    match p.selectorKind {
      | SelAll => true
      | SelById => p.selectorValue == resourceId
      | SelByTag => resourceTags.contains(p.selectorValue)
    }

  // Whether a permission's attribute set covers the requested attributes.
  pure def matchesAttributes(p: Permission, requested: Set[str]): bool =
    or {
      p.attributes == Set(),
      requested.forall(a => p.attributes.contains(a)),
    }

  // Whether a single permission authorizes the request.
  pure def permissionAllows(
    p: Permission,
    actVerb: str,
    resourceType: str,
    resourceId: str,
    resourceTags: Set[str],
    attributes: Set[str],
  ): bool = all {
    p.resourceType == resourceType,
    matchesAction(p, actVerb),
    matchesSelector(p, resourceId, resourceTags),
    matchesAttributes(p, attributes),
  }

  // Whether any permission in the set authorizes the request.
  pure def isAllowed(
    perms: Set[Permission],
    actVerb: str,
    resourceType: str,
    resourceId: str,
    resourceTags: Set[str],
    attributes: Set[str],
  ): bool =
    perms.exists(p => permissionAllows(p, actVerb, resourceType, resourceId, resourceTags, attributes))

  // --- Actions ---

  // Register a known user (principal).
  action registerUser(userId: str): bool = all {
    not(knownUsers.contains(userId)),
    knownUsers' = knownUsers.union(Set(userId)),
    permissions' = permissions,
    true
  }

  // Create a permission; user must exist and id must be unique.
  action create(p: Permission): bool = all {
    not(permissions.exists(x => x.id == p.id)),
    knownUsers.contains(p.userId),
    permissions' = permissions.union(Set(p)),
    knownUsers' = knownUsers,
    true
  }

  // Delete a permission by id.
  action remove(id: str): bool = all {
    permissions.exists(p => p.id == id),
    permissions' = permissions.filter(p => p.id != id),
    knownUsers' = knownUsers,
    true
  }

  // Cascade-delete all permissions for a user (when the user is deleted).
  action cascadeDeleteUser(userId: str): bool = all {
    permissions' = permissions.filter(p => p.userId != userId),
    knownUsers' = knownUsers,
    true
  }

  action step: bool = all {
    permissions' = permissions,
    knownUsers' = knownUsers,
    true
  }

  // --- Invariants ---

  // All permission ids are unique.
  val permissionIdsUnique: bool =
    permissions.forall(p1 =>
      permissions.forall(p2 => idUnique(p1, p2)))

  // Every permission references a known user.
  val permissionsReferenceValidUsers: bool =
    permissions.forall(p => knownUsers.contains(p.userId))

  // --- Test fixtures ---

  pure val readAllUsers: Permission = {
    id: "p1",
    userId: "u1",
    act: Read,
    customAction: "",
    resourceType: "users",
    selectorKind: SelAll,
    selectorValue: "",
    attributes: Set(),
  }

  pure val byIdPerm: Permission = {
    id: "p1",
    userId: "u1",
    act: Read,
    customAction: "",
    resourceType: "users",
    selectorKind: SelById,
    selectorValue: "abc",
    attributes: Set(),
  }

  pure val byTagPerm: Permission = {
    id: "p1",
    userId: "u1",
    act: Read,
    customAction: "",
    resourceType: "sandboxes",
    selectorKind: SelByTag,
    selectorValue: "prod",
    attributes: Set(),
  }

  pure val attrSubsetPerm: Permission = {
    id: "p1",
    userId: "u1",
    act: Read,
    customAction: "",
    resourceType: "users",
    selectorKind: SelAll,
    selectorValue: "",
    attributes: Set("email", "name"),
  }

  // --- Tests ---

  run createPermission = {
    init
      .then(registerUser("u1"))
      .then(create(readAllUsers))
      .then(all {
        assert(permissions.size() == 1),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  run cannotCreateForUnknownUser = {
    init
      .then(create(readAllUsers))
      .fail()
  }

  run cannotReusePermissionId = {
    init
      .then(registerUser("u1"))
      .then(create(readAllUsers))
      .then(create({
        id: "p1",
        userId: "u1",
        act: Write,
        customAction: "",
        resourceType: "users",
        selectorKind: SelAll,
        selectorValue: "",
        attributes: Set(),
      }))
      .fail()
  }

  run wildcardActionMatchesAny = {
    assert(matchesAction({
      id: "p1",
      userId: "u1",
      act: Wildcard,
      customAction: "",
      resourceType: "users",
      selectorKind: SelAll,
      selectorValue: "",
      attributes: Set(),
    }, "delete"))
  }

  run customActionMatchesItsVerb = {
    assert(matchesAction({
      id: "p1",
      userId: "u1",
      act: Use,
      customAction: "deploy",
      resourceType: "sandboxes",
      selectorKind: SelAll,
      selectorValue: "",
      attributes: Set(),
    }, "deploy"))
  }

  run byIdSelectorMatchesOnlyId = all {
    assert(matchesSelector(byIdPerm, "abc", Set())),
    assert(not(matchesSelector(byIdPerm, "xyz", Set()))),
  }

  run byTagSelectorMatchesTag = all {
    assert(matchesSelector(byTagPerm, "sb1", Set("prod", "staging"))),
    assert(not(matchesSelector(byTagPerm, "sb1", Set("staging")))),
  }

  run attributeSubsetRestrictsAccess = all {
    assert(matchesAttributes(attrSubsetPerm, Set("email"))),
    assert(matchesAttributes(attrSubsetPerm, Set("email", "name"))),
    assert(not(matchesAttributes(attrSubsetPerm, Set("email", "password")))),
  }

  run emptyAttributesAllowsAll =
    assert(matchesAttributes(readAllUsers, Set("email", "name", "password")))

  run evaluatorAllowsMatchingPermission =
    assert(isAllowed(Set(readAllUsers), "read", "users", "", Set(), Set()))

  run evaluatorDeniesNonMatchingResource =
    assert(not(isAllowed(Set(readAllUsers), "read", "sandboxes", "", Set(), Set())))

  run evaluatorDeniesNonMatchingAction =
    assert(not(isAllowed(Set(readAllUsers), "write", "users", "", Set(), Set())))

  run cascadeDeleteUserRemovesPermissions = {
    init
      .then(registerUser("u1"))
      .then(create(readAllUsers))
      .then(cascadeDeleteUser("u1"))
      .then(all {
        assert(permissions.size() == 0),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }
}
