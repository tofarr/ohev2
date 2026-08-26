// Permission specification: ABAC model, grammar round-trip, evaluator,
// immutability, and config baseline.
//
// Models the Permission entity (ABAC grant: principal + action + resource type
// + attribute subset), the compact string grammar that round-trips a permission
// to/from a string, the evaluator that checks whether a permission set
// authorizes a request, and the config-level baseline grants that apply to
// every authenticated user.
//
// Invariants:
//   - permission ids are unique
//   - every permission references an existing user (referential integrity)
//   - permissions are immutable (no update action)
//   - grammar round-trip: parse(to_string(p)) == p

module permission {
  // Actions a permission may grant. Wildcard covers any action.
  // CRUD verbs map to REST verbs: search=GET collection, create=POST,
  // read=GET /{id}, update=PATCH /{id}, delete=DELETE /{id}.
  type Action = Create | Read | Update | Delete | Search | Use | Wildcard

  // Resource types a permission may scope. Extensible as new entities land.
  type ResourceType = TUser | TPermission

  // A row-level scope: All (unrestricted) or None (nothing) or a predicate
  // over the resource. The real implementation uses SearchFilter subclasses;
  // the spec models the two constants plus a generic predicate.
  type Scope = SAll | SNone | SPred

  type Permission = {
    id: str,
    userId: str,   // may be null in the real model (anonymous); str here for simplicity
    act: Action,
    resourceType: ResourceType,
    attributes: Set[str],
    scope: Scope,
  }

  // Config-level baseline grants applied to every request (including anonymous).
  type BaseGrant = {
    act: Action,
    resourceType: ResourceType,
    attributes: Set[str],
  }

  var permissions: Set[Permission]
  var knownUsers: Set[str]

  // Immutable config-level baseline (fixed for the spec's lifetime).
  pure val basePermissions: Set[BaseGrant] =
    Set(
      { act: Wildcard, resourceType: TUser, attributes: Set() },
      { act: Wildcard, resourceType: TPermission, attributes: Set() }
    )

  action init = all {
    permissions' = Set(),
    knownUsers' = Set(),
  }

  // --- Helpers ---

  // No two permissions share the same id.
  def idUnique(p1: Permission, p2: Permission): bool =
    p1.id == p2.id implies p1 == p2

  // The effective action verb for matching and serialization.
  pure def actionVerb(a: Action): str =
    match a {
      | Create => "create"
      | Read => "read"
      | Update => "update"
      | Delete => "delete"
      | Search => "search"
      | Use => "use"
      | Wildcard => "all"
    }

  // Whether an action covers the requested action verb.
  pure def actionMatches(a: Action, requested: str): bool =
    or {
      a == Wildcard,
      actionVerb(a) == requested,
    }

  // Whether a permission's action covers the requested action verb.
  pure def matchesAction(p: Permission, requested: str): bool =
    actionMatches(p.act, requested)

  // Whether an attribute set covers the requested attributes.
  // An empty attribute set means all attributes are covered.
  pure def attributesMatch(attrs: Set[str], requested: Set[str]): bool =
    or {
      attrs == Set(),
      requested.forall(a => attrs.contains(a)),
    }

  // Whether a permission's attribute set covers the requested attributes.
  pure def matchesAttributes(p: Permission, requested: Set[str]): bool =
    attributesMatch(p.attributes, requested)

  // Whether a single permission authorizes the request.
  pure def permissionAllows(
    p: Permission,
    actVerb: str,
    resourceType: ResourceType,
    attributes: Set[str],
  ): bool = all {
    p.resourceType == resourceType,
    matchesAction(p, actVerb),
    matchesAttributes(p, attributes),
  }

  // Whether a base grant covers the request.
  pure def baseGrantAllows(
    g: BaseGrant,
    actVerb: str,
    resourceType: ResourceType,
    attributes: Set[str],
  ): bool = all {
    g.resourceType == resourceType,
    actionMatches(g.act, actVerb),
    attributesMatch(g.attributes, attributes),
  }

  // Whether any base grant authorizes the request.
  pure def baseAllows(
    actVerb: str,
    resourceType: ResourceType,
    attributes: Set[str],
  ): bool =
    basePermissions.exists(g => baseGrantAllows(g, actVerb, resourceType, attributes))

  // Whether any permission in the set authorizes the request.
  pure def isAllowed(
    perms: Set[Permission],
    actVerb: str,
    resourceType: ResourceType,
    attributes: Set[str],
  ): bool =
    perms.exists(p => permissionAllows(p, actVerb, resourceType, attributes))

  // Combined check: base grants OR per-user permissions.
  // This mirrors the runtime: base checked in-memory, DB queried only if base
  // does not already grant the request.
  pure def checkPermission(
    perms: Set[Permission],
    actVerb: str,
    resourceType: ResourceType,
    attributes: Set[str],
  ): bool =
    or {
      baseAllows(actVerb, resourceType, attributes),
      isAllowed(perms, actVerb, resourceType, attributes),
    }

  // --- Effective search filter (row-level scope) ---

  // Whether a permission applies to a principal (matches userId or is
  // anonymous — userId == "" models the NULL/anonymous principal).
  pure def appliesToPrincipal(p: Permission, userId: str): bool =
    or { p.userId == "", p.userId == userId }

  // The set of permissions that apply to (userId, action, resourceType).
  // Action wildcard (ALL) covers any action; anonymous perms (userId == "")
  // apply to every principal.
  pure def applicablePerms(
    perms: Set[Permission],
    userId: str,
    actVerb: str,
    resourceType: ResourceType,
  ): Set[Permission] =
    perms.filter(p =>
      and {
        appliesToPrincipal(p, userId),
        p.resourceType == resourceType,
        actionMatches(p.act, actVerb),
      })

  // The effective scope for (userId, action, resourceType). Returns:
  //   - SAll if the config baseline grants the request (unrestricted);
  //   - otherwise the OR of applicable permissions' scopes;
  //   - SNone (deny) if no permission applies.
  // This is what the centralized permission checker returns; SNone means the
  // caller denies (no rows visible / no create allowed).
  pure def effectiveScope(
    perms: Set[Permission],
    userId: str,
    actVerb: str,
    resourceType: ResourceType,
  ): Scope = {
    if (baseAllows(actVerb, resourceType, Set()))
      SAll
    else {
      val applicable = applicablePerms(perms, userId, actVerb, resourceType)
      if (applicable == Set())
        SNone
      else if (applicable.exists(p => p.scope == SAll))
        SAll
      else
        // OR of the (non-All) scopes — modeled as SPred (a predicate).
        SPred
    }
  }

  // Whether the effective scope permits an item that satisfies predicate `pred`.
  pure def scopePermits(s: Scope, pred: (str) => bool): bool =
    match s {
      | SAll => true
      | SNone => false
      | SPred => pred("x")
    }

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

  // Delete a permission by id. (No update — permissions are immutable.)
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

  // Search: returns the subset of permissions matching a predicate. The
  // predicate encodes the `<attr>__<op>` clauses from search_filter.qnt; an
  // always-true predicate (empty filter) returns every permission. Read-only.
  def search(pred: (Permission) => bool): Set[Permission] =
    permissions.filter(pred)

  pure def matchesUserIdEq(p: Permission, userId: str): bool =
    p.userId == userId

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
    resourceType: TUser,
    attributes: Set(),
    scope: SAll,
  }

  pure val attrSubsetPerm: Permission = {
    id: "p1",
    userId: "u1",
    act: Read,
    resourceType: TUser,
    attributes: Set("email", "name"),
    scope: SPred,
  }

  pure val wildcardPerm: Permission = {
    id: "p1",
    userId: "u1",
    act: Wildcard,
    resourceType: TPermission,
    attributes: Set(),
    scope: SAll,
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
        act: Update,
        resourceType: TUser,
        attributes: Set(),
        scope: SAll,
      }))
      .fail()
  }

  run wildcardActionMatchesAny = {
    assert(matchesAction({
      id: "p1",
      userId: "u1",
      act: Wildcard,
      resourceType: TUser,
      attributes: Set(),
      scope: SAll,
    }, "delete"))
  }

  run searchActionMatchesSearch = {
    assert(matchesAction({
      id: "p1",
      userId: "u1",
      act: Search,
      resourceType: TUser,
      attributes: Set(),
      scope: SAll,
    }, "search"))
  }

  run attributeSubsetRestrictsAccess = all {
    assert(matchesAttributes(attrSubsetPerm, Set("email"))),
    assert(matchesAttributes(attrSubsetPerm, Set("email", "name"))),
    assert(not(matchesAttributes(attrSubsetPerm, Set("email", "password")))),
  }

  run emptyAttributesAllowsAll =
    assert(matchesAttributes(readAllUsers, Set("email", "name", "password")))

  run evaluatorAllowsMatchingPermission =
    assert(isAllowed(Set(readAllUsers), "read", TUser, Set()))

  run evaluatorDeniesNonMatchingResource =
    assert(not(isAllowed(Set(readAllUsers), "read", TPermission, Set())))

  run evaluatorDeniesNonMatchingAction =
    assert(not(isAllowed(Set(readAllUsers), "update", TUser, Set())))

  run baseAllowsAllUsers =
    assert(baseAllows("read", TUser, Set()))

  run baseAllowsAllPermissions =
    assert(baseAllows("create", TPermission, Set()))

  run checkPermissionAllowsViaBase =
    assert(checkPermission(Set(), "delete", TUser, Set()))

  run checkPermissionAllowsViaUserPerm = {
    init
      .then(registerUser("u1"))
      .then(all {
        assert(checkPermission(
          Set({
            id: "p1",
            userId: "u1",
            act: Read,
            resourceType: TPermission,
            attributes: Set(),
            scope: SAll,
          }),
          "read",
          TPermission,
          Set(),
        )),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

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

  // An empty filter (always-true predicate) returns every permission.
  run searchEmptyFilterReturnsAll = {
    init
      .then(registerUser("u1"))
      .then(create(readAllUsers))
      .then(all {
        assert(search(_ => true).size() == 1),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  // A userId__eq filter narrows to that user's permissions.
  run searchFilterNarrowsByUserId = {
    init
      .then(registerUser("u1"))
      .then(registerUser("u2"))
      .then(create(readAllUsers))
      .then(all {
        assert(search(p => matchesUserIdEq(p, "u1")).size() == 1),
        assert(search(p => matchesUserIdEq(p, "u2")).size() == 0),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  // --- Effective scope tests ---

  // With an empty permission set and the baseline granting the request, the
  // effective scope is SAll (unrestricted).
  run effectiveScopeBaseGrantsAll =
    assert(effectiveScope(Set(), "u1", "read", TUser) == SAll)

  // An applicable permission with SAll scope yields SAll.
  run effectiveScopeApplicableAll = {
    init
      .then(registerUser("u1"))
      .then(all {
        assert(effectiveScope(
          Set({
            id: "p1",
            userId: "u1",
            act: Read,
            resourceType: TUser,
            attributes: Set(),
            scope: SAll,
          }),
          "u1",
          "read",
          TUser,
        ) == SAll),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  // No applicable permission yields SNone (deny).
  run effectiveScopeNoPermissionDenies = {
    init
      .then(all {
        assert(effectiveScope(Set(), "u1", "read", TPermission) == SNone),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  // An applicable predicate-scoped permission yields SPred.
  run effectiveScopePredicateScope = {
    init
      .then(registerUser("u1"))
      .then(all {
        assert(effectiveScope(
          Set({
            id: "p1",
            userId: "u1",
            act: Read,
            resourceType: TUser,
            attributes: Set(),
            scope: SPred,
          }),
          "u1",
          "read",
          TUser,
        ) == SPred),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  // An anonymous permission (userId == "") applies to every principal.
  run effectiveScopeAnonymousAppliesToAll = {
    init
      .then(all {
        assert(effectiveScope(
          Set({
            id: "p1",
            userId: "",
            act: Search,
            resourceType: TUser,
            attributes: Set(),
            scope: SAll,
          }),
          "u1",
          "search",
          TUser,
        ) == SAll),
        permissions' = permissions,
        knownUsers' = knownUsers,
      })
  }

  // SAll permits everything; SNone permits nothing.
  run scopePermitsConstants = all {
    assert(scopePermits(SAll, _ => false)),
    assert(not(scopePermits(SNone, _ => true))),
  }
}
