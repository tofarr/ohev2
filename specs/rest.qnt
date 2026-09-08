// REST uniformity specification.
//
// Captures the invariant that collection retrieval uses GET /{resource} and that
// action paths use POST /{resource}/{id}/{action}. Used as a spec-level guard so
// reviewers can point to it when rejecting inconsistent routes.

module rest {
  // HTTP verbs supported by the uniform API.
  type Verb = Get | Post | Patch | Delete

  // Route kinds. Every endpoint must be one of these.
  type Kind =
    | KCollection
    | KCreate
    | KRetrieve
    | KUpdate
    | KRemove
    | KAction
    | KNested
    | KCount
    | KBatch
    | KBatchWrite

  // A route is a kind plus the resource path segments that identify it.
  type Route = {
    kind: Kind,
    resource: str,
    id: str,
    actionName: str,
    child: str,
  }

  // Map a route kind to its HTTP verb.
  pure def verbFor(route: Route): Verb =
    match route.kind {
      | KCollection => Get
      | KCreate => Post
      | KRetrieve => Get
      | KUpdate => Patch
      | KRemove => Delete
      | KAction => Post
      | KNested => Get
      | KCount => Get
      | KBatch => Get
      | KBatchWrite => Post
    }

  // A route is standard iff its kind is one of the known kinds.
  pure def isStandard(route: Route): bool =
    match route.kind {
      | KCollection => true
      | KCreate => true
      | KRetrieve => true
      | KUpdate => true
      | KRemove => true
      | KAction => true
      | KNested => true
      | KCount => true
      | KBatch => true
      | KBatchWrite => true
    }

  // A route is protected iff it carries an auth/permission dependency.
  // Every registered route must satisfy this unless it is a member of the
  // public exemption set (AGENTS.md §9). Enforced in code by
  // tests/unit/test_route_permissions.py.
  type RouteWithProtection = {
    route: Route,
    protected: bool,
  }

  // The intentionally-public exemption set, modeled as a predicate over a
  // route's resource and kind (Quint has no string concatenation, so paths
  // are not assembled; the resource/kind pair identifies the route). These
  // are the only routes that may bypass the permission-dependency requirement:
  // the liveness probe, OIDC discovery, the OAuth2 credential-minting flow,
  // and the built-in dev IdP. The LLM/MCP proxy forwarders authenticate via
  // the standard permission dependencies (USE on the stored profile), so they
  // are NOT exempted.
  pure def isPublicRoute(route: Route): bool =
    (route.kind == KCollection and route.resource == "health")
    or (route.resource == ".well-known" and route.kind == KCollection)
    or (route.resource == "auth" and route.actionName == "authorize")
    or (route.resource == "auth" and route.actionName == "callback")
    or (route.resource == "auth" and route.actionName == "token")
    or (route.resource == "auth" and route.actionName == "refresh")
    or (route.resource == "auth" and route.actionName == "revoke")
    or (route.resource == "auth" and route.actionName == "logout")
    or (route.resource == "auth-dev" and route.actionName == "authorize")
    or (route.resource == "auth-dev" and route.actionName == "login")
    or (route.resource == "auth-dev" and route.actionName == "token")
    or (route.resource == "auth-dev" and route.actionName == "refresh")

  // A route satisfies the protection invariant iff it is protected or it is
  // a member of the public exemption set.
  pure def satisfiesProtection(rwp: RouteWithProtection): bool =
    rwp.protected or isPublicRoute(rwp.route)

  // Invariant: every registered route is protected unless explicitly exempted.
  pure def allRoutesProtected(rwps: Set[RouteWithProtection]): bool =
    rwps.forall(satisfiesProtection)

  // Helpers to construct routes concisely.
  pure def collection(resource: str): Route =
    { kind: KCollection, resource: resource, id: "", actionName: "", child: "" }

  pure def createRoute(resource: str): Route =
    { kind: KCreate, resource: resource, id: "", actionName: "", child: "" }

  pure def actionRoute(resource: str, id: str, act: str): Route =
    { kind: KAction, resource: resource, id: id, actionName: act, child: "" }

  pure def countRoute(resource: str): Route =
    { kind: KCount, resource: resource, id: "", actionName: "", child: "" }

  pure def batchRoute(resource: str): Route =
    { kind: KBatch, resource: resource, id: "", actionName: "", child: "" }

  pure def batchWriteRoute(resource: str): Route =
    { kind: KBatchWrite, resource: resource, id: "", actionName: "", child: "" }

  // Helpers to construct protected/unprotected route wrappers concisely.
  pure def protected(route: Route): RouteWithProtection =
    { route: route, protected: true }

  pure def unprotected(route: Route): RouteWithProtection =
    { route: route, protected: false }

  // A /health-style collection route (resource "health") used to exercise the
  // public-route exemption.
  pure def healthRoute: Route =
    collection("health")

  // An auth OAuth-flow action route, used to exercise the public-route exemption.
  pure def authTokenRoute: Route =
    actionRoute("auth", "{id}", "token")

  // Tests

  run listIsGet = {
    assert(verbFor(collection("conversations")) == Get)
  }

  run actionIsPost = {
    assert(verbFor(actionRoute("sandboxes", "sb1", "start")) == Post)
  }

  run countIsGet = {
    assert(verbFor(countRoute("users")) == Get)
  }

  run batchIsGet = {
    assert(verbFor(batchRoute("users")) == Get)
  }

  run batchWriteIsPost = {
    assert(verbFor(batchWriteRoute("users")) == Post)
  }

  run standardRoutes = all {
    assert(isStandard(collection("users"))),
    assert(isStandard(createRoute("users"))),
    assert(isStandard(collection("permissions"))),
    assert(isStandard(createRoute("permissions"))),
    assert(isStandard(actionRoute("sandboxes", "sb1", "stop"))),
    assert(isStandard(countRoute("users"))),
    assert(isStandard(countRoute("permissions"))),
    assert(isStandard(batchRoute("users"))),
    assert(isStandard(batchRoute("roles"))),
    assert(isStandard(batchRoute("user-roles"))),
    assert(isStandard(batchRoute("cors-origins"))),
    assert(isStandard(batchRoute("auth-clients"))),
    assert(isStandard(batchRoute("feature-flags"))),
    assert(isStandard(batchRoute("feature-flag-role-assignments"))),
    assert(isStandard(batchRoute("feature-flag-user-assignments"))),
    assert(isStandard(batchRoute("mcp-server-configs"))),
    assert(isStandard(batchRoute("role-mcp-server-config-permissions"))),
    assert(isStandard(batchWriteRoute("users"))),
    assert(isStandard(batchWriteRoute("roles"))),
    assert(isStandard(batchWriteRoute("user-roles"))),
    assert(isStandard(batchWriteRoute("cors-origins"))),
    assert(isStandard(batchWriteRoute("auth-clients"))),
    assert(isStandard(batchWriteRoute("feature-flags"))),
    assert(isStandard(batchWriteRoute("feature-flag-role-assignments"))),
    assert(isStandard(batchWriteRoute("feature-flag-user-assignments"))),
    assert(isStandard(batchWriteRoute("mcp-server-configs"))),
    assert(isStandard(batchWriteRoute("role-mcp-server-config-permissions"))),
  }

  // Protection invariant (AGENTS.md §9): every route is protected unless it is
  // a member of the public exemption set (isPublicRoute).

  run protectedRouteSatisfiesInvariant = {
    assert(allRoutesProtected(Set(protected(collection("users")))))
  }

  run healthIsExempted = {
    assert(allRoutesProtected(Set(unprotected(healthRoute))))
  }

  run authTokenIsExempted = {
    assert(allRoutesProtected(Set(unprotected(authTokenRoute))))
  }

  run unprotectedNonExemptedViolates = {
    assert(not(allRoutesProtected(Set(unprotected(collection("users"))))))
  }
}
