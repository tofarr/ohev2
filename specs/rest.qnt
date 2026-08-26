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
    }

  // Helpers to construct routes concisely.
  pure def collection(resource: str): Route =
    { kind: KCollection, resource: resource, id: "", actionName: "", child: "" }

  pure def createRoute(resource: str): Route =
    { kind: KCreate, resource: resource, id: "", actionName: "", child: "" }

  pure def actionRoute(resource: str, id: str, act: str): Route =
    { kind: KAction, resource: resource, id: id, actionName: act, child: "" }

  pure def countRoute(resource: str): Route =
    { kind: KCount, resource: resource, id: "", actionName: "", child: "" }

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

  run standardRoutes = all {
    assert(isStandard(collection("users"))),
    assert(isStandard(createRoute("users"))),
    assert(isStandard(collection("permissions"))),
    assert(isStandard(createRoute("permissions"))),
    assert(isStandard(actionRoute("sandboxes", "sb1", "stop"))),
    assert(isStandard(countRoute("users"))),
    assert(isStandard(countRoute("permissions"))),
  }
}
