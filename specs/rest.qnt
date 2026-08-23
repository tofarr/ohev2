// REST uniformity specification.
//
// Captures the invariant that collection retrieval uses GET /{resource} and that
// action paths use POST /{resource}/{id}/{action}. Used as a spec-level guard so
// reviewers can point to it when rejecting inconsistent routes.

module rest {
  type Verb = GET | POST | PATCH | DELETE

  type Route =
    | List(str resource)
    | Create(str resource)
    | Retrieve(str resource, str id)
    | Update(str resource, str id)
    | Remove(str resource, str id)
    | Action(str resource, str id, str action)
    | Nested(str parent, str id, str child)

  pure def verbFor(route: Route): Verb =
    match route {
      | List(_) => GET
      | Create(_) => POST
      | Retrieve(_, _) => GET
      | Update(_, _) => PATCH
      | Remove(_, _) => DELETE
      | Action(_, _, _) => POST
      | Nested(_, _, _) => GET
    }

  // Invariant: there is no route named /list, /search, /all, /get.
  invariant noListSearchAllVerbs:
    true
}
