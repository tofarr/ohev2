// CORS allow-list specification: the permitted-origin set.
//
// Models the state of the single, deployment-wide `allowed_origins` set that
// the CORS middleware reads (cached) to decide whether a request Origin gets
// `Access-Control-Allow-Origin`. The set is mutated through two actions:
//
//   add(o)    — register a permitted origin (no-op if already present).
//   remove(o) — drop a permitted origin (no-op if absent).
//
// The middleware decision is modelled as `allows(o)`, a pure query over the
// current set: an origin is allowed iff it is a member of the set.
//
// Invariants:
//   - Origins are unique (the set semantics enforce this; add is idempotent).
//   - An origin is allowed iff it has been added and not since removed.
//   - The set is global: it is independent of any OAuth client or principal.

module cors {
  var origins: Set[str]

  action init: bool = all {
    origins' = Set(),
    true,
  }

  action addOrigin(o: str): bool = all {
    origins' = origins.union(Set(o)),
    true,
  }

  action removeOrigin(o: str): bool = all {
    origins' = origins.filter(x => x != o),
    true,
  }

  // Pure query the middleware uses: an Origin is permitted iff it is in the set.
  def allows(o: str): bool = origins.contains(o)

  // Invariant: an origin is allowed iff present in the set.
  val allowedIffPresent: bool =
    origins.forall(o => allows(o) == origins.contains(o))

  // Tests

  run addThenAllows = {
    init.then(addOrigin("https://a.example.com"))
      .then(all {
        assert(allows("https://a.example.com")),
        assert(not(allows("https://b.example.com"))),
        origins' = origins,
      })
  }

  run removeDisallows = {
    init.then(addOrigin("https://a.example.com"))
      .then(removeOrigin("https://a.example.com"))
      .then(all {
        assert(not(allows("https://a.example.com"))),
        origins' = origins,
      })
  }

  run addIdempotent = {
    init.then(addOrigin("https://a.example.com"))
      .then(addOrigin("https://a.example.com"))
      .then(all {
        assert(origins.size() == 1),
        origins' = origins,
      })
  }

  run removeIdempotent = {
    init.then(addOrigin("https://a.example.com"))
      .then(removeOrigin("https://a.example.com"))
      .then(removeOrigin("https://a.example.com"))
      .then(all {
        assert(origins == Set()),
        origins' = origins,
      })
  }
}

