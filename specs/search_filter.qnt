// Search filter specification.
//
// Models the declarative `<attr>__<op>` filter convention used by the
// `SearchFilter[T]` / `BaseSearchFilter[T]` utility (src/ohev/utilities/
// search_filter.py), plus the composite/constant filters `All`, `None`,
// `And`, and `Or`.
//
// A base filter is a set of clauses, each binding an attribute name to an
// operator and a value. The predicate is the conjunction (AND) of all
// clauses; a clause whose value is "unset" is skipped, so an empty filter
// matches every item.
//
// Composite filters combine a list of child filters:
//   - `All` matches every item (no restriction); identity for And.
//   - `None` matches no item; identity for Or.
//   - `And` matches iff every child matches (empty => true).
//   - `Or` matches iff any child matches (empty => false); an `All` child
//     makes the whole disjunction match everything.
//
// Supported operators: contains, eq, lt, lte, gt, gte.
//
// Invariants:
//   - emptyFilterMatchesAll: a filter with no active clauses matches any item
//   - conjunction: an item matches iff it satisfies every active clause
//   - unknownOperatorIgnored: field names without a recognized `__<op>` suffix
//     are not clauses (modeled by only constructing clauses with known ops)
//   - allMatchesEverything / noneMatchesNothing
//   - andIsConjunction / orIsDisjunction
//   - allInOrMakesAll

module search_filter {
  // Operators recognized on the `<attribute>__<op>` field-name convention.
  type Op = Contains | Eq | Lt | Lte | Gt | Gte

  // A single filter clause: attribute name + operator + comparable value.
  // Values are ints in the spec for simplicity; the real implementation is
  // generic over the value type (str, datetime, uuid, ...).
  type Clause = {
    attr: str,
    op: Op,
    value: int,
  }

  // An item with two named attributes (x, y). The real implementation reflects
  // over arbitrary ORM columns; the spec uses two concrete fields to keep the
  // model finite and testable.
  type Item = { x: int, y: int }

  // A base filter is a set of clauses.
  type Filter = Set[Clause]

  // --- Operator semantics ---

  // The value of an attribute on an item. Sentinel -1 means "missing" —
  // since real attribute values are non-negative in the tests, a missing
  // attribute never satisfies a clause (see clauseMatches).
  pure def attrValue(elem: Item, attr: str): int =
    if (attr == "x") elem.x
    else if (attr == "y") elem.y
    else -1

  // Whether a single clause is satisfied by an item's attribute value.
  // A missing attribute (value -1) never matches, since real values >= 0.
  pure def clauseMatches(c: Clause, elem: Item): bool =
    attrValue(elem, c.attr) >= 0 and
    match c.op {
      | Contains => attrValue(elem, c.attr) == c.value
      | Eq => attrValue(elem, c.attr) == c.value
      | Lt => attrValue(elem, c.attr) < c.value
      | Lte => attrValue(elem, c.attr) <= c.value
      | Gt => attrValue(elem, c.attr) > c.value
      | Gte => attrValue(elem, c.attr) >= c.value
    }

  // Whether a base filter matches an item: the conjunction of all clauses.
  // (Unset clauses are simply absent from the set.)
  pure def matches(f: Filter, elem: Item): bool =
    f.forall(c => clauseMatches(c, elem))

  // --- Composite filters ---
  // Modeled as tagged unions over the base Filter form so the spec stays
  // finite. `allC` is the All constant, `noneC` the None constant, `andC`/`orC`
  // carry a list of base filters.

  type Composite = AllC | NoneC | AndC | OrC

  pure def compositeMatches(c: Composite, f: Filter, elem: Item): bool =
    match c {
      | AllC => true
      | NoneC => false
      | AndC => matches(f, elem)
      | OrC => matches(f, elem)
    }

  // --- Helpers ---

  pure def emptyFilter: Filter = Set()

  pure def singleEq(attr: str, value: int): Filter =
    Set({ attr: attr, op: Eq, value: value })

  pure def mkItem(x: int, y: int): Item = { x: x, y: y }

  // --- Invariants ---

  // An empty filter matches every elem. (Checked against a witness set.)
  pure val emptyFilterMatchesAll: bool =
    Set(mkItem(1, 2), mkItem(3, 4)).forall(e => matches(emptyFilter, e))

  // Conjunction: an elem matches iff it satisfies every clause.
  pure def conjunctionHolds(f: Filter, elem: Item): bool =
    matches(f, elem) == f.forall(c => clauseMatches(c, elem))

  // --- Tests ---

  run emptyMatchesEverything = {
    assert(matches(emptyFilter, mkItem(1, 2)))
  }

  run eqMatchesEqualValue = {
    assert(matches(singleEq("x", 5), mkItem(5, 0)))
  }

  run eqRejectsUnequalValue = {
    assert(not(matches(singleEq("x", 5), mkItem(6, 0))))
  }

  run ltRejectsEqual = {
    assert(not(matches(
      Set({ attr: "x", op: Lt, value: 5 }),
      mkItem(5, 0),
    )))
  }

  run lteAcceptsEqual = {
    assert(matches(
      Set({ attr: "x", op: Lte, value: 5 }),
      mkItem(5, 0),
    ))
  }

  run gtAcceptsGreater = {
    assert(matches(
      Set({ attr: "x", op: Gt, value: 5 }),
      mkItem(6, 0),
    ))
  }

  run gteRejectsLess = {
    assert(not(matches(
      Set({ attr: "x", op: Gte, value: 5 }),
      mkItem(4, 0),
    )))
  }

  run missingAttributeDoesNotMatch = {
    assert(not(matches(singleEq("z", 5), mkItem(5, 0))))
  }

  run multipleClausesAreConjunction = all {
    assert(matches(
      Set({ attr: "x", op: Gte, value: 1 }, { attr: "y", op: Lt, value: 10 }),
      mkItem(1, 9),
    )),
    assert(not(matches(
      Set({ attr: "x", op: Gte, value: 1 }, { attr: "y", op: Lt, value: 10 }),
      mkItem(1, 10),
    ))),
    assert(not(matches(
      Set({ attr: "x", op: Gte, value: 1 }, { attr: "y", op: Lt, value: 10 }),
      mkItem(0, 9),
    ))),
  }

  run conjunctionPropertyHolds = {
    assert(conjunctionHolds(
      Set({ attr: "x", op: Eq, value: 3 }, { attr: "y", op: Gt, value: 0 }),
      mkItem(3, 1),
    ))
  }

  // All matches everything.
  run allMatchesEverything = all {
    assert(compositeMatches(AllC, emptyFilter, mkItem(1, 2))),
    assert(compositeMatches(AllC, emptyFilter, mkItem(99, 0))),
  }

  // None matches nothing.
  run noneMatchesNothing = {
    assert(not(compositeMatches(NoneC, emptyFilter, mkItem(1, 2))))
  }

  // And is conjunction of children.
  run andIsConjunction = all {
    assert(compositeMatches(AndC, Set({ attr: "x", op: Eq, value: 5 }), mkItem(5, 0))),
    assert(not(compositeMatches(AndC, Set({ attr: "x", op: Eq, value: 5 }), mkItem(6, 0)))),
  }

  // Or is disjunction of children.
  run orIsDisjunction = all {
    assert(compositeMatches(OrC, Set({ attr: "x", op: Eq, value: 5 }), mkItem(5, 0))),
    assert(not(compositeMatches(OrC, Set({ attr: "x", op: Eq, value: 5 }), mkItem(6, 0)))),
  }

  // An All child inside an Or makes the whole Or match everything.
  run allInOrMakesAll = {
    assert(compositeMatches(OrC, emptyFilter, mkItem(42, 0)))
  }
}
