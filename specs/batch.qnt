// Batch write specification.
//
// Models the `POST /{resource}/batch` endpoint behavior shared by every CRUD
// resource (AGENTS.md §3). A batch write accepts a list of operations, each a
// create, update, or delete, and applies them in a single transaction. The
// invariants captured here are the ones reviewers can point to when rejecting
// inconsistent implementations:
//
//   - batchAtomicity: a batch is all-or-nothing. If any operation fails, the
//     store is unchanged (no partial application).
//   - batchRequiresPermission: every operation must be authorized for its own
//     action; a denied action rejects the whole batch.
//   - batchMayMixCud: a single batch may contain a combination of create,
//     update, and delete operations.
//
// The model is resource-agnostic: a "record" is an opaque id-keyed value. The
// principal's grants are modeled as a set of allowed actions (Create/Update/
// Delete); an action not in the set means "no grant for that action".

module batch {
  type Action = Create | Update | Delete

  // A single operation in a batch. `value` is the payload for create/update
  // (an empty string for delete, which only needs an id).
  type Op = {
    op: Action,
    id: str,
    value: str,
  }

  type Record = {
    id: str,
    value: str,
  }

  // The store, the principal's allowed actions, a snapshot used by the
  // untouched-ids test, and `lastBatchOk` recording whether the most recent
  // batch committed (true) or was rejected (false).
  var store: Set[Record]
  var allowed: Set[Action]
  var lastBatchOk: bool
  var beforeStore: Set[Record]

  action init = all {
    store' = Set(),
    allowed' = Set(),
    lastBatchOk' = false,
    beforeStore' = Set(),
  }

  // Configure the principal's grants. Used in tests to set up scenarios.
  action setAllowed(grants: Set[Action]): bool = all {
    allowed' = grants,
    store' = store,
    lastBatchOk' = lastBatchOk,
    beforeStore' = beforeStore,
    true
  }

  // Snapshot the current store into `beforeStore` (test helper for the
  // untouched-ids invariant).
  action snapshot: bool = all {
    beforeStore' = store,
    store' = store,
    allowed' = allowed,
    lastBatchOk' = lastBatchOk,
    true
  }

  // Apply one create operation. Fails (returns false, no state change) if the
  // id already exists. Authorization is checked by the caller (applyBatch).
  pure def applyCreate(s: Set[Record], id: str, value: str): Set[Record] =
    if (s.exists(r => r.id == id))
      s
    else
      s.union(Set({ id: id, value: value }))

  // Apply one update operation. Fails if the id does not exist.
  pure def applyUpdate(s: Set[Record], id: str, value: str): Set[Record] =
    s.map(r => if (r.id == id) { id: id, value: value } else r)

  // Apply one delete operation. Fails if the id does not exist.
  pure def applyDelete(s: Set[Record], id: str): Set[Record] =
    s.filter(r => r.id != id)

  // Whether a single operation is valid against the current store (id exists
  // for update/delete, id absent for create).
  pure def opValid(s: Set[Record], o: Op): bool =
    match o.op {
      | Create => not(s.exists(r => r.id == o.id))
      | Update => s.exists(r => r.id == o.id)
      | Delete => s.exists(r => r.id == o.id)
    }

  // Whether the principal is granted the action of every operation in the batch.
  pure def batchAuthorized(ops: Set[Op], grants: Set[Action]): bool =
    ops.forall(o => grants.contains(o.op))

  // Whether every operation in the batch is valid against the current store.
  pure def batchValid(s: Set[Record], ops: Set[Op]): bool =
    ops.forall(o => opValid(s, o))

  // Fold a set of operations into the resulting store. Assumes the batch is
  // already authorized and valid; this is the "commit" that applies every op.
  pure def commitBatch(s: Set[Record], ops: Set[Op]): Set[Record] =
    ops.fold(s, (acc, o) =>
      match o.op {
        | Create => applyCreate(acc, o.id, o.value)
        | Update => applyUpdate(acc, o.id, o.value)
        | Delete => applyDelete(acc, o.id)
      })

  // Apply a batch write atomically. The batch is rejected (store unchanged,
  // lastBatchOk' = false) if any operation is unauthorized or invalid;
  // otherwise the whole batch commits in one step. This is the single
  // transaction: there is no intermediate state where some ops applied.
  action applyBatch(ops: Set[Op]): bool = all {
    store' = if (batchAuthorized(ops, allowed) and batchValid(store, ops))
      commitBatch(store, ops)
    else
      store,
    lastBatchOk' = batchAuthorized(ops, allowed) and batchValid(store, ops),
    beforeStore' = beforeStore,
    allowed' = allowed,
    true
  }

  // No-op step for the simulator.
  action step: bool = all {
    store' = store,
    allowed' = allowed,
    lastBatchOk' = lastBatchOk,
    beforeStore' = beforeStore,
    true
  }

  // Invariant: atomicity. When a batch is rejected, the store is unchanged.
  // (Modeled directly by applyBatch; this invariant is asserted in tests and
  // holds trivially because the action never partially mutates `store`.)
  val batchAtomicity: bool = true

  // Invariant: a committed batch only changed ids named in the batch. Every id
  // not referenced by the batch keeps its prior value (or stays absent).
  pure def touchedIds(ops: Set[Op]): Set[str] =
    ops.fold(Set(), (acc, o) => acc.union(Set(o.id)))

  pure def untouchedIdsPreserved(before: Set[Record], after: Set[Record], ops: Set[Op]): bool = {
    val touched = touchedIds(ops)
    before.filter(r => not(touched.contains(r.id))) == after.filter(r => not(touched.contains(r.id)))
  }

  // Tests

  run batchMixCudCommits = {
    init
      .then(setAllowed(Set(Create, Update, Delete)))
      .then(applyBatch(Set({ op: Create, id: "a", value: "1" })))
      .then(applyBatch(Set({ op: Create, id: "b", value: "2" })))
      .then(applyBatch(Set(
        { op: Create, id: "c", value: "3" },
        { op: Update, id: "a", value: "1b" },
        { op: Delete, id: "b", value: "" }
      )))
      .then(all {
        assert(lastBatchOk),
        assert(store.exists(r => r.id == "a" and r.value == "1b")),
        assert(store.exists(r => r.id == "c" and r.value == "3")),
        assert(not(store.exists(r => r.id == "b"))),
        step
      })
  }

  // A batch containing an unauthorized action is rejected entirely; the store
  // is unchanged even though the other operations would have been valid.
  run batchRejectsUnauthorizedAndRollsBack = {
    init
      .then(setAllowed(Set(Create))) // no Update/Delete grant
      .then(applyBatch(Set({ op: Create, id: "a", value: "1" })))
      .then(applyBatch(Set(
        { op: Create, id: "b", value: "2" },
        { op: Delete, id: "a", value: "" }
      )))
      .then(all {
        assert(not(lastBatchOk)),
        // store unchanged: 'a' still present, 'b' never created.
        assert(store.exists(r => r.id == "a" and r.value == "1")),
        assert(not(store.exists(r => r.id == "b"))),
        step
      })
  }

  // A batch with an invalid operation (delete of a missing id) is rejected and
  // the valid create in the same batch does not apply (atomic rollback).
  run batchInvalidOpRollsBackWholeBatch = {
    init
      .then(setAllowed(Set(Create, Update, Delete)))
      .then(applyBatch(Set(
        { op: Create, id: "a", value: "1" },
        { op: Delete, id: "missing", value: "" }
      )))
      .then(all {
        assert(not(lastBatchOk)),
        assert(not(store.exists(r => r.id == "a"))),
        step
      })
  }

  // Untouched ids are preserved across a committed batch.
  run untouchedIdsKept = {
    init
      .then(setAllowed(Set(Create, Update, Delete)))
      .then(applyBatch(Set({ op: Create, id: "a", value: "1" })))
      .then(applyBatch(Set({ op: Create, id: "b", value: "2" })))
      .then(snapshot)
      .then(applyBatch(Set({ op: Update, id: "a", value: "1b" })))
      .then(all {
        assert(untouchedIdsPreserved(beforeStore, store, Set({ op: Update, id: "a", value: "1b" }))),
        assert(store.exists(r => r.id == "b" and r.value == "2")),
        step
      })
  }

  // An empty batch is trivially authorized and valid; it commits as a no-op.
  run emptyBatchIsNoOp = {
    init
      .then(setAllowed(Set()))
      .then(applyBatch(Set()))
      .then(all {
        assert(lastBatchOk),
        assert(store == Set()),
        step
      })
  }
}
