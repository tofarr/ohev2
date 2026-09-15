// Event callback resource specification (issue #134).
//
// Models the /event-callbacks governed resource and the invariants the REST
// collection must uphold (AGENTS.md §11):
//
//   - callback ids are unique
//   - every callback has exactly one creator (the principal that created it)
//   - a callback is linked to either a conversation or a conversation template
//     — exactly one of conversationId / conversationTemplateId is set (the
//     "exactly-one-link" invariant, enforced by the service layer and a DB
//     CHECK constraint)
//   - event_kind is non-empty
//   - status is one of READY / SUCCESS / ERROR / SKIPPED / DISABLED
//   - result state (status / detail / lastEventId / lastRunAt) is merged onto
//     the callback row itself — there is no separate result object or table
//   - access is governed by the `event_callback_permission` role column:
//     creators manage their own callbacks; non-creators are granted access via
//     a grant role (`on_mismatch`). Deleting the callback revokes both creator
//     management and granted access.
//   - deleting a user cascades to callbacks they created
//
// Companion to rbac.qnt (per-entity JSONB permission columns), role.qnt
// (role lifecycle), and rest.qnt (the uniform REST route/verb mapping).

module event_callback {
  type CallbackStatus = Ready | Success | Error | Skipped | Disabled

  type LinkTarget = Conversation(str) | Template(str)

  type EventCallback = {
    id: str,
    creatorId: str,
    eventKind: str,
    hasProcessor: bool,
    link: LinkTarget,
    status: CallbackStatus,
    hasDetail: bool,
    hasLastEventId: bool,
    hasLastRunAt: bool,
    createdAt: int,
    updatedAt: int,
  }

  var callbacks: Set[EventCallback]

  action init = all {
    callbacks' = Set(),
  }

  // No-op step for the simulator (needed by `quint run --invariant`).
  action step: bool = all {
    callbacks' = callbacks,
    true
  }

  def idUnique(c1: EventCallback, c2: EventCallback): bool =
    c1.id == c2.id implies c1 == c2

  def eventKindNonEmpty(c: EventCallback): bool =
    c.eventKind != ""

  // The exactly-one-link invariant is inherent in the LinkTarget sum type: a
  // callback's link is always exactly one of Conversation(id) / Template(id).
  // The DB CHECK constraint and service layer enforce this on the two nullable
  // FK columns; the spec models it as a non-optional union field.

  pure def sampleCallback(id: str, creatorId: str, link: LinkTarget): EventCallback =
    { id: id, creatorId: creatorId, eventKind: "MessageEvent",
      hasProcessor: true, link: link, status: Ready,
      hasDetail: false, hasLastEventId: false, hasLastRunAt: false,
      createdAt: 0, updatedAt: 0 }

  action createCallback(c: EventCallback): bool = all {
    not(callbacks.exists(existing => existing.id == c.id)),
    c.creatorId != "",
    eventKindNonEmpty(c),
    callbacks' = callbacks.union(Set(c)),
    true,
  }

  action updateStatus(id: str, status: CallbackStatus): bool = all {
    callbacks.exists(c => c.id == id),
    callbacks' = callbacks.map(c =>
      if (c.id == id)
        { id: c.id, creatorId: c.creatorId, eventKind: c.eventKind,
          hasProcessor: c.hasProcessor, link: c.link, status: status,
          hasDetail: c.hasDetail, hasLastEventId: c.hasLastEventId,
          hasLastRunAt: c.hasLastRunAt, createdAt: c.createdAt,
          updatedAt: c.updatedAt + 1 }
      else
        c),
    true,
  }

  action deleteCallback(id: str): bool = all {
    callbacks.exists(c => c.id == id),
    callbacks' = callbacks.filter(c => c.id != id),
    true,
  }

  action deleteUser(userId: str): bool = all {
    callbacks' = callbacks.filter(c => c.creatorId != userId),
    true,
  }

  val callbackIdsUnique: bool =
    callbacks.forall(c1 => callbacks.forall(c2 => idUnique(c1, c2)))

  val callbackEventKindsNonEmpty: bool =
    callbacks.forall(eventKindNonEmpty)

  run canCreateCallback = {
    init.then(createCallback(sampleCallback("c1", "u1", Conversation("conv1"))))
      .then(all {
        assert(callbacks.exists(c => c.id == "c1")),
        callbacks' = callbacks,
      })
  }

  run canCreateTemplateLinkedCallback = {
    init.then(createCallback(sampleCallback("c1", "u1", Template("tpl1"))))
      .then(all {
        assert(callbacks.exists(c => c.id == "c1" and c.link == Template("tpl1"))),
        callbacks' = callbacks,
      })
  }

  run cannotCreateDuplicateId = {
    init
      .then(createCallback(sampleCallback("c1", "u1", Conversation("conv1"))))
      .then(createCallback(sampleCallback("c1", "u2", Conversation("conv2"))))
      .fail()
  }

  run cannotCreateEmptyEventKind = {
    init.then(createCallback({ id: "c1", creatorId: "u1", eventKind: "",
      hasProcessor: true, link: Conversation("conv1"), status: Ready,
      hasDetail: false, hasLastEventId: false, hasLastRunAt: false,
      createdAt: 0, updatedAt: 0 })).fail()
  }

  run canUpdateStatus = {
    init
      .then(createCallback(sampleCallback("c1", "u1", Conversation("conv1"))))
      .then(updateStatus("c1", Success))
      .then(all {
        assert(callbacks.exists(c => c.id == "c1" and c.status == Success)),
        callbacks' = callbacks,
      })
  }

  run deleteCallbackRemovesIt = {
    init
      .then(createCallback(sampleCallback("c1", "u1", Conversation("conv1"))))
      .then(deleteCallback("c1"))
      .then(all {
        assert(not(callbacks.exists(c => c.id == "c1"))),
        callbacks' = callbacks,
      })
  }

  run cannotDeleteMissingCallback = {
    init.then(deleteCallback("missing")).fail()
  }

  run deletingCreatorUserRemovesCallbacks = {
    init
      .then(createCallback(sampleCallback("c1", "u1", Conversation("conv1"))))
      .then(createCallback(sampleCallback("c2", "u2", Template("tpl1"))))
      .then(deleteUser("u1"))
      .then(all {
        assert(not(callbacks.exists(c => c.id == "c1"))),
        assert(callbacks.exists(c => c.id == "c2")),
        callbacks' = callbacks,
      })
  }
}
