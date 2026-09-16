// Webhook ingestion specification (tofarr/ohev2#125).
//
// Models the legacy agent-server webhook adapter: the sandbox config id is
// carried on the URL (POST /webhooks/{sandbox_config_id}/conversation_records and
// POST /webhooks/{sandbox_config_id}/conversation_records/{conversation_record_id}/events),
// and authentication/authorization go through the standard permission
// dependencies (role-policy filters). Invariants checked here:
//
//   - an unknown sandbox config id on the URL is invisible (404) and leaves
//     the state unchanged
//   - every mutation is scoped to conversation_records whose sandboxConfigId equals
//     the URL's config id: cross-scope upserts and event appends are
//     rejected (404) and change nothing
//   - the resolved permission filter must both pass the route guard and
//     match() the candidate/existing row; a deny at either level is a total
//     no-op (fail-closed, existence not leaked)
//   - conversation_record webhook payloads upsert: an in-scope payload whose id
//     already exists updates title/metrics instead of duplicating the row;
//     a payload with executionStatus = "deleting" never creates a row
//   - stats folding: a stats snapshot event updates the owning
//     conversation_record's metrics to the absolute snapshot values; non-stats
//     events leave the metrics untouched
//   - total tokens always equal prompt + completion
//
// The role-policy resolution itself (how a principal's roles reduce to a
// filter) is specified in rbac.qnt; this spec treats the resolved outcome
// (authorized) as an input. Companion to conversation_record.qnt (storage +
// user-side CRUD/scope) and event.qnt (event storage).

module webhook {
  // Only the fields the ingestion rules depend on are modeled.
  type SandboxConfig = {
    id: str,
  }

  type ConversationRecord = {
    id: str,
    sandboxConfigId: str,
    title: str,
    accumulatedCost: int,
    promptTokens: int,
    completionTokens: int,
    totalTokens: int,
  }

  // An ingested event: stats snapshots carry absolute metric values.
  type Event = {
    id: str,
    conversationRecordId: str,
    isStats: bool,
    cost: int,
    prompt: int,
    completion: int,
  }

  var sandboxConfigs: Set[SandboxConfig]
  var conversation_records: Set[ConversationRecord]
  var events: Set[Event]

  action init = all {
    sandboxConfigs' = Set(),
    conversation_records' = Set(),
    events' = Set(),
  }

  // ------------------------------------------------------------------ #
  // Helpers
  // ------------------------------------------------------------------ #

  // A conversation_record is in scope for a webhook URL iff it is backed by the
  // URL's sandbox config id.
  pure def inScope(c: ConversationRecord, configId: str): bool =
    c.sandboxConfigId == configId

  pure def tokensConsistent(c: ConversationRecord): bool =
    c.totalTokens == c.promptTokens + c.completionTokens

  // The URL's config must exist; otherwise the request is a 404 no-op.
  def urlConfigExists(configId: str): bool =
    sandboxConfigs.exists(sc => sc.id == configId)

  // ------------------------------------------------------------------ #
  // Actions
  // ------------------------------------------------------------------ #

  // Register a sandbox config. Authorization for config CRUD is outside the
  // webhook's concern (modeled in sandbox.qnt).
  action createConfig(sc: SandboxConfig): bool = all {
    not(sandboxConfigs.exists(x => x.id == sc.id)),
    sc.id != "",
    sandboxConfigs' = sandboxConfigs.union(Set(sc)),
    conversation_records' = conversation_records,
    events' = events,
  }

  // POST /webhooks/{cfg}/conversation_records with a *deleting* execution status
  // (and, in general, any payload whose id does not resolve to an existing
  // row): a no-op that never creates a row.
  action webhookDeleteStatus(configId: str, id: str, authorized: bool): bool = all {
    urlConfigExists(configId),
    authorized,
    not(conversation_records.exists(c => c.id == id)),
    conversation_records' = conversation_records,
    sandboxConfigs' = sandboxConfigs,
    events' = events,
  }

  // POST /webhooks/{cfg}/conversation_records: upsert. The route guard
  // (authorized) and the URL scope must both hold; the URL's config must
  // own a created row, and an updated row must already belong to it. Any
  // violation is rejected and the state is unchanged.
  action webhookUpsert(configId: str, c: ConversationRecord, authorized: bool): bool = all {
    authorized,
    inScope(c, configId),
    conversation_records.forall(x => x.id == c.id implies x.sandboxConfigId == configId),
    conversation_records' =
      if (conversation_records.exists(x => x.id == c.id))
        conversation_records.map(x =>
          if (x.id == c.id)
            { ...x, title: c.title, accumulatedCost: c.accumulatedCost,
              promptTokens: c.promptTokens, completionTokens: c.completionTokens,
              totalTokens: c.totalTokens }
          else
            x)
      else
        conversation_records.union(Set(c)),
    sandboxConfigs' = sandboxConfigs,
    events' = events,
  }

  // POST /webhooks/{cfg}/conversation_records/{cid}/events: append a batch. All-or-
  // nothing scope check: every event must target an in-scope, existing
  // conversation_record, or the whole batch is rejected (404) and the state is
  // unchanged. Stats events fold their absolute snapshot into the
  // conversation_record metrics.
  action webhookEvents(configId: str, newEvents: Set[Event], authorized: bool): bool = all {
    authorized,
    newEvents.forall(e =>
      conversation_records.exists(c => c.id == e.conversationRecordId and inScope(c, configId))),
    newEvents.forall(e => not(events.exists(x => x.id == e.id))),
    newEvents.forall(e => e.cost >= 0 and e.prompt >= 0 and e.completion >= 0),
    events' = events.union(newEvents),
    conversation_records' = conversation_records.map(c =>
      newEvents.filter(e => e.conversationRecordId == c.id and e.isStats).fold(c, (acc, e) =>
        { ...acc, accumulatedCost: e.cost, promptTokens: e.prompt,
          completionTokens: e.completion, totalTokens: e.prompt + e.completion })),
    sandboxConfigs' = sandboxConfigs,
  }

  action step: bool = all {
    sandboxConfigs' = sandboxConfigs,
    conversation_records' = conversation_records,
    events' = events,
  }

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // Every conversation_record is backed by an existing sandbox config.
  val allBackedByConfig: bool =
    conversation_records.forall(c => sandboxConfigs.exists(sc => sc.id == c.sandboxConfigId))

  // Every event is backed by an existing conversation_record.
  val allEventsBacked: bool =
    events.forall(e => conversation_records.exists(c => c.id == e.conversationRecordId))

  // total == prompt + completion for every conversation_record, always.
  val allTokensConsistent: bool =
    conversation_records.forall(c => tokensConsistent(c))

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  val _cfg: SandboxConfig = { id: "cfg1" }
  val _other: SandboxConfig = { id: "cfg2" }
  val _conv: ConversationRecord = {
    id: "c1", sandboxConfigId: "cfg1", title: "webhook conversation_record",
    accumulatedCost: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0,
  }

  run createViaWebhook = {
    init.then(createConfig(_cfg))
      .then(webhookUpsert("cfg1", _conv, true))
      .then(all {
        assert(conversation_records.exists(c => c.id == "c1" and c.sandboxConfigId == "cfg1")),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run unauthorizedDenied = {
    init.then(createConfig(_cfg))
      .then(webhookUpsert("cfg1", _conv, false))
      .fail()
  }

  run crossScopeUpsertRejected = {
    init.then(createConfig(_cfg))
      .then(createConfig(_other))
      .then(webhookUpsert("cfg1", _conv, true))
      // The cfg2 URL must not update cfg1's conversation_record.
      .then(webhookUpsert("cfg2", { ..._conv, title: "hijacked" }, true))
      .fail()
  }

  run upsertUpdatesExisting = {
    init.then(createConfig(_cfg))
      .then(webhookUpsert("cfg1", _conv, true))
      .then(webhookUpsert("cfg1", {
        ..._conv, title: "renamed", accumulatedCost: 3,
        promptTokens: 10, completionTokens: 5, totalTokens: 15,
      }, true))
      .then(all {
        assert(conversation_records.size() == 1),
        assert(conversation_records.exists(c =>
          c.id == "c1" and c.title == "renamed" and c.totalTokens == 15)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run deletingStatusNeverCreates = {
    init.then(createConfig(_cfg))
      .then(webhookDeleteStatus("cfg1", "c1", true))
      .then(all {
        assert(not(conversation_records.exists(c => c.id == "c1"))),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run deletingStatusUnauthorizedIsNoop = {
    init.then(createConfig(_cfg))
      .then(webhookDeleteStatus("cfg1", "c1", false))
      .fail()
  }

  val _msgEvent: Event = {
    id: "e1", conversationRecordId: "c1", isStats: false, cost: 0, prompt: 0, completion: 0,
  }
  val _statsEvent: Event = {
    id: "e2", conversationRecordId: "c1", isStats: true, cost: 2, prompt: 8, completion: 4,
  }

  run eventsAppendAndStatsFold = {
    init.then(createConfig(_cfg))
      .then(webhookUpsert("cfg1", _conv, true))
      .then(webhookEvents("cfg1", Set(_msgEvent, _statsEvent), true))
      .then(all {
        assert(events.size() == 2),
        assert(conversation_records.exists(c =>
          c.id == "c1" and c.accumulatedCost == 2 and c.promptTokens == 8
            and c.completionTokens == 4 and c.totalTokens == 12)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run nonStatsEventLeavesMetrics = {
    init.then(createConfig(_cfg))
      .then(webhookUpsert("cfg1", _conv, true))
      .then(webhookEvents("cfg1", Set(_msgEvent), true))
      .then(all {
        assert(conversation_records.exists(c =>
          c.id == "c1" and c.accumulatedCost == 0 and c.totalTokens == 0)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run crossScopeEventRejected = {
    init.then(createConfig(_cfg))
      .then(createConfig(_other))
      .then(webhookUpsert("cfg1", _conv, true))
      // The cfg2 URL must not append events to cfg1's conversation_record.
      .then(webhookEvents("cfg2", Set(_msgEvent), true))
      .fail()
  }

  run unauthorizedEventRejected = {
    init.then(createConfig(_cfg))
      .then(webhookUpsert("cfg1", _conv, true))
      .then(webhookEvents("cfg1", Set(_msgEvent), false))
      .fail()
  }

  run eventToUnknownConversationRejected = {
    init.then(createConfig(_cfg))
      .then(webhookEvents("cfg1", Set(_msgEvent), true))
      .fail()
  }
}
