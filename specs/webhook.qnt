// Webhook ingestion specification (tofarr/ohev2#125).
//
// Models the legacy agent-server webhook adapter (POST /webhooks/conversations,
// POST /webhooks/events/{conversation_id}) and the scoped ingestion path it
// shares with PATCH /conversations/{id} and POST /conversations/{id}/events.
// Invariants checked here:
//
//   - a sandbox authenticates with its session API key; the key resolves by
//     its stored hash to at most one sandbox config, and an unknown key is
//     rejected (401) — auth fails closed
//   - the resolved credential scopes every mutation to conversations whose
//     sandboxConfigId equals the credential's own config: cross-sandbox
//     conversation upserts and event appends are rejected (404), so the
//     sandbox credential is never the creator's user session
//   - conversation webhook payloads upsert: an in-scope payload whose id
//     already exists updates title/metrics instead of duplicating the row;
//     a payload with executionStatus = "deleting" never creates a row
//   - stats folding: a stats snapshot event updates the owning
//     conversation's metrics to the absolute snapshot values; non-stats
//     events leave the metrics untouched
//   - total tokens always equal prompt + completion
//
// Companion to conversation.qnt (storage + user-side CRUD/scope) and
// event.qnt (event storage). The user-credential half of the ingestion
// endpoints is covered by those specs' access policies.

module webhook {
  // Only the fields the ingestion rules depend on are modeled.
  type SandboxConfig = {
    id: str,
    // The stored SHA-256 lookup hash of the config's session API key.
    // Two configs never share one (unique index).
    keyHash: str,
  }

  type Conversation = {
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
    conversationId: str,
    isStats: bool,
    cost: int,
    prompt: int,
    completion: int,
  }

  var sandboxConfigs: Set[SandboxConfig]
  var conversations: Set[Conversation]
  var events: Set[Event]

  action init = all {
    sandboxConfigs' = Set(),
    conversations' = Set(),
    events' = Set(),
  }

  // ------------------------------------------------------------------ #
  // Helpers
  // ------------------------------------------------------------------ #

  // The session key resolves by hash to at most one config; "" stands in
  // for "no config holds this hash" (unknown key => 401).
  pure def resolveKey(configs: Set[SandboxConfig], keyHash: str): str =
    configs.fold("", (acc, sc) => if (sc.keyHash == keyHash) sc.id else acc)

  // A conversation is in scope for a sandbox credential iff it is backed by
  // the credential's own config.
  pure def inScope(c: Conversation, configId: str): bool =
    c.sandboxConfigId == configId

  pure def tokensConsistent(c: Conversation): bool =
    c.totalTokens == c.promptTokens + c.completionTokens

  // ------------------------------------------------------------------ #
  // Actions
  // ------------------------------------------------------------------ #

  // Register a sandbox config with a (hash-unique) session key.
  action createSandboxConfig(sc: SandboxConfig): bool = all {
    not(sandboxConfigs.exists(x => x.id == sc.id)),
    not(sandboxConfigs.exists(x => x.keyHash == sc.keyHash)),
    sc.id != "",
    sc.keyHash != "",
    sandboxConfigs' = sandboxConfigs.union(Set(sc)),
    conversations' = conversations,
    events' = events,
  }

  // POST /webhooks/conversations for a *deleting* execution status: a no-op
  // that never creates a row.
  action webhookDelete(keyHash: str, id: str): bool = all {
    resolveKey(sandboxConfigs, keyHash) != "",
    not(conversations.exists(c => c.id == id)),
    conversations' = conversations,
    sandboxConfigs' = sandboxConfigs,
    events' = events,
  }

  // POST /webhooks/conversations: upsert. Requires a known key and, when the
  // conversation already exists, that it is in scope for the credential.
  // Otherwise the request is rejected (401 unknown key / 404 out of scope)
  // and the state is unchanged.
  action webhookUpsert(keyHash: str, c: Conversation): bool = all {
    val configId = resolveKey(sandboxConfigs, keyHash)
    all {
      configId != "",
      // A created row is always backed by the credential's own config; an
      // updated row must already belong to it.
      inScope(c, configId),
      conversations.forall(x => x.id == c.id implies x.sandboxConfigId == configId),
      conversations' =
        if (conversations.exists(x => x.id == c.id))
          conversations.map(x =>
            if (x.id == c.id)
              { ...x, title: c.title, accumulatedCost: c.accumulatedCost,
                promptTokens: c.promptTokens, completionTokens: c.completionTokens,
                totalTokens: c.totalTokens }
            else
              x)
        else
          conversations.union(Set(c)),
      sandboxConfigs' = sandboxConfigs,
      events' = events,
    }
  }

  // POST /webhooks/events/{conversation_id} (and the scoped
  // POST /conversations/{id}/events): append a batch. Every event must
  // target a conversation that exists and is in scope for the credential;
  // stats events fold their absolute snapshot into the conversation metrics.
  action webhookEvents(keyHash: str, newEvents: Set[Event]): bool = all {
    val configId = resolveKey(sandboxConfigs, keyHash)
    all {
      configId != "",
      // All-or-nothing scope check: every event targets an in-scope,
      // existing conversation, or the whole batch is rejected (404) and the
      // state is unchanged.
      newEvents.forall(e =>
        conversations.exists(c => c.id == e.conversationId and inScope(c, configId))),
      newEvents.forall(e => not(events.exists(x => x.id == e.id))),
      newEvents.forall(e => e.cost >= 0 and e.prompt >= 0 and e.completion >= 0),
      events' = events.union(newEvents),
      conversations' = conversations.map(c =>
        newEvents.filter(e => e.conversationId == c.id and e.isStats).fold(c, (acc, e) =>
          { ...acc, accumulatedCost: e.cost, promptTokens: e.prompt,
            completionTokens: e.completion, totalTokens: e.prompt + e.completion })),
      sandboxConfigs' = sandboxConfigs,
    }
  }

  action step: bool = all {
    sandboxConfigs' = sandboxConfigs,
    conversations' = conversations,
    events' = events,
  }

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // Session key hashes are unique across configs: a key resolves to at most
  // one config.
  val keyHashUnique: bool =
    sandboxConfigs.forall(sc1 =>
      sandboxConfigs.forall(sc2 =>
        sc1.keyHash == sc2.keyHash implies sc1 == sc2))

  // Every conversation is backed by an existing sandbox config.
  val allBackedByConfig: bool =
    conversations.forall(c => sandboxConfigs.exists(sc => sc.id == c.sandboxConfigId))

  // Every event is backed by an existing conversation.
  val allEventsBacked: bool =
    events.forall(e => conversations.exists(c => c.id == e.conversationId))

  // total == prompt + completion for every conversation, always.
  val allTokensConsistent: bool =
    conversations.forall(c => tokensConsistent(c))

  // Fail-closed auth: an unknown session key admits nothing.
  val unknownKeyAdmitsNothing: bool =
    resolveKey(sandboxConfigs, "never-issued") == ""

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  val _cfg: SandboxConfig = { id: "cfg1", keyHash: "hash1" }
  val _other: SandboxConfig = { id: "cfg2", keyHash: "hash2" }
  val _conv: Conversation = {
    id: "c1", sandboxConfigId: "cfg1", title: "webhook conversation",
    accumulatedCost: 0, promptTokens: 0, completionTokens: 0, totalTokens: 0,
  }

  run createViaWebhook = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookUpsert("hash1", _conv))
      .then(all {
        assert(conversations.exists(c => c.id == "c1" and c.sandboxConfigId == "cfg1")),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run unknownKeyRejected = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookUpsert("bogus", _conv))
      .fail()
  }

  run crossSandboxUpsertRejected = {
    init.then(createSandboxConfig(_cfg))
      .then(createSandboxConfig(_other))
      .then(webhookUpsert("hash1", _conv))
      // cfg2's key must not be able to update cfg1's conversation.
      .then(webhookUpsert("hash2", { ..._conv, title: "hijacked" }))
      .fail()
  }

  run upsertUpdatesExisting = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookUpsert("hash1", _conv))
      .then(webhookUpsert("hash1", {
        ..._conv, title: "renamed", accumulatedCost: 3,
        promptTokens: 10, completionTokens: 5, totalTokens: 15,
      }))
      .then(all {
        assert(conversations.size() == 1),
        assert(conversations.exists(c =>
          c.id == "c1" and c.title == "renamed" and c.totalTokens == 15)),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run deletingStatusNeverCreates = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookDelete("hash1", "c1"))
      .then(all {
        assert(not(conversations.exists(c => c.id == "c1"))),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  val _msgEvent: Event = {
    id: "e1", conversationId: "c1", isStats: false, cost: 0, prompt: 0, completion: 0,
  }
  val _statsEvent: Event = {
    id: "e2", conversationId: "c1", isStats: true, cost: 2, prompt: 8, completion: 4,
  }

  run eventsAppendAndStatsFold = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookUpsert("hash1", _conv))
      .then(webhookEvents("hash1", Set(_msgEvent, _statsEvent)))
      .then(all {
        assert(events.size() == 2),
        assert(conversations.exists(c =>
          c.id == "c1" and c.accumulatedCost == 2 and c.promptTokens == 8
            and c.completionTokens == 4 and c.totalTokens == 12)),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run nonStatsEventLeavesMetrics = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookUpsert("hash1", _conv))
      .then(webhookEvents("hash1", Set(_msgEvent)))
      .then(all {
        assert(conversations.exists(c =>
          c.id == "c1" and c.accumulatedCost == 0 and c.totalTokens == 0)),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
        events' = events,
      })
  }

  run crossSandboxEventRejected = {
    init.then(createSandboxConfig(_cfg))
      .then(createSandboxConfig(_other))
      .then(webhookUpsert("hash1", _conv))
      // cfg2's key must not be able to append events to cfg1's conversation.
      .then(webhookEvents("hash2", Set(_msgEvent)))
      .fail()
  }

  run eventToUnknownConversationRejected = {
    init.then(createSandboxConfig(_cfg))
      .then(webhookEvents("hash1", Set(_msgEvent)))
      .fail()
  }

  run duplicateKeyHashRejected = {
    init.then(createSandboxConfig(_cfg))
      .then(createSandboxConfig({ id: "cfg3", keyHash: "hash1" }))
      .fail()
  }
}
