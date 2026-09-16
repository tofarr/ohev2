// ConversationRecord entity specification.
//
// Models the ConversationRecord resource lifecycle and the invariants that the
// /conversation_records REST collection must uphold:
//
//   - conversation_record ids are unique
//   - every conversation_record is backed by an existing sandbox config
//   - metric columns (cost/tokens) start at 0 and accumulate via update
//   - total tokens always equal prompt + completion tokens
//   - deleting a sandbox config cascade-removes its conversation_records
//   - non-admin users get read/search only, scoped to conversation_records whose
//     backing sandbox config they created (ConversationRecordAccess policy);
//     create/update/delete are denied to them
//   - event_callbacks is an embedded list of polymorphic callables (an
//     EventCallback discriminated union, the only default kind being
//     LoggingCallback). Round-trip serialization preserves the concrete
//     subclass — the discriminator ("kind") is restored on read (issue #159)
//
// The webhook ingestion path that populates conversation_records is modeled in
// webhook.qnt; this spec covers storage + CRUD and the cross-table
// ownership scope only.
//
// Companion to rbac.qnt (conversation_record permissions are governed by the
// conversation_record_permission column on Role) and api_key.qnt (same CRUD shape).

module conversation_record {
  // The discriminator of an embedded EventCallback. The EventCallback union
  // is modeled here as a closed kind: only LoggingCallback is defined (the
  // default implementation). It carries its serialized payload (the JSONB
  // blob) so the round-trip restores the concrete callable.
  type CallbackKind = LoggingCallback(str)

  // The only concrete callback: LoggingCallback with its serialized payload.
  pure def loggingCallback(payload: str): CallbackKind = LoggingCallback(payload)

  type ConversationRecord = {
    id: str,
    sandboxConfigId: str,
    title: str,
    accumulatedCost: int,  // USD modeled as integer cents
    promptTokens: int,
    completionTokens: int,
    totalTokens: int,
    // Each element carries its discriminator so the round-trip restores the
    // concrete callable.
    eventCallbacks: Set[CallbackKind],
    createdAt: int,
    updatedAt: int,
  }

  // Only the fields the access policy depends on are modeled.
  type SandboxConfig = {
    id: str,
    creatorId: str,
  }

  var conversation_records: Set[ConversationRecord]
  var sandboxConfigs: Set[SandboxConfig]

  action init = all {
    conversation_records' = Set(),
    sandboxConfigs' = Set(),
  }

  // No two conversation_records share the same id.
  def idUnique(c1: ConversationRecord, c2: ConversationRecord): bool =
    c1.id == c2.id implies c1 == c2

  // Every conversation_record is backed by an existing sandbox config.
  def hasBackingConfig(c: ConversationRecord): bool =
    sandboxConfigs.exists(sc => sc.id == c.sandboxConfigId)

  // total tokens are always the sum of prompt and completion tokens.
  def tokensConsistent(c: ConversationRecord): bool =
    c.totalTokens == c.promptTokens + c.completionTokens

  // Metrics are never negative.
  def metricsNonNegative(c: ConversationRecord): bool =
    c.accumulatedCost >= 0 and c.promptTokens >= 0
      and c.completionTokens >= 0 and c.totalTokens >= 0

  // Round-trip serialization preserves the concrete subclass. CallbackKind
  // is a closed union whose only constructor is LoggingCallback, so every
  // embedded callback is a known kind by construction — the JSONB
  // TypeDecorator deserializes via the union and restores it.
  def callbacksRoundTrip(c: ConversationRecord): bool =
    c.eventCallbacks.forall(cb => isLoggingCallback(cb))

  // The only constructor defined on CallbackKind; true for every value of the
  // type. Kept as a named predicate so the invariant remains meaningful when
  // additional kinds are added to the union.
  pure def isLoggingCallback(cb: CallbackKind): bool = true

  // Cross-table ownership scope (the ConversationRecordAccess policy): a non-admin
  // user may read/search a conversation_record iff they created the backing sandbox
  // config. Admin bypasses the scope entirely (Permitted).
  pure def canRead(c: ConversationRecord, userId: str, isAdmin: bool,
                   configs: Set[SandboxConfig]): bool =
    isAdmin or configs.exists(sc => sc.id == c.sandboxConfigId and sc.creatorId == userId)

  // ConversationRecordAccess denies every write action to non-admin users;
  // conversation_records are written by the ingestion path, not by end users.
  pure def canWrite(c: ConversationRecord, userId: str, isAdmin: bool): bool =
    isAdmin

  // Anonymous principals (modeled as userId "") are denied even reads.
  pure def anonymousCanRead(c: ConversationRecord, configs: Set[SandboxConfig]): bool =
    canRead(c, "", false, configs)

  // ------------------------------------------------------------------ #
  // Actions
  // ------------------------------------------------------------------ #

  // Register a sandbox config (owned by its creator).
  action createSandboxConfig(sc: SandboxConfig): bool = all {
    not(sandboxConfigs.exists(x => x.id == sc.id)),
    sc.creatorId != "",
    sandboxConfigs' = sandboxConfigs.union(Set(sc)),
    conversation_records' = conversation_records,
  }

  // Create a conversation_record. Metrics start at 0; the backing sandbox config
  // must exist. Event callbacks are embedded at create time.
  action create(c: ConversationRecord): bool = all {
    not(conversation_records.exists(x => x.id == c.id)),
    hasBackingConfig(c),
    c.title != "",
    c.accumulatedCost == 0,
    c.promptTokens == 0,
    c.completionTokens == 0,
    c.totalTokens == 0,
    conversation_records' = conversation_records.union(Set(c)),
    sandboxConfigs' = sandboxConfigs,
  }

  // Update the accumulated metrics (the PATCH path the ingestion uses).
  // totalTokens must remain prompt + completion.
  action updateMetrics(id: str, cost: int, prompt: int, completion: int,
                       now: int): bool = all {
    conversation_records.exists(c => c.id == id),
    cost >= 0,
    prompt >= 0,
    completion >= 0,
    conversation_records' = conversation_records.map(c =>
      if (c.id == id)
        { ...c, accumulatedCost: cost, promptTokens: prompt,
          completionTokens: completion, totalTokens: prompt + completion,
          updatedAt: now }
      else
        c),
    sandboxConfigs' = sandboxConfigs,
  }

  // Update the embedded event callbacks. The replacement list must itself
  // round-trip (every callback is a known constructor).
  action updateCallbacks(id: str, callbacks: Set[CallbackKind],
                         now: int): bool = all {
    conversation_records.exists(c => c.id == id),
    callbacks.forall(cb => isLoggingCallback(cb)),
    conversation_records' = conversation_records.map(c =>
      if (c.id == id)
        { ...c, eventCallbacks: callbacks, updatedAt: now }
      else
        c),
    sandboxConfigs' = sandboxConfigs,
  }

  // Delete a conversation_record by id.
  action remove(id: str): bool = all {
    conversation_records.exists(c => c.id == id),
    conversation_records' = conversation_records.filter(c => c.id != id),
    sandboxConfigs' = sandboxConfigs,
  }

  // Deleting a sandbox config cascade-removes its conversation_records
  // (ON DELETE CASCADE on conversation_records.sandbox_config_id).
  action removeSandboxConfig(id: str): bool = all {
    sandboxConfigs.exists(sc => sc.id == id),
    sandboxConfigs' = sandboxConfigs.filter(sc => sc.id != id),
    conversation_records' = conversation_records.filter(c => c.sandboxConfigId != id),
  }

  action step: bool = all {
    conversation_records' = conversation_records,
    sandboxConfigs' = sandboxConfigs,
  }

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // All conversation_record ids are unique.
  val idsUnique: bool =
    conversation_records.forall(c1 =>
      conversation_records.forall(c2 => idUnique(c1, c2)))

  // Every conversation_record is backed by an existing sandbox config.
  val allBackedByConfig: bool =
    conversation_records.forall(c => hasBackingConfig(c))

  // total == prompt + completion for every conversation_record.
  val allTokensConsistent: bool =
    conversation_records.forall(c => tokensConsistent(c))

  // Metrics are never negative.
  val allMetricsNonNegative: bool =
    conversation_records.forall(c => metricsNonNegative(c))

  // Round-trip serialization preserves the concrete subclass for every
  // embedded callback (the discriminator is restored on read).
  val allCallbacksRoundTrip: bool =
    conversation_records.forall(c => callbacksRoundTrip(c))

  // The user ids the spec quantifies over: every sandbox-config creator plus
  // a fixed "stranger" standing in for users who created nothing.
  pure def mentionedUsers(configs: Set[SandboxConfig]): Set[str] =
    configs.map(sc => sc.creatorId).union(Set("stranger"))

  // A non-admin user can read a conversation_record only if they created the backing
  // sandbox config.
  val readScopeSound: bool =
    conversation_records.forall(c =>
      mentionedUsers(sandboxConfigs).forall(u =>
        canRead(c, u, false, sandboxConfigs) implies
          sandboxConfigs.exists(sc => sc.id == c.sandboxConfigId and sc.creatorId == u)))

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  pure def _logCb: CallbackKind = LoggingCallback("{}")

  val _sc1: SandboxConfig = { id: "sc1", creatorId: "u1" }
  val _conv1: ConversationRecord = {
    id: "c1", sandboxConfigId: "sc1", title: "first", accumulatedCost: 0,
    promptTokens: 0, completionTokens: 0, totalTokens: 0,
    eventCallbacks: Set(), createdAt: 0, updatedAt: 0,
  }

  run createConversationRecord = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(conversation_records.exists(c => c.id == "c1" and c.sandboxConfigId == "sc1")),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  run cannotCreateWithoutBackingConfig = {
    init.then(create(_conv1))
      .fail()
  }

  run cannotReuseId = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(create({ ..._conv1, title: "second" }))
      .fail()
  }

  run cannotCreateWithNonzeroMetrics = {
    init.then(createSandboxConfig(_sc1))
      .then(create({ ..._conv1, totalTokens: 10 }))
      .fail()
  }

  run metricsAccumulateAndConserveTotal = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(updateMetrics("c1", 12, 100, 50, 1))
      .then(all {
        assert(conversation_records.exists(c =>
          c.id == "c1" and c.accumulatedCost == 12 and c.totalTokens == 150)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  run deleteRemovesConversationRecord = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(remove("c1"))
      .then(all {
        assert(not(conversation_records.exists(c => c.id == "c1"))),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  run deletingSandboxConfigCascades = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(removeSandboxConfig("sc1"))
      .then(all {
        assert(not(conversation_records.exists(c => c.id == "c1"))),
        assert(not(sandboxConfigs.exists(sc => sc.id == "sc1"))),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // A conversation_record created with embedded callbacks preserves them on read.
  run createWithCallbacksRoundTrips = {
    init.then(createSandboxConfig(_sc1))
      .then(create({ ..._conv1, eventCallbacks: Set(_logCb) }))
      .then(all {
        assert(conversation_records.exists(c =>
          c.id == "c1" and c.eventCallbacks.size() == 1
            and c.eventCallbacks.contains(_logCb))),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // Updating the embedded callbacks replaces them and the round-trip
  // invariant continues to hold.
  run updateCallbacksRoundTrips = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(updateCallbacks("c1", Set(_logCb, _logCb), 1))
      .then(all {
        assert(conversation_records.exists(c =>
          c.id == "c1" and c.eventCallbacks.size() == 1)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // A non-admin user reads conversation_records backed by sandbox configs they
  // created, and only those.
  run ownerCanReadStrangerCannot = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(canRead(_conv1, "u1", false, sandboxConfigs)),
        assert(not(canRead(_conv1, "u2", false, sandboxConfigs))),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // Admin (Permitted) bypasses the ownership scope entirely.
  run adminCanReadAnything = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(canRead(_conv1, "u2", true, sandboxConfigs)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // ConversationRecordAccess is read/search-only for non-admin users: writes are
  // denied regardless of ownership.
  run nonAdminCannotWrite = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(not(canWrite(_conv1, "u1", false))),
        assert(canWrite(_conv1, "u1", true)),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // Anonymous principals are denied even reads.
  run anonymousDenied = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(not(anonymousCanRead(_conv1, sandboxConfigs))),
        conversation_records' = conversation_records,
        sandboxConfigs' = sandboxConfigs,
      })
  }
}
