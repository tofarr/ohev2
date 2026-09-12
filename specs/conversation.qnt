// Conversation entity specification.
//
// Models the Conversation resource lifecycle and the invariants that the
// /conversations REST collection must uphold:
//
//   - conversation ids are unique
//   - every conversation is backed by an existing sandbox config
//   - metric columns (cost/tokens) start at 0 and accumulate via update
//   - total tokens always equal prompt + completion tokens
//   - deleting a sandbox config cascade-removes its conversations
//   - non-admin users get read/search only, scoped to conversations whose
//     backing sandbox config they created (ConversationAccess policy);
//     create/update/delete are denied to them
//
// The webhook ingestion path that populates conversations is out of scope
// here (see the webhook sub-issue of #122); this spec covers storage + CRUD
// and the cross-table ownership scope only.
//
// Companion to rbac.qnt (conversation permissions are governed by the
// conversation_permission column on Role) and api_key.qnt (same CRUD shape).

module conversation {
  type Conversation = {
    id: str,
    sandboxConfigId: str,
    title: str,
    accumulatedCost: int,  // USD modeled as integer cents
    promptTokens: int,
    completionTokens: int,
    totalTokens: int,
    createdAt: int,
    updatedAt: int,
  }

  // Only the fields the access policy depends on are modeled.
  type SandboxConfig = {
    id: str,
    creatorId: str,
  }

  var conversations: Set[Conversation]
  var sandboxConfigs: Set[SandboxConfig]

  action init = all {
    conversations' = Set(),
    sandboxConfigs' = Set(),
  }

  // No two conversations share the same id.
  def idUnique(c1: Conversation, c2: Conversation): bool =
    c1.id == c2.id implies c1 == c2

  // Every conversation is backed by an existing sandbox config.
  def hasBackingConfig(c: Conversation): bool =
    sandboxConfigs.exists(sc => sc.id == c.sandboxConfigId)

  // total tokens are always the sum of prompt and completion tokens.
  def tokensConsistent(c: Conversation): bool =
    c.totalTokens == c.promptTokens + c.completionTokens

  // Metrics are never negative.
  def metricsNonNegative(c: Conversation): bool =
    c.accumulatedCost >= 0 and c.promptTokens >= 0
      and c.completionTokens >= 0 and c.totalTokens >= 0

  // Cross-table ownership scope (the ConversationAccess policy): a non-admin
  // user may read/search a conversation iff they created the backing sandbox
  // config. Admin bypasses the scope entirely (Permitted).
  pure def canRead(c: Conversation, userId: str, isAdmin: bool,
                   configs: Set[SandboxConfig]): bool =
    isAdmin or configs.exists(sc => sc.id == c.sandboxConfigId and sc.creatorId == userId)

  // ConversationAccess denies every write action to non-admin users;
  // conversations are written by the ingestion path, not by end users.
  pure def canWrite(c: Conversation, userId: str, isAdmin: bool): bool =
    isAdmin

  // Anonymous principals (modeled as userId "") are denied even reads.
  pure def anonymousCanRead(c: Conversation, configs: Set[SandboxConfig]): bool =
    canRead(c, "", false, configs)

  // ------------------------------------------------------------------ #
  // Actions
  // ------------------------------------------------------------------ #

  // Register a sandbox config (owned by its creator).
  action createSandboxConfig(sc: SandboxConfig): bool = all {
    not(sandboxConfigs.exists(x => x.id == sc.id)),
    sc.creatorId != "",
    sandboxConfigs' = sandboxConfigs.union(Set(sc)),
    conversations' = conversations,
  }

  // Create a conversation. Metrics start at 0; the backing sandbox config
  // must exist.
  action create(c: Conversation): bool = all {
    not(conversations.exists(x => x.id == c.id)),
    hasBackingConfig(c),
    c.title != "",
    c.accumulatedCost == 0,
    c.promptTokens == 0,
    c.completionTokens == 0,
    c.totalTokens == 0,
    conversations' = conversations.union(Set(c)),
    sandboxConfigs' = sandboxConfigs,
  }

  // Update the accumulated metrics (the PATCH path the ingestion uses).
  // totalTokens must remain prompt + completion.
  action updateMetrics(id: str, cost: int, prompt: int, completion: int,
                       now: int): bool = all {
    conversations.exists(c => c.id == id),
    cost >= 0,
    prompt >= 0,
    completion >= 0,
    conversations' = conversations.map(c =>
      if (c.id == id)
        { ...c, accumulatedCost: cost, promptTokens: prompt,
          completionTokens: completion, totalTokens: prompt + completion,
          updatedAt: now }
      else
        c),
    sandboxConfigs' = sandboxConfigs,
  }

  // Delete a conversation by id.
  action remove(id: str): bool = all {
    conversations.exists(c => c.id == id),
    conversations' = conversations.filter(c => c.id != id),
    sandboxConfigs' = sandboxConfigs,
  }

  // Deleting a sandbox config cascade-removes its conversations
  // (ON DELETE CASCADE on conversations.sandbox_config_id).
  action removeSandboxConfig(id: str): bool = all {
    sandboxConfigs.exists(sc => sc.id == id),
    sandboxConfigs' = sandboxConfigs.filter(sc => sc.id != id),
    conversations' = conversations.filter(c => c.sandboxConfigId != id),
  }

  action step: bool = all {
    conversations' = conversations,
    sandboxConfigs' = sandboxConfigs,
  }

  // ------------------------------------------------------------------ #
  // Invariants
  // ------------------------------------------------------------------ #

  // All conversation ids are unique.
  val idsUnique: bool =
    conversations.forall(c1 =>
      conversations.forall(c2 => idUnique(c1, c2)))

  // Every conversation is backed by an existing sandbox config.
  val allBackedByConfig: bool =
    conversations.forall(c => hasBackingConfig(c))

  // total == prompt + completion for every conversation.
  val allTokensConsistent: bool =
    conversations.forall(c => tokensConsistent(c))

  // Metrics are never negative.
  val allMetricsNonNegative: bool =
    conversations.forall(c => metricsNonNegative(c))

  // The user ids the spec quantifies over: every sandbox-config creator plus
  // a fixed "stranger" standing in for users who created nothing.
  pure def mentionedUsers(configs: Set[SandboxConfig]): Set[str] =
    configs.map(sc => sc.creatorId).union(Set("stranger"))

  // A non-admin user can read a conversation only if they created the backing
  // sandbox config.
  val readScopeSound: bool =
    conversations.forall(c =>
      mentionedUsers(sandboxConfigs).forall(u =>
        canRead(c, u, false, sandboxConfigs) implies
          sandboxConfigs.exists(sc => sc.id == c.sandboxConfigId and sc.creatorId == u)))

  // ------------------------------------------------------------------ #
  // Tests
  // ------------------------------------------------------------------ #

  val _sc1: SandboxConfig = { id: "sc1", creatorId: "u1" }
  val _conv1: Conversation = {
    id: "c1", sandboxConfigId: "sc1", title: "first", accumulatedCost: 0,
    promptTokens: 0, completionTokens: 0, totalTokens: 0, createdAt: 0,
    updatedAt: 0,
  }

  run createConversation = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(conversations.exists(c => c.id == "c1" and c.sandboxConfigId == "sc1")),
        conversations' = conversations,
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
        assert(conversations.exists(c =>
          c.id == "c1" and c.accumulatedCost == 12 and c.totalTokens == 150)),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  run deleteRemovesConversation = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(remove("c1"))
      .then(all {
        assert(not(conversations.exists(c => c.id == "c1"))),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  run deletingSandboxConfigCascades = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(removeSandboxConfig("sc1"))
      .then(all {
        assert(not(conversations.exists(c => c.id == "c1"))),
        assert(not(sandboxConfigs.exists(sc => sc.id == "sc1"))),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // A non-admin user reads conversations backed by sandbox configs they
  // created, and only those.
  run ownerCanReadStrangerCannot = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(canRead(_conv1, "u1", false, sandboxConfigs)),
        assert(not(canRead(_conv1, "u2", false, sandboxConfigs))),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // Admin (Permitted) bypasses the ownership scope entirely.
  run adminCanReadAnything = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(canRead(_conv1, "u2", true, sandboxConfigs)),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // ConversationAccess is read/search-only for non-admin users: writes are
  // denied regardless of ownership.
  run nonAdminCannotWrite = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(not(canWrite(_conv1, "u1", false))),
        assert(canWrite(_conv1, "u1", true)),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }

  // Anonymous principals are denied even reads.
  run anonymousDenied = {
    init.then(createSandboxConfig(_sc1))
      .then(create(_conv1))
      .then(all {
        assert(not(anonymousCanRead(_conv1, sandboxConfigs))),
        conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
  }
}
