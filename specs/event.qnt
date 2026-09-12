// Event entity specification.
//
// Models the Event resource (tofarr/ohev2#124): a daily-partitioned Postgres
// projection plus a backing object store (filesystem/S3) holding every
// event's full body at a derivable key. Invariants checked here:
//
//   - event ids are unique, and every event is backed by an existing
//     conversation (FK → conversations)
//   - the body cap rule: serialized payloads of at most `bodyCap` bytes are
//     stored inline; larger ones become a truncation stub with
//     `_truncated = true` and a preview; `sizeBytes` always records the
//     original serialized size
//   - every event's full body lands in the store (not just the oversized
//     ones), so /body resolves inline for not-truncated rows and hits the
//     store for truncated rows (never a mixed state)
//   - partition drop removes the day's rows and the store's matching
//     date prefix in one aligned sweep (single rm/delete-prefix)
//   - the backfill job (store → Postgres) restores rows for stored
//     envelopes missing from the table, with their stored id/timestamp
//   - a non-admin user may read/search events only on conversations backed
//     by sandbox configs they created (EventAccess); writes are denied to
//     them. Admin bypasses the scope (Permitted).
//
// Companion to conversation.qnt (parent entity) and rbac.qnt
// (event_permission column on Role).

module event {
  // Only the fields the access policy/body-cap rule depends on are modeled.
  type Event = {
    id: str,
    conversationId: str,
    kind: str,
    timestamp: int,   // epoch day (partition grain)
    sizeBytes: int,
    truncated: bool,
    bodyPreview: str,
  }

  type Conversation = {
    id: str,
    sandboxConfigId: str,
  }

  type SandboxConfig = {
    id: str,
    creatorId: str,
  }

  // Sized for the test runs below (inline = at most, stub = over).
  val bodyCap: int = 16

  var events: Set[Event]
  var conversations: Set[Conversation]
  var sandboxConfigs: Set[SandboxConfig]
  // The backing store as a set of event ids whose full body it holds.
  var storedBodies: Set[str]

  action init = all {
    events' = Set(),
    conversations' = Set(),
    sandboxConfigs' = Set(),
    storedBodies' = Set(),
  }

  // ---------------------------------------------------------------

  // Helpers

  // Every event is backed by an existing conversation.
  def hasBackingConversation(e: Event): bool =
    conversations.exists(c => c.id == e.conversationId)

  // Payloads of at most bodyCap bytes are stored inline; over-cap becomes a
  // stub. sizeBytes always records the original serialized size.
  def capRule(e: Event): bool =
    e.truncated == (e.sizeBytes > bodyCap)

  // Truncated bodies store a self-describing stub (non-empty preview).
  def stubSelfDescribing(e: Event): bool =
    e.truncated implies e.bodyPreview != ""

  // A title/kind must be non-empty at write time.
  def kindNonEmpty(e: Event): bool =
    e.kind != ""

  // EventAccess scope: read/search iff the conversation is backed by a
  // sandbox config the principal created; admin bypasses.
  pure def canRead(e: Event, userId: str, isAdmin: bool,
                   convs: Set[Conversation], cfgs: Set[SandboxConfig]): bool =
    isAdmin or convs.filter(c => c.id == e.conversationId).exists(c =>
      cfgs.exists(sc => sc.id == c.sandboxConfigId and sc.creatorId == userId))

  // The /body endpoint: not-truncated serves the row, truncated hits the
  // store; a missing store object is a 404. There is never a mixed state.
  pure def bodyResolved(e: Event, bodies: Set[str]): bool =
    not(e.truncated) or bodies.contains(e.id)

  // ---------------------------------------------------------------

  // Actions

  action createConversation(c: Conversation): bool = all {
    not(conversations.exists(x => x.id == c.id)),
    conversations' = conversations.union(Set(c)),
    events' = events,
    sandboxConfigs' = sandboxConfigs,
    storedBodies' = storedBodies,
  }

  action createSandboxConfig(sc: SandboxConfig): bool = all {
    not(sandboxConfigs.exists(x => x.id == sc.id)),
    sc.creatorId != "",
    sandboxConfigs' = sandboxConfigs.union(Set(sc)),
    events' = events,
    conversations' = conversations,
    storedBodies' = storedBodies,
  }

  // Write an event. Over-cap payloads stub + store; the store write carries
  // the full body of every event (rebuild property).
  action create(e: Event): bool = all {
    not(events.exists(x => x.id == e.id)),
    hasBackingConversation(e),
    kindNonEmpty(e),
    capRule(e),
    stubSelfDescribing(e),
    events' = events.union(Set(e)),
    storedBodies' = storedBodies.union(Set(e.id)),
    conversations' = conversations,
    sandboxConfigs' = sandboxConfigs,
  }

  // Partition retention drop: remove the day's rows AND the store's matching
  // date-prefix entries in one aligned sweep.
  action dropPartition(day: int): bool = {
    val dropped = events.filter(e => e.timestamp == day)
    all {
      events' = events.exclude(dropped),
      storedBodies' = storedBodies.exclude(dropped.map(e => e.id)),
      conversations' = conversations,
      sandboxConfigs' = sandboxConfigs,
    }
  }

  // Deleting a conversation cascade-removes its events and their stored
  // bodies (FK ON DELETE CASCADE; bodies orphaned only if the row cascade
  // ran — modeled as the aligned cleanup).
  action deleteConversation(id: str): bool = {
    val gone = events.filter(e => e.conversationId == id)
    all {
      events' = events.exclude(gone),
      storedBodies' = storedBodies.exclude(gone.map(e => e.id)),
      conversations' = conversations.filter(c => c.id != id),
      sandboxConfigs' = sandboxConfigs,
    }
  }

  // Backfill (store → Postgres): an envelope in the store whose row is
  // missing is rebuilt with its stored id/timestamp (re-stubbed as needed).
  action backfill(e: Event): bool = all {
    storedBodies.contains(e.id),
    not(events.exists(x => x.id == e.id)),
    hasBackingConversation(e),
    capRule(e),
    stubSelfDescribing(e),
    kindNonEmpty(e),
    events' = events.union(Set(e)),
    storedBodies' = storedBodies,
    conversations' = conversations,
    sandboxConfigs' = sandboxConfigs,
  }

  action step: bool = all {
    events' = events,
    conversations' = conversations,
    sandboxConfigs' = sandboxConfigs,
    storedBodies' = storedBodies,
  }

  // ---------------------------------------------------------------

  // Invariants

  // ids unique
  val idsUnique: bool =
    events.forall(e1 => events.forall(e2 => e1.id == e2.id implies e1 == e2))

  // every event is backed by an existing conversation
  val allBackedByConversation: bool =
    events.forall(e => hasBackingConversation(e))

  // the body-cap rule holds for every stored row
  val allCapRule: bool =
    events.forall(e => capRule(e))

  // non-empty kind + stub self-describing
  val allKindsNonEmpty: bool =
    events.forall(e => kindNonEmpty(e))
  val allStubsSelfDescribing: bool =
    events.forall(e => stubSelfDescribing(e))

  // /body resolves for every event: inline for not-truncated, store for
  // truncated (this is the aligned store mirror the partition drop must
  // preserve).
  val allBodiesResolvable: bool =
    events.forall(e => bodyResolved(e, storedBodies))

  // The user ids the read scope quantifies over: every sandbox-config
  // creator plus a fixed "stranger".
  pure def mentionedUsers(c: Set[SandboxConfig]): Set[str] =
    c.map(sc => sc.creatorId).union(Set("stranger"))

  val readScopeSound: bool =
    events.forall(e =>
      mentionedUsers(sandboxConfigs).forall(u =>
        canRead(e, u, false, conversations, sandboxConfigs) implies
          conversations.exists(c =>
            c.id == e.conversationId and
              sandboxConfigs.exists(sc =>
                sc.id == c.sandboxConfigId and sc.creatorId == u))))

  // ---------------------------------------------------------------

  // Tests

  val _cfg1: SandboxConfig = { id: "sc1", creatorId: "u1" }
  val _conv1: Conversation = { id: "c1", sandboxConfigId: "sc1" }
  val _evInline: Event = {
    id: "e1", conversationId: "c1", kind: "message", timestamp: 0,
    sizeBytes: 12, truncated: false, bodyPreview: "",
  }
  val _evStub: Event = {
    id: "e2", conversationId: "c1", kind: "observation", timestamp: 0,
    truncated: true, bodyPreview: "<first-4k", sizeBytes: 2000000,
  }

  run createInlineEvent = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evInline))
      .then(all {
        assert(events.exists(e => e.id == "e1" and e.truncated == false)),
        assert(storedBodies.contains("e1")),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }

  run createOverCapBecomesStub = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evStub))
      .then(all {
        assert(events.exists(e => e.id == "e2" and e.truncated)),
        assert(storedBodies.contains("e2")),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }

  run cannotCreateWithoutConversation = {
    init.then(create(_evInline)).fail()
  }

  run cannotCreateTwice = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evInline))
      .then(create({ ..._evInline, kind: "other" }))
      .fail()
  }

  run cannotCreateMixed = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create({ ..._evInline, truncated: true }))
      .fail()
  }

  run partitionDropClearsStorePrefix = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evStub))
      .then(dropPartition(0))
      .then(all {
        assert(not(events.exists(e => e.id == "e2"))),
        assert(not(storedBodies.contains("e2"))),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }

  run conversationDeleteCascades = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evStub))
      .then(deleteConversation("c1"))
      .then(all {
        assert(not(events.exists(e => e.id == "e2"))),
        assert(not(storedBodies.contains("e2"))),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }

  run backfillRestoresMissingRow = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evStub))
      .then(dropPartition(0))
      // simulated Postgres-down: row gone but the store envelope survived
      // the mock; backfill restores it.
      .then(all {
        storedBodies' = storedBodies.union(Set("e2")),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs,
      })
      .then(backfill({ ..._evStub, truncated: true }))
      .then(all {
        assert(events.exists(e => e.id == "e2")),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }

  run ownerCanReadStrangerCannot = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evInline))
      .then(all {
        assert(canRead(_evInline, "u1", false, conversations, sandboxConfigs)),
        assert(not(canRead(_evInline, "stranger", false, conversations, sandboxConfigs))),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }

  run adminBypassesScope = {
    init.then(createSandboxConfig(_cfg1))
      .then(createConversation(_conv1))
      .then(create(_evInline))
      .then(all {
        assert(canRead(_evInline, "stranger", true, conversations, sandboxConfigs)),
        events' = events, conversations' = conversations,
        sandboxConfigs' = sandboxConfigs, storedBodies' = storedBodies,
      })
  }
}
