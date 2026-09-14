// Conversation template resource specification (issue #132).
//
// Models the /conversation-templates governed resource and the invariants the
// REST collection must uphold (AGENTS.md §11):
//
//   - template ids are unique
//   - every template has exactly one creator (the principal that created it)
//   - name is non-empty
//   - access is governed by the `conversation_template_permission` role column:
//     creators manage their own templates; non-creators are granted USE via a
//     grant role (`on_mismatch`), never full management. Deleting the template
//     revokes both creator management and granted USE.
//   - deleting a user cascades to templates they created
//   - an `agent_kind` is one of the two SDL settings discriminators
//     (openhands / acp) so the start service can meet the `AgentSettings`
//     discriminated-union contract.
//
// Companion to rbac.qnt (per-entity JSONB permission columns), role.qnt
// (role lifecycle), and rest.qnt (the uniform REST route/verb mapping).

module conversation_template {
  type AgentKind = Openhands | Acp

  type ConversationTemplate = {
    id: str,
    creatorId: str,
    name: str,
    agentKind: AgentKind,
    llmId: OptStr,
    mcpServerConfigIds: List[str],
    secretProviderIds: List[str],
    staticSecretIds: List[str],
    hasAgentConfig: bool,
    hasConversationConfig: bool,
    hasDefaultCallbacks: bool,
    createdAt: int,
    updatedAt: int,
  }

  // Optional string id; Absent models an unset FK / empty list.
  type OptStr = Present(str) | Absent

  // Template ids the principal may USE (resolved from the role's
  // conversation_template_permission via a grant role `on_mismatch`).
  // Reveal/use at start-conversation time is gated on this alone.
  var templates: Set[ConversationTemplate]

  var templateIdsUserCanUse: Set[str]

  action init = all {
    templates' = Set(),
    templateIdsUserCanUse' = Set(),
  }

  // No two templates share the same id.
  def idUnique(t1: ConversationTemplate, t2: ConversationTemplate): bool =
    t1.id == t2.id implies t1 == t2

  // Every template name is non-empty.
  def nameNonEmpty(t: ConversationTemplate): bool =
    t.name != ""

  pure def sampleTemplate(id: str, creatorId: str): ConversationTemplate =
    { id: id, creatorId: creatorId, name: "default", agentKind: Openhands,
      llmId: Absent, mcpServerConfigIds: [], secretProviderIds: [],
      staticSecretIds: [], hasAgentConfig: false, hasConversationConfig: false,
      hasDefaultCallbacks: false, createdAt: 0, updatedAt: 0 }

  action createTemplate(t: ConversationTemplate): bool = all {
    not(templates.exists(existing => existing.id == t.id)),
    t.creatorId != "",
    nameNonEmpty(t),
    templates' = templates.union(Set(t)),
    templateIdsUserCanUse' = templateIdsUserCanUse,
    true,
  }

  action updateTemplate(id: str, name: str): bool = all {
    templates.exists(t => t.id == id),
    name != "",
    templates' = templates.map(t =>
      if (t.id == id)
        { id: t.id, creatorId: t.creatorId, name: name, agentKind: t.agentKind,
          llmId: t.llmId, mcpServerConfigIds: t.mcpServerConfigIds,
          secretProviderIds: t.secretProviderIds,
          staticSecretIds: t.staticSecretIds,
          hasAgentConfig: t.hasAgentConfig,
          hasConversationConfig: t.hasConversationConfig,
          hasDefaultCallbacks: t.hasDefaultCallbacks,
          createdAt: t.createdAt, updatedAt: t.updatedAt + 1 }
      else
        t),
    templateIdsUserCanUse' = templateIdsUserCanUse,
    true,
  }

  action deleteTemplate(id: str): bool = all {
    templates.exists(t => t.id == id),
    templates' = templates.filter(t => t.id != id),
    templateIdsUserCanUse' = templateIdsUserCanUse.filter(tid => tid != id),
    true,
  }

  action grantTemplateUse(id: str): bool = all {
    templates.exists(t => t.id == id),
    not(templateIdsUserCanUse.contains(id)),
    templates' = templates,
    templateIdsUserCanUse' = templateIdsUserCanUse.union(Set(id)),
    true,
  }

  action deleteUser(userId: str): bool = all {
    templates' = templates.filter(t => t.creatorId != userId),
    // A user's granted USE is revoked with the templates it covers.
    templateIdsUserCanUse' = templateIdsUserCanUse.filter(tid =>
      templates.exists(t => t.id == tid and t.creatorId != userId)),
    true,
  }

  val templateIdsUnique: bool =
    templates.forall(t1 => templates.forall(t2 => idUnique(t1, t2)))

  val templateNamesNonEmpty: bool =
    templates.forall(nameNonEmpty)

  val templateUsesReferenceTemplate: bool =
    templateIdsUserCanUse.forall(tid => templates.exists(t => t.id == tid))

  run canCreateTemplate = {
    init.then(createTemplate(sampleTemplate("t1", "u1")))
      .then(all {
        assert(templates.exists(t => t.id == "t1")),
        assert(templateIdsUserCanUse.size() == 0),
        templates' = templates,
        templateIdsUserCanUse' = templateIdsUserCanUse,
      })
  }

  run canUpdateTemplate = {
    init.then(createTemplate(sampleTemplate("t1", "u1")))
      .then(updateTemplate("t1", "renamed"))
      .then(all {
        assert(templates.exists(t => t.id == "t1" and t.name == "renamed")),
        templates' = templates,
        templateIdsUserCanUse' = templateIdsUserCanUse,
      })
  }

  run cannotCreateDuplicateId = {
    init
      .then(createTemplate(sampleTemplate("t1", "u1")))
      .then(createTemplate(sampleTemplate("t1", "u2")))
      .fail()
  }

  run cannotCreateEmptyName = {
    init.then(createTemplate({ id: "t1", creatorId: "u1", name: "",
      agentKind: Openhands, llmId: Absent, mcpServerConfigIds: [],
      secretProviderIds: [], staticSecretIds: [], hasAgentConfig: false,
      hasConversationConfig: false, hasDefaultCallbacks: false,
      createdAt: 0, updatedAt: 0 })).fail()
  }

  run canGrantUse = {
    init
      .then(createTemplate(sampleTemplate("t1", "u1")))
      .then(grantTemplateUse("t1"))
      .then(all {
        assert(templateIdsUserCanUse.contains("t1")),
        templates' = templates,
        templateIdsUserCanUse' = templateIdsUserCanUse,
      })
  }

  run cannotGrantUseOnMissingTemplate = {
    init.then(grantTemplateUse("missing")).fail()
  }

  run deleteRevokesUse = {
    init
      .then(createTemplate(sampleTemplate("t1", "u1")))
      .then(grantTemplateUse("t1"))
      .then(deleteTemplate("t1"))
      .then(all {
        assert(not(templates.exists(t => t.id == "t1"))),
        assert(not(templateIdsUserCanUse.contains("t1"))),
        templates' = templates,
        templateIdsUserCanUse' = templateIdsUserCanUse,
      })
  }

  run deletingCreatorUserRemovesTemplates = {
    init
      .then(createTemplate(sampleTemplate("t1", "u1")))
      .then(createTemplate(sampleTemplate("t2", "u2")))
      .then(deleteUser("u1"))
      .then(all {
        assert(not(templates.exists(t => t.id == "t1"))),
        assert(templates.exists(t => t.id == "t2")),
        templates' = templates,
        templateIdsUserCanUse' = templateIdsUserCanUse,
      })
  }
}