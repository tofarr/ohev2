// Secret specification (AGENTS.md §12).
//
// The secrets surface is multi-provider, retrieval-oriented. A
// `SecretProvider` is a governed CRUD row (`secret_provider_permission`)
// selecting a retrieval-only implementation via its `kind` discriminator;
// the built-in `static` kind reads from the DB-backed `static_secrets`
// store. The `/secret-values` reveal projection returns decrypted plaintext
// gated by a **single** USE permission on the parent provider — there is no
// separate value-reveal permission or per-secret link table.
//
// The composite secret id is `{provider_id}/{internal_id}`; in this spec the
// composite is modeled as the pair `(providerId, internalId)` (Quint strings
// do not support splitting), and `internalId` addresses a secret within a
// provider's store. Static-secret names are unique and env-var compatible.

module secret {
  // ---- Data model -----------------------------------------------------------

  type SecretProvider = {
    id: str,
    kind: str,
    creatorId: str,
  }

  type StaticSecret = {
    id: str,
    name: str,
    value: str,
    creatorId: str,
  }

  // The composite id `{provider_id}/{internal_id}` addresses a value.
  type CompositeId = (str, str)

  // ---- State --------------------------------------------------------------

  var providers: Set[SecretProvider]

  var staticSecrets: Set[StaticSecret]

  // Provider ids the principal may USE (resolved from the role's
  // secret_provider_permission). Reveal is gated on this alone.
  var providerIdsUserCanUse: Set[str]

  action init = all {
    providers' = Set(),
    staticSecrets' = Set(),
    providerIdsUserCanUse' = Set(),
  }

  // ---- Actions --------------------------------------------------------------

  action createProvider(provider: SecretProvider): bool = all {
    not(providers.exists(p => p.id == provider.id)),
    provider.kind != "",
    providers' = providers.union(Set(provider)),
    staticSecrets' = staticSecrets,
    providerIdsUserCanUse' = providerIdsUserCanUse,
    true,
  }

  action deleteProvider(id: str): bool = all {
    providers.exists(p => p.id == id),
    providers' = providers.filter(p => p.id != id),
    staticSecrets' = staticSecrets,
    providerIdsUserCanUse' = providerIdsUserCanUse.filter(pid => pid != id),
    true,
  }

  action grantProviderUse(id: str): bool = all {
    providers.exists(p => p.id == id),
    not(providerIdsUserCanUse.contains(id)),
    providers' = providers,
    staticSecrets' = staticSecrets,
    providerIdsUserCanUse' = providerIdsUserCanUse.union(Set(id)),
    true,
  }

  action createStaticSecret(secret: StaticSecret): bool = all {
    not(staticSecrets.exists(s => s.id == secret.id)),
    not(staticSecrets.exists(s => s.name == secret.name)),
    secret.name != "",
    providers' = providers,
    staticSecrets' = staticSecrets.union(Set(secret)),
    providerIdsUserCanUse' = providerIdsUserCanUse,
    true,
  }

  action deleteStaticSecret(id: str): bool = all {
    staticSecrets.exists(s => s.id == id),
    providers' = providers,
    staticSecrets' = staticSecrets.filter(s => s.id != id),
    providerIdsUserCanUse' = providerIdsUserCanUse,
    true,
  }

  action deleteUser(userId: str): bool = all {
    providers' = providers,
    staticSecrets' = staticSecrets.filter(s => s.creatorId != userId),
    providerIdsUserCanUse' = providerIdsUserCanUse,
    true,
  }

  // ---- Reveal projection ------------------------------------------------------

  // A value reveal succeeds when the principal may USE the composite's provider
  // AND a static secret with that internal id exists. There is no second
  // value-reveal permission: USE on the provider alone gates revelation.
  def canReveal(composite: CompositeId): bool =
    providerIdsUserCanUse.contains(composite._1)
      and staticSecrets.exists(s => s.id == composite._2)

  // ---- Invariants ------------------------------------------------------------

  val providerIdsUnique: bool =
    providers.forall(a => providers.forall(b => (a.id == b.id) implies a == b))

  val staticSecretIdsUnique: bool =
    staticSecrets.forall(a => staticSecrets.forall(b => (a.id == b.id) implies a == b))

  val staticSecretNamesUnique: bool =
    staticSecrets.forall(a => staticSecrets.forall(b => (a.name == b.name) implies a.id == b.id))

  // Valueless state-change noop helper for tests.
  action assertNoStateChange: bool = all {
    providers' = providers,
    staticSecrets' = staticSecrets,
    providerIdsUserCanUse' = providerIdsUserCanUse,
    true,
  }

  // ---- Tests -----------------------------------------------------------------

  run revealRequiresProviderUse = {
    init
      .then(createProvider({ id: "p1", kind: "static", creatorId: "u1" }))
      .then(createStaticSecret({ id: "s1", name: "API_KEY", value: "hunter2", creatorId: "u1" }))
      .then(all {
        // Without USE on the provider the reveal is denied...
        assert(not(canReveal(("p1", "s1")))),
        assertNoStateChange,
      })
      .then(grantProviderUse("p1"))
      .then(all {
        // ...with USE, the composite reveal succeeds (single gate).
        assert(canReveal(("p1", "s1"))),
        assert(
          staticSecrets.exists(s => s.id == "s1" and s.name == "API_KEY" and s.value == "hunter2")
        ),
        assertNoStateChange,
      })
  }

  run useScopeIsPerProvider = {
    init
      .then(createProvider({ id: "p1", kind: "static", creatorId: "u1" }))
      .then(createProvider({ id: "p2", kind: "static", creatorId: "u1" }))
      .then(createStaticSecret({ id: "s1", name: "API_KEY", value: "hunter2", creatorId: "u1" }))
      .then(grantProviderUse("p2"))
      .then(all {
        // USE on p2 alone does not grant reveal scope over p1.
        assert(not(providerIdsUserCanUse.contains("p1"))),
        assert(providerIdsUserCanUse.contains("p2")),
        assert(not(canReveal(("p1", "s1")))),
        assertNoStateChange,
      })
      .then(grantProviderUse("p1"))
      .then(all {
        assert(canReveal(("p1", "s1"))),
        assertNoStateChange,
      })
  }

  run cannotReuseStaticSecretName = {
    init
      .then(createStaticSecret({ id: "s1", name: "API_KEY", value: "a", creatorId: "u1" }))
      .then(createStaticSecret({ id: "s2", name: "API_KEY", value: "b", creatorId: "u1" }))
      .fail()
  }

  run staticSecretIdsAreUnique = {
    init
      .then(createStaticSecret({ id: "s1", name: "API_KEY", value: "a", creatorId: "u1" }))
      .then(createStaticSecret({ id: "s1", name: "OTHER", value: "b", creatorId: "u1" }))
      .fail()
  }

  run deleteProviderRevokesReveal = {
    init
      .then(createProvider({ id: "p1", kind: "static", creatorId: "u1" }))
      .then(createStaticSecret({ id: "s1", name: "API_KEY", value: "hunter2", creatorId: "u1" }))
      .then(grantProviderUse("p1"))
      .then(all {
        assert(canReveal(("p1", "s1"))),
        assertNoStateChange,
      })
      .then(deleteProvider("p1"))
      .then(all {
        assert(not(canReveal(("p1", "s1")))),
        assert(not(providers.exists(p => p.id == "p1"))),
        assertNoStateChange,
      })
  }
}