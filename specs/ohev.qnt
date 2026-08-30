// ohev — top-level Quint specification index.
//
// Specs live one-per-resource under specs/. Each module is self-contained and
// verified independently in CI:
//
//   quint typecheck specs/<module>.qnt
//   quint test specs/<module>.qnt --main=<module>
//   quint run specs/<module>.qnt --main=<module> --invariant=<inv> --max-steps=100
//
// Modules (alphabetical):
//
//   api_key.qnt      — API key entity: owner, prefix, hash-at-rest, revocation
//   auth.qnt         — federated OAuth/OIDC auth state machine + token lifetimes
//   batch.qnt        — batch write semantics: atomicity, authorization, CUD mix
//   cors.qnt         — CORS allow-list: add/remove origins
//   encryption.qnt   — encryption key config + encryptionKeyInDecryptionKeys invariant
//   rbac.qnt         — RBAC evaluation: permission-union, filter disjunction
//   rest.qnt         — uniform REST route/verb mapping (review guard)
//   role.qnt         — role entity: name uniqueness, per-entity permissions
//   sandbox.qnt      — sandbox lifecycle state machine: ownership, transitions
//   search_filter.qnt — search filter semantics: operators, conjunction, composite
//   user.qnt         — user entity: id/email/username uniqueness, passwords
//
// Cross-cutting concerns:
//   - rbac.qnt models the UserRole link table and cascade-delete semantics
//   - api_key.qnt models cascade-delete when a user is removed
//   - sandbox.qnt models ownership enforcement
//
// This file intentionally does not import the submodules, so each can be
// typechecked and tested in isolation. To compose them in the future, add
// `import specs.<module>.*` here and run against --main=ohev.

module ohev {
  // Index of available spec modules. See header comment for invocation.
  pure val specModules: str = "api_key, auth, batch, cors, encryption, rbac, rest, role, sandbox, search_filter, user"
}
