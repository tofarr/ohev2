// ohev — top-level Quint specification index.
//
// Specs live one-per-resource under specs/. Each module is self-contained and
// verified independently in CI:
//
//   quint typecheck specs/<module>.qnt
//   quint test specs/<module>.qnt --main=<module>
//   quint run specs/<module>.qnt --main=<module> --invariant=<inv> --max-steps=100
//
// Modules:
//   sandbox.qnt    — sandbox lifecycle state machine + statesConsistent invariant
//   rest.qnt       — uniform REST route/verb mapping (review guard)
//   encryption.qnt — encryption key config + encryptionKeyInDecryptionKeys invariant
//   user.qnt       — user entity + userIdsUnique / userEmailsUnique invariants
//   auth2.qnt      — federated OAuth/OIDC auth state machine + token lifetimes
//
// This file intentionally does not import the submodules, so each can be
// typechecked and tested in isolation. To compose them in the future, add
// `import specs.<module>.*` here and run against --main=ohev.

module ohev {
  // Index of available spec modules. See header comment for invocation.
  pure val specModules: str = "sandbox, rest, encryption, user, auth2"
}
