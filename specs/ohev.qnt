// ohev — top-level Quint specification.
//
// Specs live one-per-resource under specs/. This file is the entry point and
// re-exports the modules used for invariant checking.
//
// Run: quintc specs/<module>.qnt
// Test: quint test --main=<module>::<name> specs/<module>.qnt

module ohev {
  import sandbox.*
  import auth.*
  import rest.*
}
