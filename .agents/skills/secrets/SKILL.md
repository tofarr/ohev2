---
name: secrets
description: Secret provider architecture, value-reveal projection, encryption at rest, and SecretStr serialization conventions. Load when working on secrets, encryption, or SecretStr fields.
version: "1.0.0"
---

# Secrets & the value-reveal projection

The secrets surface is **multi-provider and retrieval-oriented**. A
`SecretProvider` is a governed CRUD row (`secret/secret_provider.py`,
`secret/secret_models.py::SecretProvider`) selecting a retrieval-only
implementation via its `kind` discriminator; the built-in `static` kind
reads from the DB-backed `static_secrets` store (`StaticSecret`). There is
no app-scoped `SecretsService` abstract factory and no
`secrets_service_class` config knob — providers are ordinary governed
resources, so external vaults (AWS Secrets Manager, 1Password, …) can be
registered/revoked through the API without a second admin surface.

## The `SecretProvider` ABC is session-aware

The provider interface (`secret/secret_provider.py`) exposes **read paths
only** (no create/update/delete) — customers administer an external vault in
their own console/CLI, and this API adds retrieval with permission gating,
not a second admin surface. Every method receives the caller's
`AsyncSession` so provider reads happen **inside the caller's transaction**
(per-test savepoints, batch commits). Providers that do not need the
database may ignore it.

Provider implementations are selected at request time from
`secret_providers.kind` via `secret_provider_registry.py`
(`register_provider_factory`). Client objects are constructed lazily per
row and cached (`SecretProviderCache`); because they are read-only there is
no explicit cleanup on shutdown. The static provider
(`secret/static_secret_provider.py`) reads `static_secrets` and decrypts
`value` via `EncryptionService` at read time.

The REST surface:

* `GET/POST/PATCH/DELETE /secret-providers` — CRUD on the governed provider
  rows. `data` is provider-specific config whose values are encrypted to
  JWE ciphertext on create/update and decrypted on read
  (`SecretProviderRead.data` masks by default).
* `GET/POST/PATCH/DELETE /static-secrets` (`kind="static"` only) — CRUD on
  the DB-backed store. `StaticSecretRead` never carries `value`.
* `GET /secret-values` (+ `/{id}`, `/batch`) — read-only reveal projection.

`secret_provider_permission` and `static_secret_permission` are ordinary
entity columns in `ROLE_ENTITY_COLUMNS` registered 1:1 via
`register_resource_policy` (both in `auth_dependencies.py`), exactly like
every other governed entity.

## Value reveal is gated by a single USE on the provider

The secret tables **never** expose their sensitive values through their own
CRUD endpoints — `StaticSecretRead` omits `value` entirely, and
`/static-secrets` returns metadata only. Decrypted plaintext is revealed
solely through the **`/secret-values`** projection, a read-only surface
(`GET /secret-values`, `GET /secret-values/batch`, `GET /secret-values/{id}`)
backed by `secret_value_service.py::SecretValueSession`, which resolves the
composite id to a provider and reads through the provider implementation.

The composite secret id is `{provider_id}/{internal_id}`
(`SecretValue.split_id`), so a caller can identify both the provider and the
secret in one token. `internal_id` is opaque (the static provider uses the
stringified row UUID).

A secret is revealed when the principal has the **`USE` action on the parent
`SecretProvider`** — there is **no separate value-reveal permission** and no
per-secret link table. Providers that admit USE disclose every value they
can read; per-item narrowing is expressed through the provider's
`AclPermission` filter being ANDed into the USE resolution. Failing the USE
filter yields 404 (fail-closed — a 404, not a 403, so existence is not
leaked). The Quint spec mirrors this in `canReveal` / `specs/secret.qnt`.

## Sensitive `data` is encrypted at rest

`SecretProvider.data` values are plaintext in transit and JWE ciphertext at
rest: the service layer encrypts each value on create/update (`encrypt_secret_map`)
and decrypts on read (`decrypt_secret_map`), exactly matching the MCP server
config pattern. `StaticSecret.value` is likewise JWE ciphertext, decrypted
by the static provider at read time. The read schemas mask `data` values as
`**********` by default; only callers that pass the `expose_secrets`
context flag see plaintext.

# SecretStr serialization standard

Sensitive fields that travel as `SecretStr` are serialized through a uniform
pydantic-context convention implemented in
`util/secret_serialization.py` and used from
`field_serializer` / `field_validator` decorators on the owning models.

* An **optional context object** is passed when serializing/deserializing.
* If the context carries an `encryption_service` (an `EncryptionService`),
  `SecretStr` values are **encrypted on dump** via
  `EncryptionService.encrypt_value` and **decrypted on load** via
  `EncryptionService.decrypt_value` (the column stores JWE ciphertext).
* Otherwise, if the context carries `expose_secrets: true`, secrets are
  dumped in plaintext.
* Otherwise (no context / neither flag), secrets are **redacted** (Pydantic's
  default `str(SecretStr)` → `**********`).

Encryption wins over plaintext exposure, which wins over redaction — an
explicit encryption request must never leak plaintext through a stray flag.
The helpers accept the pydantic `ValidationInfo` / `SerializationInfo` when
available so the context flows through `model_dump(..., context=...)` and
`model_validate(..., context=...)`.
