# ADR-0002: Pluggable sandbox providers

## Context
Sandboxes may run on Docker, Kubernetes, E2B, or other runtimes. We must support
both ephemeral (request-scoped) and persistent (addressable, long-lived) sandboxes.

## Decision
A single `SandboxProvider` interface is the only integration point. Backends
(Docker, Kubernetes, E2B) implement it and register via config. Services never call
backend-specific APIs directly. Lifecycle is modeled in `specs/sandbox.qnt`.

## Consequences
Adding a backend = implement interface + config entry. No core changes. Both
lifetimes share the same API.
