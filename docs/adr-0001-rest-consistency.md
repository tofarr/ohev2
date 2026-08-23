# ADR-0001: Uniform REST resource patterns

## Context
ohev exposes many resources (users, conversations, sandboxes, MCP tools). Ad-hoc
naming historically produces inconsistency (e.g. `/list` vs `/search`).

## Decision
Every resource follows identical verbs:
- `GET /{resource}` — list (paginated)
- `POST /{resource}` — create
- `GET /{resource}/{id}` — retrieve
- `PATCH /{resource}/{id}` — partial update
- `DELETE /{resource}/{id}` — remove
- `POST /{resource}/{id}/{action}` — scoped action

Search uses query params (`?q=…`), never a bespoke route. Enforced by spec
`specs/rest.qnt` and review checklist in `AGENTS.md` §3.

## Consequences
Reviewers reject any PR that introduces a non-uniform verb. Frontend clients get
one mental model.
