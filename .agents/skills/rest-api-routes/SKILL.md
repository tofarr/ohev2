---
name: rest-api-routes
description: REST API naming conventions, allowed verbs, batch endpoints, error shapes, and pagination rules. Load before creating or modifying any REST route.
version: "1.0.0"
---

# REST API consistency

The REST surface must be uniform. These rules are non-negotiable:

* Collection retrieval is **always** `GET /{resource}` (paginated via `?cursor=&limit=`).
  Never invent `/list`, `/search`, `/all`, `/get` action paths for listing.
* Search is expressed as query params on the collection (`GET /{resource}?q=…`), never
  a separate `/search` route.
* Standard verbs only: `GET` (list/retrieve), `POST` (create/action), `PATCH`
  (partial update), `DELETE` (remove). Avoid `PUT` unless full-replace semantics are
  genuinely required and documented.
* Resource-scoped actions use `POST /{resource}/{id}/{action}`.
* Nested resources: `/{parent}/{id}/{child}`.
* Resource names are plural lowercase nouns (`/conversations`, `/sandboxes`).
* Every response is a documented Pydantic schema; no ad-hoc dicts.
* Error responses use a single `ProblemDetail` shape (RFC 9457) everywhere.
* Pagination, sorting, and filtering query keys are identical across resources.
* Every CRUD resource exposes both batch endpoints alongside its single-item
  CRUD:
  - Batch read: `GET /{resource}/batch?ids=<uuid>&ids=<uuid>...` returns the
    resources positionally aligned with the requested ids (`null` for
    missing/out-of-scope), capped at 100 ids.
  - Batch write: `POST /{resource}/batch` accepts a list of operations, each a
    create, update, or delete against the same resource, applied in a single
    transaction. Updates target a specific id; deletes target a specific id;
    creates carry the same payload as `POST /{resource}`.
  Batch writes must: (a) authorize each operation against its own action
  (`CREATE`/`UPDATE`/`DELETE`) using the principal's effective permission
  filter, denying the whole batch if any operation is out of scope; (b) commit
  exactly once at the end so a failure of any operation rolls back the entire
  batch (atomic, no partial application); (c) accept a mix of create/update/
  delete in one request. Resources without an update (e.g. immutable link
  tables) omit the `update` op rather than inventing one. The batch response is
  positionally aligned with the operations: the i-th entry is the resulting
  `Read` for a create/update or `null` for a delete.

When reviewing: if two resources use different verbs/names for the same operation,
reject the change. If a CRUD resource ships without its batch read/write
endpoints, reject the change unless the resource is documented as non-CRUD.
