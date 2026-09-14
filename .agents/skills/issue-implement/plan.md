# Issue Implementation Automation — Plan

A custom-script automation that complements the existing `issue-review`
automation. Once an hour it scans open issues that are **approved and ready for
implementation**, starts an implementation conversation for any that have none
yet, and checks up on conversations that appear to have stalled — using a
label-based countdown to bound retries.

GitHub labels + the marker comment are the **sole source of truth**. There is
**no KV store**, so multiple automation servers can track the same repo
independently without shared-state races. Conversation liveness is determined
by querying the agent server (not by a stored timestamp).

---

## 1. Trigger

Cron, hourly: `0 * * * *` (UTC), mirroring the issue-review automation.

## 2. Custom script (no LLM for orchestration)

This is a **custom Python script** (`main.py`, entrypoint `python3 main.py`),
not a prompt/plugin preset. The orchestration is deterministic — GitHub REST +
agent-server REST. Only the two *spawned* conversations (implementation and
check-up) use an LLM. Uses the standard no-LLM helpers `get_secret` /
`fire_callback` from the automation skill, and the same GitHub/agent-server
helpers as the issue-review `main.py`.

## 3. Labels (state machine)

| Label | Meaning |
|---|---|
| `agent_approved` | (from issue-review) approved for implementation. |
| `ready_for_implementation` | Manually applied by a human — eligible for the next run. |
| `agent_remaining_attempts_<N>` (N >= 0) | Retry budget remaining. **No bare `agent_remaining_attempts`** — absence means the budget is exhausted (N = 0). Initial value on first dispatch: `agent_remaining_attempts_3`. |

`agent_approved` + `ready_for_implementation` together = "in the scan set".
`agent_remaining_attempts_<N>` is optional at first dispatch; if absent it is
treated as N = 0 for the purpose of the *check-up* branch, but a fresh
implementation conversation is still started once (see §6.1).

> **Note:** the issue-review automation already owns `agent_approved`. This
> automation consumes it (read-only) as part of the eligibility filter and
> never adds/removes it.

## 4. Eligibility filter (per run)

Enumerate open issues with **both** `agent_approved` AND `ready_for_implementation`.
Then drop an issue if it has an **open** linked PR:
- A separate process closes the issue when the PR is merged, so an open PR
  means implementation is in flight elsewhere and we must not double-dispatch.
- Closed/unmerged PRs do **not** exclude the issue (a fresh attempt is valid).

Linked-PR detection uses the GitHub timeline `connected`/`cross-referenced`
events plus PR-body `Fixes #N` / `Closes #N` parsing, filtered to PRs whose
state is `open`. (The GitHub REST `GET /repos/{repo}/issues/{n}/timeline` and
`GET /repos/{repo}/issues/{n}/events` endpoints are used.)

Cap: **at most 3 issues acted on per run** (`MAX_ISSUES_PER_RUN`, default 3)
across both branches (fresh-start + check-up), to bound token/sandbox cost.

## 5. Marker comment (canonical, owned by the script)

When the script starts an implementation conversation it **immediately** posts
a canonical marker comment so the next run sees it (no race with a
slow-to-start agent). Format:

```
<!-- openhands-automation: implementation -->
An Agent is working on this in conversation: <CONVERSATION_URL>
```

- The hidden HTML marker (`<!-- openhands-automation: implementation -->`)
  lets the script reliably find *its own* comment (the latest one) even when
  humans or other agents add comments.
- `<CONVERSATION_URL>` is the full agent-server conversation URL, e.g.
  `http://<host>/api/conversations/<uuid>`. The conversation id is extracted
  from this URL with a strict regex (see §9).
- On a retry that spawns a **new** implementation conversation, the script
  **updates** the existing marker comment (edits the same comment id) rather
  than posting a duplicate, so there is always exactly one canonical marker.
  This removes "which conversation do I check up on?" ambiguity.

## 6. Per-issue flow

For each eligible issue (up to the cap):

### 6.1 No marker comment present → fresh start

1. Add `agent_remaining_attempts_3` (only if no `agent_remaining_attempts_<N>`
   label is already present — a human may have pre-set a different budget).
2. Start an implementation conversation: repo cloned, branch `main`, with the
   implementation prompt (§7.1). The `GITHUB_TOKEN` is passed as a
   conversation secret so the agent can open the PR and apply labels.
3. Immediately post the marker comment (§5) with the returned conversation id.
4. Done for this issue this run.

### 6.2 Marker comment present → check up on the existing conversation

1. Extract and **validate** the conversation id from the marker (§9). If
   invalid → skip the issue this run (do not act on an untrusted string).
2. Query the agent server: `GET /api/conversations/{id}`. If the conversation
   **could not be found** (HTTP 404) → **skip** this issue this run (per the
   user's instruction; the conversation may have been deleted, or this server
   doesn't host it). Do not decrement, do not start a new one — just skip.
3. Read `execution_status` from the conversation:
   - **Terminal** (`FINISHED` / `ERROR` / `STUCK`) → the implementation run
     ended. Spawn a **check-up conversation** (§7.2) to figure out what
     happened and decide retry vs give-up.
   - **Non-terminal but stalled** (`RUNNING`/`PAUSED`/
     `WAITING_FOR_CONFIRMATION`/`IDLE`) and the conversation has had **no new
     events for > STALE_THRESHOLD** (default 20 min) → spawn a check-up
     conversation. "Last event timestamp" is read from
     `GET /api/conversations/{id}/events/search?sort_order=desc&limit=1` —
     no stored timestamp needed.
   - **Actively running** (events within STALE_THRESHOLD) → skip; let it work.
   - **`DELETING`** → skip.

### 6.3 Verdict → script decides from execution_status (no LLM cooperation needed)

The **script** decides retry-vs-give-up deterministically from the
implementation conversation's `execution_status` — the check-up conversation
is spawned purely to summarize and post a human-auditable comment (fire-and-
forget; the script does not wait for it).

- Parse the current `agent_remaining_attempts_<N>` (minimum if multiple;
  default 0 if none).
- **Success (FINISHED + open linked PR exists):** skip — the open-PR filter
  (§4) excludes the issue from future runs. No label change, no retry.
- **Failure (ERROR / STUCK, or FINISHED with no open PR):**
  - **N > 0 (retry):** remove `agent_remaining_attempts_<N>`, add
    `agent_remaining_attempts_<N-1}`. Start a fresh implementation conversation
    (§7.1). **Update** the marker comment (§5) to point at the new conversation
    id. Spawn a check-up conversation (§7.2, fire-and-forget) to summarize
    what went wrong.
  - **N == 0 (give-up):** go to §6.4.

### 6.4 Terminal at countdown 0 → stop retrying

When `agent_remaining_attempts_0` is present (or N reaches 0 after a
decrement):

1. Remove `ready_for_implementation` (so the issue drops out of the scan set).
2. Post a "gave up after 3 attempts" comment to the issue, summarizing that
   the automation exhausted its retry budget and a human should take over.
3. Leave `agent_approved` in place (it's the review automation's label; not
   this automation's to remove).

> The issue can be re-queued later by a human re-adding
> `ready_for_implementation` (and optionally bumping the attempts label).

## 7. Prompts

### 7.1 Implementation prompt

Sent to the implementation conversation (repo cloned, branch `main`):

> Please implement <ISSUE_URL>. Create a PR when you are finished with an
> appropriate title and description linked to the issue. Mark the PR with the
> labels `agent_generated` and `ready_for_review`.
>
> (Standard impl-detail note: the repo's AGENTS.md and .agents/skills/ are
> loaded in your workspace; follow them.)

The `agent_remaining_attempts_3` label is applied to the **issue** by the
script (§6.1), not by the implementation agent, and not on the PR.

### 7.2 Check-up prompt

Sent to the check-up conversation. `<CONVERSATION_ID>` is the validated id
extracted from the marker; `<ISSUE_URL>` is the issue's HTML URL:

> It looks like a conversation was created to handle <ISSUE_URL>, but it has
> been running for quite some time. Please examine conversation
> <CONVERSATION_ID> and its events with a view to figuring out what happened.
> If there was an error, please try to summarize a reason and post a comment
> back to the issue explaining it.

When the countdown label is present and **greater than zero**, append:

> If the issue seems trivial / recoverable, please prompt the agent to
> continue. Remove label `agent_remaining_attempts_<N>` from the issue and add
> label `agent_remaining_attempts_<N-1>` to the issue.

…where `<N>` is the current parsed value. (The check-up agent is told the
label names for transparency, but the **script** performs the actual label
swap after the agent returns, to keep bookkeeping deterministic and atomic.
The agent's job is to examine, summarize, and commit to a retry/give-up
verdict.)

The check-up conversation has the repo cloned (so it can post comments via the
GitHub API) and `GITHUB_TOKEN` as a secret. It reads the implementation
conversation's events via the agent-server REST API
(`GET /api/conversations/<id>/events/search`) using `AGENT_SERVER_URL` +
`SESSION_API_KEY` — confirmed available (see §8).

## 8. Can the check-up agent read another conversation's events? — YES

Confirmed by inspecting the agent server source
(`openhands-agent-server/openhands/agent_server/`):

- The entire `/api` surface is protected by a single dependency,
  `check_session_api_key` (`dependencies.py`), applied once to the
  `api_router` (`api.py`). It validates only that the supplied
  `X-Session-API-Key` is in the server's global `session_api_keys` list —
  **there is no per-conversation scoping**. Any valid session key can read
  any conversation's events.
- `GET /api/conversations/{conversation_id}/events/search` returns events for
  any conversation id, gated only by that header. `GET /api/conversations/{id}`
  returns `execution_status` (and 404s if the conversation doesn't exist on
  this server).
- `ConversationExecutionStatus` (`openhands/sdk/conversation/state.py`) has
  `IDLE | RUNNING | PAUSED | WAITING_FOR_CONFIRMATION | FINISHED | ERROR |
  STUCK | DELETING`, with `is_terminal()` = `{FINISHED, ERROR, STUCK}`. This
  is exactly what the script needs to decide fresh-vs-stalled-vs-terminal.

So the spawned check-up conversation can fetch another conversation's events
directly using its injected `AGENT_SERVER_URL` + `SESSION_API_KEY`. The script
also uses the same endpoints for its own liveness check before spawning.

## 9. conversation_id validation

Extracted from the marker comment's `<CONVERSATION_URL>` with a strict regex:
`/api/conversations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`.
If the URL doesn't match (or the id fails `uuid.UUID` parsing), the issue is
**skipped** this run — an untrusted/tampered comment must never inject an
arbitrary string into the check-up prompt or a URL parameter.

## 10. Multi-server independence (no KV store)

State lives entirely in GitHub (labels + the marker comment) and is
re-derived each run from the agent server. Therefore:

- Multiple automation servers can run the same cron against the same repo
  without a shared KV store.
- The main race is two servers dispatching a fresh implementation conversation
  for the same issue in the same tick. Mitigation: the marker comment is
  posted **immediately** after a conversation starts, and the eligibility check
  reads comments before acting. This is best-effort (two servers could both
  read "no marker" within the same minute). Acceptable given the per-run cap
  of 3 and hourly cadence; a duplicate conversation is non-fatal (the
  check-up branch will pick the latest marker). A stricter guard can be added
  later via a GitHub "lock" label if needed.

## 11. Files (mirrors issue-review layout)

```
.agents/skills/issue-implement/
  plan.md                 # this file
  SKILL.md                # skill doc (labels + state machine, like issue-review's)
  AUTOMATION_PROMPT.md    # fenced prompt templates (impl + check-up)
  main.py                 # custom dispatch script
  deploy.sh               # creates labels, tars, uploads, creates cron automation
```

## 12. Config (env, defaults)

| Env | Default | Purpose |
|---|---|---|
| `OHE_REPO` | `tofarr/ohev2` | target repo |
| `MAX_ISSUES_PER_RUN` | `3` | per-run cap across both branches |
| `STALE_THRESHOLD` | `1200` (20 min) | no-new-events → stalled |
| `CONV_TIMEOUT` | `600` | per-conversation timeout (s) |
| `OHE_AGENT_PROFILE` | `default` | agent profile name |
| `OHE_WORKSPACE_ROOT` | `/tmp/issue-implement-workspaces` | clone root |

Injected at runtime by the automation service: `AGENT_SERVER_URL`,
`SESSION_API_KEY`, `AUTOMATION_CALLBACK_URL`,
`AUTOMATION_CALLBACK_API_KEY`, `AUTOMATION_RUN_ID`. `GITHUB_TOKEN` is fetched
via `get_secret("GITHUB_TOKEN")`.

## 13. Labels to create (deploy.sh)

| Label | Color | Description |
|---|---|---|
| `ready_for_implementation` | `22C55E` | Manually applied: ready for agent implementation |
| `agent_remaining_attempts_0` | `EF4444` | Retry budget exhausted |
| `agent_remaining_attempts_1` | `F59E0B` | 1 retry remaining |
| `agent_remaining_attempts_2` | `F59E0B` | 2 retries remaining |
| `agent_remaining_attempts_3` | `3B82F6` | 3 retries remaining (initial) |
| `agent_generated` | `8B5CF6` | PR opened by an agent (PR-level) |
| `ready_for_review` | `10B981` | PR ready for human review (PR-level) |

(`agent_approved` is owned by the issue-review automation and not recreated
here.)

## 14. Resolved decisions

1. **`agent_remaining_attempts_3` belongs on the issue, not the PR.** The
   script applies it to the issue on first dispatch (§6.1). The implementation
   prompt only tells the agent to add `agent_generated` + `ready_for_review`
   to the PR.
2. **Verdict from execution_status.** The script decides retry-vs-give-up
   purely from `execution_status` (§6.3). No LLM cooperation needed for the
   label swap. The check-up conversation is fire-and-forget summarization.
3. **Stale threshold = 20 minutes** (1200 s).
4. **Linked-PR detection** via GitHub timeline `cross-referenced` events +
   PR-body `Fixes #N` / `Closes #N` parsing, filtered to open PRs.
