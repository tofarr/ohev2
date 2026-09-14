# Issue Implementation Automation

An hourly cron automation that picks up issues approved by the `issue-review`
automation and dispatches an implementation agent for each. It starts a fresh
conversation when none exists, and checks up on conversations that have
stalled — bounding retries with a label-based countdown.

GitHub labels + a canonical marker comment are the **sole source of truth**.
There is no KV store, so multiple automation servers can track the same repo
independently. Conversation liveness is derived from the agent server at run
time.

## When to use

This skill documents the state machine consumed by the `issue-implement`
automation run (`main.py`). It is not invoked directly by a human.

## Labels (state machine)

| Label | Meaning |
|---|---|
| `agent_approved` | (owned by `issue-review`) approved for implementation. Read-only here. |
| `ready_for_implementation` | Manually applied by a human — eligible for the next run. |
| `agent_remaining_attempts_<N>` (N >= 0) | Retry budget remaining on the **issue**. Absence means N = 0. Initial value on first dispatch: `agent_remaining_attempts_3`. |
| `agent_generated` | (PR-level) PR opened by an agent. |
| `ready_for_review` | (PR-level) PR ready for human review. |

### Eligibility

An issue is in the scan set when it is open and has **both**
`agent_approved` AND `ready_for_implementation`, and has **no open linked PR**.
A separate process closes the issue when a PR is merged; an open PR means
implementation is in flight and the issue is skipped. Closed/unmerged PRs do
not exclude the issue.

### Dispatch-side transitions (deterministic, script — not the LLM)

1. **Enumerate** eligible issues (§Eligibility), up to `MAX_ISSUES_PER_RUN`
   (default 3).
2. For each issue, look for the canonical marker comment
   (`<!-- openhands-automation: implementation -->`):
   - **No marker** → **fresh start** (§Fresh start).
   - **Marker present** → **check up** (§Check up).

### Fresh start (no marker)

1. Add `agent_remaining_attempts_3` to the **issue** (only if no
   `agent_remaining_attempts_<N>` label is already present).
2. Start an implementation conversation (repo cloned, branch `main`) with the
   implementation prompt.
3. Immediately post the marker comment with the returned conversation URL —
   the script owns this, not the agent, so there is no race with a
   slow-to-start conversation.

### Check up (marker present)

1. Extract + validate the conversation id from the marker (strict UUID regex).
   Invalid → skip the issue this run.
2. `GET /api/conversations/{id}`. **404 → skip** (conversation deleted or not
   hosted on this server).
3. Read `execution_status`:
   - **Terminal** (`FINISHED` / `ERROR` / `STUCK`) → resolve outcome (§Verdict).
   - **Non-terminal + no new events for > 20 min** (stalled) → spawn a
     fire-and-forget check-up conversation to summarize what happened, then
     resolve outcome as a failure (§Verdict). "Last event" is read from
     `GET /api/conversations/{id}/events/search?sort_order=desc&limit=1`.
   - **Actively running** (events within 20 min) → skip; let it work.
   - **`DELETING`** → skip.

### Verdict (script decides from execution_status — no LLM cooperation)

- Parse `agent_remaining_attempts_<N>` (minimum if multiple; default 0).
- **Success** (`FINISHED` + an open linked PR now exists): skip — the open-PR
  filter excludes the issue from future runs. No label change.
- **Failure** (`ERROR` / `STUCK`, or `FINISHED` with no open PR):
  - **N > 0 (retry):** remove `agent_remaining_attempts_<N>`, add
    `agent_remaining_attempts_<N-1}`. Start a fresh implementation conversation.
    **Update** the marker comment to point at the new conversation id. Spawn a
    fire-and-forget check-up conversation to summarize the failure.
  - **N == 0 (give-up):** remove `ready_for_implementation`; post a
    "gave up after 3 attempts" comment. Leave `agent_approved` in place.

## Marker comment format

```
<!-- openhands-automation: implementation -->
An Agent is working on this in conversation: <CONVERSATION_URL>
```

The hidden HTML marker lets the script find its own comment (the latest one)
reliably. On retry the script **edits** the existing comment (same comment id)
to point at the new conversation, so there is always exactly one canonical
marker per issue.

## Conversation-id validation

The conversation id is extracted from `<CONVERSATION_URL>` with a strict UUID
regex. A tampered comment that doesn't match is skipped — an untrusted string
must never reach a prompt or a URL parameter.
