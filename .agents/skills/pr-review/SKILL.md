# PR Review Automation

An hourly cron automation that picks up PRs which are **ready for review**,
have **no outstanding "request changes" reviews**, and have **all CI checks
passing**. It starts a conversation that reviews the PR using the `code-review`
skill, cross-checks it against the original issue, and then either approves
the PR or applies fixes and re-queues for a full re-review — bounding retries
with a label-based countdown.

GitHub labels + a canonical marker comment are the **sole source of truth**.
There is no KV store, so multiple automation servers can track the same repo
independently. Conversation liveness is derived from the agent server at run
time.

## When to use

This skill documents the state machine consumed by the `pr-review` automation
run (`main.py`). It is not invoked directly by a human.

## Labels (state machine)

| Label | Meaning |
|---|---|
| `ready_for_review` | (owned by `issue-implement`) PR eligible for review. Consumed read-only here as the queue signal, then swapped by this automation during review. |
| `agent_reviewing` | In-flight claim token — a conversation is reviewing this PR. Persists through crashes. |
| `agent_attempts_remaining_<N>` (N >= 0) | Review/fix budget remaining on the **PR**. Absence means N = 0. Initial value on first dispatch: `agent_attempts_remaining_3`. |
| `agent_reviewed` | Done — PR approved by the agent. |
| `agent_changes_requested` | Done — agent requested changes and exhausted its fix budget. Escalate to a human. |

### Eligibility

A PR is in the scan set when it is open and has the `ready_for_review` label
AND does NOT have the `agent_reviewing` label, AND has **no
`CHANGES_REQUESTED` reviews** (from anyone), AND all CI checks are passing
(combined status = success). A PR with a `CHANGES_REQUESTED` review is
excluded — that means a human (or the agent) has already asked for changes and
the author must push new commits before re-review.

### Dispatch-side transitions (deterministic, script — not the LLM)

1. **Enumerate** two sets of PRs:
   - `ready_for_review` PRs (eligible for fresh start), up to `MAX_PRS_PER_RUN`
     (default 3).
   - `agent_reviewing` PRs (in-flight — need check-up or rescue).
2. **Rescue** (each run, after enumeration): PRs with `agent_reviewing` whose
   conversation has had no new events for > `STALE_THRESHOLD` (default 20 min)
   → remove `agent_reviewing`, re-add `ready_for_review`. N is preserved
   because `agent_attempts_remaining_<N>` was never removed at claim time.
   PRs with `agent_reviewing` but no valid marker comment are also re-queued
   (stale claim from a crashed run).
3. **Check up** on `agent_reviewing` PRs (up to the cap): find the marker
   comment, validate the conversation id, query the agent server for
   `execution_status`, and resolve the outcome (§Verdict).
4. **Fresh start** on `ready_for_review` PRs (up to the cap) that have no
   marker (or were just rescued): verify CI, claim, start a review
   conversation, post the marker.

### Fresh start (no marker)

1. **Verify CI is green** (combined status = success). If not green, skip the
   PR this run — it will be picked up next hour when checks finish.
2. **Claim** the PR: remove `ready_for_review`; add `agent_reviewing`. **Leave**
   any `agent_attempts_remaining_<N>`.
3. Set `agent_attempts_remaining_3` on the PR (only if no
   `agent_attempts_remaining_<N>` label is already present).
4. **Find the linked issue** (from the PR body `Fixes #N` / `Closes #N` /
   timeline `cross-referenced` events). Pass its URL into the prompt so the
   reviewer can verify the PR accomplishes what was requested.
5. **Start** a review conversation (repo cloned at the PR head) with the review
   prompt (§Review prompt).
6. Immediately post the marker comment with the returned conversation URL and
   the base SHA — the script owns this, so there is no race with a
   slow-to-start conversation.

### Check up (marker present)

1. Extract + validate the conversation id from the marker (strict UUID regex).
   Invalid → skip the PR this run.
2. `GET /api/conversations/{id}`. **404 → skip** (conversation deleted or not
   hosted on this server).
3. Read `execution_status`:
   - **Terminal** (`FINISHED` / `ERROR` / `STUCK`) → resolve outcome (§Verdict).
   - **Non-terminal + no new events for > 20 min** (stalled) → resolve outcome
     as a failure (§Verdict). "Last event" is read from
     `GET /api/conversations/{id}/events/search?limit=1&sort_order=TIMESTAMP_DESC`.
   - **Actively running** (events within 20 min) → skip; let it work.
   - **`DELETING`** → skip.

### Verdict (script decides from GitHub state + execution_status — no LLM cooperation)

The **script** decides the outcome deterministically from the PR's GitHub state
(reviews + commits) after the conversation finishes. Parse
`agent_attempts_remaining_<N>` (minimum if multiple; default 0).

- **Approved (an `APPROVE` review exists on the PR):** remove `agent_reviewing`
  + `agent_attempts_remaining_<N>`; add `agent_reviewed`. Done.
- **Changes requested (a `CHANGES_REQUESTED` review exists):** remove
  `agent_reviewing` + `agent_attempts_remaining_<N>`; add
  `agent_changes_requested`. Done — human takeover.
- **Fixes applied (head SHA changed since the marker's base SHA, and no
  `CHANGES_REQUESTED` review):** the agent pushed its own fixes. Re-queue for a
  full re-review:
  - **N > 0 (retry):** remove `agent_attempts_remaining_<N>`, add
    `agent_attempts_remaining_<N-1>` + `ready_for_review`; remove
    `agent_reviewing`. **Update** the marker comment's base SHA to the new head
    and its conversation URL to a fresh review conversation (started now).
  - **N == 0 (final re-review):** re-queue at N=0 for a final re-review of the
    self-applied fixes — **never** leave a "request changes" state for
    self-applied fixes. If the next run finds no further SHA change and no
    approve, it escalates to give-up (§Give-up).
- **Failure (ERROR / STUCK / stalled, no review and no new commits):**
  - **N > 0 (retry):** remove `agent_attempts_remaining_<N>`, add
    `agent_attempts_remaining_<N-1>` + `ready_for_review`; remove
    `agent_reviewing`. **Update** the marker to point at a fresh review
    conversation (started now). Spawn a fire-and-forget check-up conversation
    to summarize the failure.
  - **N == 0 (give-up):** remove `agent_reviewing` +
    `agent_attempts_remaining_<N>`; add `agent_changes_requested`; post a
    "gave up after 3 attempts" comment. Human takeover.

> **Key rule:** when the agent applied its own fixes (head SHA changed) and did
> **not** leave a `CHANGES_REQUESTED` review, the script does **not** mark the
> PR as "changes requested" — it re-queues for a full re-review. The agent
> only submits a `CHANGES_REQUESTED` review when the fixes are **not**
> straightforward, signalling that a human must take over.

## Marker comment format

```
<!-- openhands-automation: pr-review -->
An Agent is reviewing this PR in conversation: <CONVERSATION_URL>
Base SHA: <HEAD_SHA>
```

The hidden HTML marker lets the script find its own comment (the latest one)
reliably. On retry the script **edits** the existing comment (same comment id)
to point at the new conversation and new base SHA, so there is always exactly
one canonical marker per PR.

## Conversation-id validation

The conversation id is extracted from `<CONVERSATION_URL>` with a strict UUID
regex. A tampered comment that doesn't match is skipped — an untrusted string
must never reach a prompt or a URL parameter.

## Review procedure (LLM)

The review conversation does the following, in order:

1. **Invoke the `code-review` skill** and follow its review framework
   (data-structure analysis, complexity/good-taste, pragmatic problem
   analysis, breaking-change risk, security/correctness, testing gaps, risk
   assessment). The repo is already checked out at the PR head; read files
   directly to ground line-number references.

2. **Cross-check against the original issue.** The issue URL is passed into
   the prompt. Read the issue body and confirm the PR actually accomplishes
   what was requested — not just that the code is clean, but that it fulfills
   the acceptance criteria and intent. A PR that is well-written but does not
   solve the issue is a failing review.

3. **Post a findings comment** on the PR (always, regardless of outcome),
   using the code-review skill's output format (Taste Rating, Critical Issues,
   Improvement Opportunities, Testing Gaps, Risk Assessment, Verdict). End
   with the mandatory self-improvement message block.

4. **Decide and act:**
   - **No critical issues (or all issues are straightforward to fix):** apply
     the fixes directly in the workspace, commit, and push to the PR branch.
     Do **not** submit a `CHANGES_REQUESTED` review. Do **not** submit an
     `APPROVE` review either — the re-review on the next run will decide. The
     pushed commits trigger a full re-review via the countdown.
   - **Critical issues that are NOT straightforward to fix:** submit a
     `CHANGES_REQUESTED` review on GitHub (event = `REQUEST_CHANGES`, with the
     review body summarizing the findings). This signals human takeover.
   - **No issues at all (clean PR, fulfills the issue):** submit an `APPROVE`
     review on GitHub (event = `APPROVE`, with the review body). Done.

> The `code-review` skill says "DO NOT MODIFY THE CODE" — this automation
> **overrides** that for the auto-fix path. The skill's *methodology* (the
> review framework, risk assessment, output format) is still followed
> exactly; only the "do not modify" constraint is relaxed so the agent can
> apply straightforward fixes and push them.

---
This skill is located at `.agents/skills/pr-review`. Any files it references
(e.g. under `scripts/`, `references/`, `assets/`) are relative to that
directory.
