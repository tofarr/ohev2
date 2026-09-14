# PR Review Automation — Plan

A custom-script automation that reviews PRs which are ready for review, have
no outstanding "request changes" reviews, and have all CI checks passing.
Each hour it scans for eligible PRs, starts a review conversation (using the
`code-review` skill, cross-checked against the original issue) for any that
have none yet, and checks up on conversations that appear to have stalled —
using a label-based countdown to bound review/fix retries.

GitHub labels + the marker comment are the **sole source of truth**. There is
**no KV store**, so multiple automation servers can track the same repo
independently without shared-state races. Conversation liveness is determined
by querying the agent server (not by a stored timestamp).

---

## 1. Trigger

Cron, hourly: `0 * * * *` (UTC), mirroring the issue-review and
issue-implement automations.

## 2. Custom script (no LLM for orchestration)

This is a **custom Python script** (`main.py`, entrypoint `python3 main.py`),
not a prompt/plugin preset. The orchestration is deterministic — GitHub REST +
agent-server REST. Only the two *spawned* conversations (review and
check-up) use an LLM. Uses the standard no-LLM helpers `get_secret` /
`fire_callback` from the automation skill, and the same GitHub/agent-server
helpers as the issue-implement `main.py`.

## 3. Labels (state machine)

| Label | Meaning |
|---|---|
| `ready_for_review` | (from issue-implement) PR eligible for review. Consumed read-only as the queue signal; swapped to `agent_reviewing` during review. |
| `agent_reviewing` | In-flight claim token. |
| `agent_attempts_remaining_<N>` (N >= 0) | Review/fix budget remaining on the PR. **No bare `agent_attempts_remaining`** — absence means the budget is exhausted (N = 0). Initial value on first dispatch: `agent_attempts_remaining_3`. |
| `agent_reviewed` | Done — PR approved by the agent. |
| `agent_changes_requested` | Done — agent requested changes (exhausted fix budget or non-straightforward issues). Human takeover. |

`ready_for_review` + absence of `agent_reviewing` = "in the scan set" (subject
to the CI and review-state filters in §4).

> **Note:** the issue-implement automation owns `ready_for_review` (it is
> applied to PRs by the implementation agent). This automation consumes it as
> the review-queue signal and swaps it to `agent_reviewing` during review.
> When review finishes (approve / changes-requested / give-up), the label is
> either left off (terminal states) or re-added (retry re-queue).

## 4. Eligibility filter (per run)

The script fetches **two** lists of PRs each run:

1. **`ready_for_review` PRs** — eligible for fresh start. Dropped if any hold:
   - `agent_reviewing` label (already in flight — should not happen since the
     label was removed at claim time, but guarded defensively).
   - A `CHANGES_REQUESTED` review from anyone (GitHub
     `GET /repos/{repo}/pulls/{n}/reviews`, filtered to `state ==
     "CHANGES_REQUESTED"`). A changes-requested review means the author must
     push new commits before re-review.
   - Combined CI status is not `success` (§5). A PR with pending or failing
     checks is skipped this run — it will be picked up next hour when checks
     finish.

2. **`agent_reviewing` PRs** — in-flight reviews. These are processed through
   `check_up` (resolve outcome) or `rescue_stale` (re-queue if stalled). This
   list is critical: once a PR is claimed (`ready_for_review` removed,
   `agent_reviewing` added), it is **only** visible via this second list.
   Without it, the PR would be stuck in `agent_reviewing` forever.

Cap: **at most 3 PRs acted on per run** (`MAX_PRS_PER_RUN`, default 3)
across both branches (check-up + fresh-start), to bound token/sandbox cost.

## 5. CI check (combined status)

For a given PR head SHA, the script checks whether all CI checks pass:

1. `GET /repos/{repo}/commits/{sha}/check-runs?per_page=100` — every
   `check_run` must have `status == "completed"` and `conclusion == "success"`
   (or `neutral`, which GitHub treats as non-blocking). A check that is
   `completed` with `conclusion` in `{failure, timed_out, cancelled, action_required}`
   means CI is failing.
2. `GET /repos/{repo}/commits/{sha}/statuses?per_page=100` — every `status`
   must have `state` in `{success, neutral}`. A `pending` or `failure` state
   means CI is not green.

A PR is "CI green" only when both endpoints return no failing/pending entries.
If either endpoint is empty (no checks configured), the PR is treated as green
(a repo may not have CI). The script is best-effort: if an endpoint 404s, the
PR is treated as green (the commit may predate check-runs).

## 6. Marker comment (canonical, owned by the script)

When the script starts a review conversation it **immediately** posts a
canonical marker comment so the next run sees it (no race with a slow-to-start
agent). Format:

```
<!-- openhands-automation: pr-review -->
An Agent is reviewing this PR in conversation: <CONVERSATION_URL>
Base SHA: <HEAD_SHA>
```

- The hidden HTML marker (`<!-- openhands-automation: pr-review -->`) lets the
  script reliably find *its own* comment (the latest one) even when humans or
  other agents add comments.
- `<CONVERSATION_URL>` is the full agent-server conversation URL. The
  conversation id is extracted with a strict regex (see §11).
- `<HEAD_SHA>` is the PR head SHA at the time the review started. On retry
  (after the agent pushed fixes), the script **updates** the marker to record
  the *new* head SHA, so the next verdict can detect whether the agent pushed
  again.
- On a retry that spawns a **new** review conversation, the script **edits**
  the existing marker comment (same comment id) rather than posting a
  duplicate, so there is always exactly one canonical marker.

## 7. Per-PR flow

For each eligible PR (up to the cap):

### 7.1 No marker comment present → fresh start

1. **Verify CI is green** (§5). If not green, skip the PR this run.
2. **Claim** the PR: remove `ready_for_review`; add `agent_reviewing`. **Leave**
   any `agent_attempts_remaining_<N>`.
3. Set `agent_attempts_remaining_3` (only if no
   `agent_attempts_remaining_<N>` label is already present — a human may have
   pre-set a different budget).
4. **Find the linked issue** (§8). Pass its URL (or "none") into the prompt.
5. Start a review conversation: repo cloned at the PR head (§9), with the
   review prompt (§10.1). The `GITHUB_TOKEN` is passed as a conversation
   secret so the agent can submit reviews, comment, and push fixes.
6. Immediately post the marker comment (§6) with the returned conversation id
   and the PR head SHA.
7. Done for this PR this run.

### 7.2 Marker comment present → check up on the existing conversation

1. Extract and **validate** the conversation id from the marker (§11). If
   invalid → skip the PR this run.
2. Query the agent server: `GET /api/conversations/{id}`. If 404 → **skip**
   this PR this run (the conversation may have been deleted, or this server
   doesn't host it). Do not decrement, do not start a new one — just skip.
3. Read `execution_status`:
   - **Terminal** (`FINISHED` / `ERROR` / `STUCK`) → resolve outcome (§7.3).
   - **Non-terminal but stalled** (`RUNNING`/`PAUSED`/
     `WAITING_FOR_CONFIRMATION`/`IDLE`) and no new events for >
     `STALE_THRESHOLD` (default 20 min) → resolve outcome as a failure.
     "Last event timestamp" is read from
     `GET /api/conversations/{id}/events/search?limit=1&sort_order=TIMESTAMP_DESC`.
   - **Actively running** (events within `STALE_THRESHOLD`) → skip; let it work.
   - **`DELETING`** → skip.

### 7.3 Verdict → script decides from GitHub state (no LLM cooperation needed)

The **script** decides the outcome deterministically from the PR's GitHub
state after the conversation finishes — the check-up conversation is spawned
purely to summarize failures (fire-and-forget; the script does not wait for
it).

Parse `agent_attempts_remaining_<N>` (minimum if multiple; default 0). Then:

- **Approved:** an `APPROVE` review exists on the PR
  (`GET /repos/{repo}/pulls/{n}/reviews`, any with `state == "APPROVED"`).
  → remove `agent_reviewing` + `agent_attempts_remaining_<N>`; add
  `agent_reviewed`. Done.
- **Changes requested:** a `CHANGES_REQUESTED` review exists. → remove
  `agent_reviewing` + `agent_attempts_remaining_<N>`; add
  `agent_changes_requested`. Done — human takeover.
- **Fixes applied (head SHA changed since marker base SHA, no
  CHANGES_REQUESTED review):** the agent pushed its own fixes. Re-queue:
  - **N > 0:** remove `agent_attempts_remaining_<N>`, add
    `agent_attempts_remaining_<N-1>` + `ready_for_review`; remove
    `agent_reviewing`. Update the marker's base SHA to the new head + start a
    fresh review conversation, updating the marker's conversation URL.
  - **N == 0 (final re-review):** re-queue at N=0 for a final re-review of
    the self-applied fixes — **never** leave a "request changes" state for
    self-applied fixes. If the next run finds no further SHA change and no
    approve, it escalates to give-up (§7.4).
- **Failure (ERROR / STUCK / stalled, no review and no new commits):**
  - **N > 0:** remove `agent_attempts_remaining_<N>`, add
    `agent_attempts_remaining_<N-1>` + `ready_for_review`; remove
    `agent_reviewing`. Start a fresh review conversation; update the marker.
    Spawn a check-up conversation (§10.2, fire-and-forget) to summarize.
  - **N == 0:** give-up (§7.4).

> **Key rule:** when the agent applied its own fixes (head SHA changed) and
> did **not** leave a `CHANGES_REQUESTED` review, the script re-queues for a
> full re-review — it does **not** mark the PR as "changes requested". This
> matches the user's requirement: "When the agent applied its own fixes, it
> should not leave a 'request changes' state."

### 7.4 Terminal at countdown 0 → stop retrying

1. Remove `agent_reviewing` + `agent_attempts_remaining_<N>`.
2. Add `agent_changes_requested`.
3. Post a "gave up after 3 attempts" comment to the PR, summarizing that the
   automation exhausted its review/fix budget and a human should take over.

> The PR can be re-queued later by a human removing
> `agent_changes_requested` and re-adding `ready_for_review` (and optionally
> bumping the attempts label).

## 8. Linked-issue detection

The script finds the issue the PR addresses via:

1. **PR body parsing:** `Fixes #N` / `Closes #N` / `Resolves #N` (case-
   insensitive) in the PR body. The first match wins.
2. **Timeline `cross-referenced` events:**
   `GET /repos/{repo}/issues/{n}/timeline` — events where `event ==
   "cross-referenced"` and the source issue has a `number` (an issue, not a
   PR). This catches PRs that link an issue without a `Fixes` keyword.

If no issue is found, the prompt receives `ISSUE_URL=none` and the reviewer
is told to review the PR on its own merits (noting the missing cross-check).

## 9. Repo checkout at the PR head

The script clones the repo (shallow, branch `main`) and then fetches + checks
out the PR head:

```
git clone --depth 1 --branch main <url> <dest>
cd <dest>
git fetch origin pull/{PR_NUMBER}/head:pr-head --depth 50
git checkout pr-head
```

This gives the review conversation a workspace at the exact PR head SHA, so
file reads and line-number references are grounded. The `GITHUB_TOKEN` is
embedded in the remote URL so the agent can push fixes to the PR branch.

## 10. Prompts

### 10.1 Review prompt

Sent to the review conversation (repo at the PR head). See
`AUTOMATION_PROMPT.md` for the full template. Placeholders:
`{PR_URL}`, `{REPO}`, `{PR_HEAD_SHA}`, `{PR_BRANCH}`, `{PR_NUMBER}`,
`{ISSUE_URL}`, `{N}`.

The prompt instructs the agent to:
1. Invoke the `code-review` skill and follow its review framework.
2. Cross-check the PR against the original issue.
3. Post a findings comment (always).
4. Decide: APPROVE (clean PR), auto-fix + push (straightforward issues), or
   CHANGES_REQUESTED (non-straightforward issues).

The `code-review` skill's "DO NOT MODIFY THE CODE" constraint is **overridden**
for the auto-fix path — the skill's *methodology* is followed, but the agent
may apply straightforward fixes and push them.

### 10.2 Check-up prompt

Sent to the check-up conversation (fire-and-forget, on failure). See
`AUTOMATION_PROMPT.md`. The conversation reads the failed review
conversation's events via the agent-server REST API and posts a summary
comment to the PR.

## 11. conversation_id validation

Extracted from the marker comment's `<CONVERSATION_URL>` with a strict regex:
`/api/conversations/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})`.
If the URL doesn't match (or the id fails `uuid.UUID` parsing), the PR is
**skipped** this run — an untrusted/tampered comment must never inject an
arbitrary string into a URL parameter.

## 12. Multi-server independence (no KV store)

State lives entirely in GitHub (labels + the marker comment) and is
re-derived each run from the agent server. Therefore:

- Multiple automation servers can run the same cron against the same repo
  without a shared KV store.
- The main race is two servers dispatching a fresh review conversation for the
  same PR in the same tick. Mitigation: the marker comment is posted
  **immediately** after a conversation starts, and the eligibility check reads
  comments before acting. Best-effort (two servers could both read "no marker"
  within the same minute). Acceptable given the per-run cap of 3 and hourly
  cadence; a duplicate conversation is non-fatal (the check-up branch picks
  the latest marker).

## 13. Files (mirrors issue-implement layout)

```
.agents/skills/pr-review/
  plan.md                 # this file
  SKILL.md                # skill doc (labels + state machine)
  AUTOMATION_PROMPT.md    # fenced prompt templates (review + check-up)
  main.py                 # custom dispatch script
  deploy.sh               # creates labels, tars, uploads, creates cron automation
```

## 14. Config (env, defaults)

| Env | Default | Purpose |
|---|---|---|
| `OHE_REPO` | `tofarr/ohev2` | target repo |
| `MAX_PRS_PER_RUN` | `3` | per-run cap across both branches |
| `STALE_THRESHOLD` | `1200` (20 min) | no-new-events → stalled |
| `CONV_TIMEOUT` | `600` | per-conversation timeout (s) |
| `OHE_AGENT_PROFILE` | `default` | agent profile name |
| `OHE_WORKSPACE_ROOT` | `/tmp/pr-review-workspaces` | clone root |

Injected at runtime by the automation service: `AGENT_SERVER_URL`,
`SESSION_API_KEY`, `AUTOMATION_CALLBACK_URL`,
`AUTOMATION_CALLBACK_API_KEY`, `AUTOMATION_RUN_ID`. `GITHUB_TOKEN` is fetched
via `get_secret("GITHUB_TOKEN")`.

## 15. Labels to create (deploy.sh)

| Label | Color | Description |
|---|---|---|
| `agent_reviewing` | `F59E0B` | Agent is reviewing this PR |
| `agent_attempts_remaining_0` | `EF4444` | Review budget exhausted |
| `agent_attempts_remaining_1` | `F59E0B` | 1 review/fix attempt remaining |
| `agent_attempts_remaining_2` | `F59E0B` | 2 review/fix attempts remaining |
| `agent_attempts_remaining_3` | `3B82F6` | 3 review/fix attempts remaining (initial) |
| `agent_reviewed` | `10B981` | PR approved by the agent |
| `agent_changes_requested` | `EF4444` | Agent requested changes; human takeover |

(`ready_for_review` is owned by the issue-implement automation and not
recreated here. `agent_reviewing` is shared with the issue-review automation —
it is created here only if it doesn't already exist.)

## 16. Resolved decisions

1. **`agent_attempts_remaining_3` belongs on the PR.** The script applies it
   to the PR on first dispatch (§7.1). The review prompt does not touch
   labels.
2. **Verdict from GitHub state, not LLM cooperation.** The script detects
   APPROVE / CHANGES_REQUESTED reviews and head-SHA changes via the GitHub
   API. No LLM cooperation needed for the label swap. The check-up
   conversation is fire-and-forget summarization.
3. **Stale threshold = 20 minutes** (1200 s).
4. **Auto-fix does not leave "request changes".** When the agent pushes its
   own fixes (head SHA changed) and does not submit a CHANGES_REQUESTED
   review, the script re-queues for a full re-review — it does not mark the
   PR as "changes requested". This matches the user's requirement.
5. **CI must be green before review starts.** A PR with pending or failing
   checks is skipped (not claimed) so the review runs against a PR whose
   checks have settled.
6. **Issue cross-check is part of the review.** The linked issue URL is
   passed into the prompt; the reviewer confirms the PR fulfills the issue's
   acceptance criteria. A clean PR that does not solve the issue is a failing
   review.
7. **`agent_attempts_remaining_<N>` label name.** The user specified
   `agent_attempts_remaining_<N>` (distinct from the implementer's
   `agent_remaining_attempts_<N>`) so the two automations' budgets do not
   collide on the same issue/PR.
