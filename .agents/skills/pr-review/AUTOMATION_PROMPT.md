# PR Review Automation — Prompts

This file holds the prompt templates sent to the OpenHands conversations
spawned by the hourly pr-review automation (`main.py`). Keep it in sync
with `.agents/skills/pr-review/SKILL.md`.

## How these prompts are used

The automation runs hourly via cron. Each run:

1. Enumerates open PRs with the `ready_for_review` label, no
   `agent_reviewing` label, no `CHANGES_REQUESTED` reviews, and all CI checks
   passing, up to `MAX_PRS_PER_RUN` (default 3).
2. For each PR, looks for the canonical marker comment
   (`<!-- openhands-automation: pr-review -->`):
   - **No marker** → verifies CI is green, claims the PR (swaps
     `ready_for_review` → `agent_reviewing`), finds the linked issue, starts a
     review conversation with the **Review prompt** below, then posts the
     marker comment.
   - **Marker present** → validates the conversation id, queries the agent
     server for `execution_status`, and either skips (still running / not
     found) or resolves an outcome (terminal). On retry it starts a fresh
     review conversation, updates the marker, and (on failure) spawns a
     fire-and-forget **Check-up prompt** conversation.

GitHub labels + the marker comment are the **sole source of truth** — no KV
store, no external state. The script owns all label swaps and review/commit
state detection; the conversations only review / fix / summarize.

## Review prompt

```
You are reviewing PR {PR_URL} in repository {REPO}. The repository is already
cloned into your workspace, checked out at the PR head ({PR_HEAD_SHA}); its
AGENTS.md and .agents/skills/ are loaded. The review/fix budget for this PR is
N={N}.

The PR was opened to address this issue: {ISSUE_URL}
(If the issue URL is "none", no linked issue was found — review the PR on its
own merits and note that you could not cross-check against an issue.)

STEP 1 — Invoke the `code-review` skill and follow its review framework
exactly: data-structure analysis, complexity / "good taste" assessment,
pragmatic problem analysis, breaking-change risk, security/correctness,
testing gaps, dependency changes, risk and safety evaluation, and the output
format (Taste Rating, Critical Issues, Improvement Opportunities, Testing
Gaps, Risk Assessment, Verdict, Key Insight). Read files directly from the
workspace to ground any line-number references. Check the Files Changed
manifest before claiming anything is "missing".

STEP 2 — Cross-check against the original issue. Read the issue body at
{ISSUE_URL} and confirm the PR actually accomplishes what was requested — not
just that the code is clean, but that it fulfills the acceptance criteria and
intent. A well-written PR that does not solve the issue is a FAILING review.

STEP 3 — Post a findings comment on the PR using the code-review skill's
output format. This comment is ALWAYS posted, regardless of outcome. End with
the skill's mandatory self-improvement message block. Include the note:
"This review was performed by an AI agent (OpenHands) on behalf of the repo
owner."

STEP 4 — Decide and act. The `code-review` skill says "DO NOT MODIFY THE CODE"
— this automation OVERRIDES that for the auto-fix path. Your options:

  A) CLEAN PR (no issues at all, fulfills the issue):
     - Submit an APPROVE review on GitHub:
       POST /repos/{REPO}/pulls/{PR_NUMBER}/reviews
       with event=APPROVE and the review body summarizing your findings.
     - Do not push any commits.
     - Done.

  B) ISSUES ARE STRAIGHTFORWARD TO FIX (critical or improvement issues that
     you can address with confidence — clear, localized, low-risk fixes):
     - Apply the fixes directly in your workspace.
     - Commit and push to the PR branch ({PR_BRANCH}). The remote is already
       configured with your GITHUB_TOKEN.
     - Do NOT submit a CHANGES_REQUESTED review. Do NOT submit an APPROVE
       review. The pushed commits trigger a full re-review on the next hourly
       run (the countdown handles retries).
     - In your findings comment, clearly state which fixes you applied and
       why, so the re-review (and humans) can see what changed.
     - Done.

  C) ISSUES ARE NOT STRAIGHTFORWARD TO FIX (fundamental design problems,
       ambiguous requirements, large scope, or fixes you cannot make with
       confidence):
     - Submit a CHANGES_REQUESTED review on GitHub:
       POST /repos/{REPO}/pulls/{PR_NUMBER}/reviews
       with event=REQUEST_CHANGES and the review body summarizing the
       findings and why they need human attention.
     - Do not push any commits.
     - Done.

Notes:
- You have GitHub write scope for this repo (reviews, comments, commits, push).
  Use the GitHub REST API (curl) with the GITHUB_TOKEN secret.
- The PR branch is {PR_BRANCH}. To push fixes, commit and run:
  git push origin HEAD:{PR_BRANCH}
- If a referenced spec or AGENTS.md rule is ambiguous, treat that as a
  finding against the PR, not as a reason to edit the spec.
- When N reaches 0, the next failure that you cannot fix will escalate to a
  human (the script applies `agent_changes_requested`). The countdown is the
  sole termination guarantee.
```

## Check-up prompt

```
It looks like a conversation was created to review PR {PR_URL}, but it has
been running for quite some time. Please examine conversation
{CONVERSATION_ID} and its events with a view to figuring out what happened. If
there was an error, please try to summarize a reason and post a comment back
to the PR explaining it.

The conversation events are available via the agent server REST API:
  GET {AGENT_SERVER_URL}/api/conversations/{CONVERSATION_ID}/events/search
Authenticate with the X-Session-API-Key header (the SESSION_API_KEY env var).
Use sort_order=TIMESTAMP_DESC to read the most recent events first. Do not
modify the review conversation — only read it and post your summary comment to
the PR.
```
