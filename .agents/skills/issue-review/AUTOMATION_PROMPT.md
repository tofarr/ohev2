# Issue Review Automation -- Prompt

This file holds the prompt sent to the OpenHands conversation spawned for each
issue claimed by the hourly review automation. Keep it in sync with the review
skill in `.agents/skills/issue-review/SKILL.md`.

## How this prompt is used

The automation runs hourly via cron. Each run:

1. Enumerates issues with `ready_for_agent_review` AND NOT `agent_reviewing`, up
   to `max_issues_per_run` (default 5).
2. Claims each (removes `ready_for_agent_review` + `agent_approved` +
   `needs_refinement`; adds `agent_reviewing`).
3. Starts one OpenHands conversation per claimed issue, passing the issue URL
   into the prompt below. The repo is cloned so `AGENTS.md` and
   `.agents/skills/` load automatically.
4. After dispatch, rescues stale claims: issues with `agent_reviewing` AND
   `updated:<2h-ago` get `agent_reviewing` removed and `ready_for_agent_review`
   re-added.

GitHub labels are the **sole source of truth** -- no KV store, no external
state.

## The prompt

```
You are reviewing GitHub issue {ISSUE_URL} to decide whether it is ready for an
agent to implement. This repo is already cloned into your workspace; its
AGENTS.md and .agents/skills/ are loaded.

STEP 1 -- Invoke the `issue-review` skill and follow its review procedure
exactly. It gives the deterministic checklist (clarity and completeness,
consistency with project invariants, implementability and dependencies, and a
secondary complexity sanity-check). Record a PASS/FAIL finding for EVERY
criterion. Do not invent new criteria; do not skip criteria. Complexity alone
is NEVER a refinement trigger -- it is informational.

STEP 2 -- Post a findings comment on the issue using the skill's findings
template (Verdict / Findings / Next steps). Quote the specific issue text for
each FAIL finding. This comment is ALWAYS posted, regardless of outcome.

STEP 3 -- Apply labels based on the outcome:

  A) ALL criteria pass (approved):
     - Remove the `agent_reviewing` label.
     - Add the `agent_approved` label.

  B) One or more criteria fail:
     - Remove the `agent_reviewing` label.
     - Add the `needs_refinement` label.

     Do NOT rewrite the issue body, create sub-issues, or attempt to fix the
     findings yourself. A failed review is terminal from the automation's
     perspective. The findings comment is the hand-off: the author runs the
     `refine-issue` skill interactively to address each finding, then
     re-applies `ready_for_agent_review` to re-queue.

STEP 4 -- Stop. Do not implement the issue, open a PR, or run tests. Your only
job is classification.

Notes:
- You have GitHub issue write scope for this repo only (labels, comments). Do
  not touch the issue body, PRs, code, or settings.
- If a referenced spec or AGENTS.md rule is ambiguous, treat that as a finding
  against the issue ("cannot confirm consistency against spec X"), not as a
  reason to edit the spec.
```
