# Issue Review Automation -- Prompt

This file holds the prompt sent to the OpenHands conversation spawned for each
issue claimed by the hourly review automation. Keep it in sync with the review
skill in `.agents/skills/issue-review/SKILL.md`.

## How this prompt is used

The automation runs hourly via cron. Each run:

1. Enumerates issues with `ready_for_agent_review` AND NOT `agent_reviewing`, up
   to `max_issues_per_run` (default 5).
2. Claims each (removes `ready_for_agent_review` + `agent_approved` +
   `needs_refinement`; adds `agent_reviewing`; leaves `auto_refine_<N>`).
3. Parses N from any `auto_refine_<N>` label (minimum if multiple; default 0).
4. Starts one OpenHands conversation per claimed issue, passing the issue URL
   and N into the prompt below. The repo is cloned so `AGENTS.md` and
   `.agents/skills/` load automatically.
5. After dispatch, rescues stale claims: issues with `agent_reviewing` AND
   `updated:<2h-ago` get `agent_reviewing` removed and `ready_for_agent_review`
   re-added (N preserved via the untouched `auto_refine_<N>`).

GitHub labels are the **sole source of truth** -- no KV store, no external
state.

## The prompt

```
You are reviewing GitHub issue {ISSUE_URL} to decide whether it is ready for an
agent to implement. This repo is already cloned into your workspace; its
AGENTS.md and .agents/skills/ are loaded. The refinement budget for this issue
is N={N}.

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
     - Remove any `auto_refine_<N>` label if present.
     - Add the `agent_approved` label.

  B) One or more criteria fail AND N <= 0 (no refinement budget):
     - Remove the `agent_reviewing` label.
     - Remove any `auto_refine_<N>` label if present.
     - Add the `needs_refinement` label.

  C) One or more criteria fail AND N > 0 (refinement budget remains):
     - Read ALL comments on the issue (prior agent findings + human comments).
     - Attempt to fix the found problems:
       * Body update -- REWRITE the issue body to address the findings: add
         missing acceptance criteria, clarify ambiguous terms, resolve
         inconsistencies. You may REPLACE content that is no longer relevant or
         where a decision has changed -- do not just append notes on top of
         notes, or repeated refinement will bloat the issue into incoherence.
         The goal is a clean, coherent issue body that a fresh reader can
         understand without reading the comment history. Preserve the original
         intent and any still-relevant context; replace only what is stale or
         superseded. The findings comments remain the auditable record of what
         each review concluded.
       * Split -- if scope is genuinely too large for one PR, create 2-6
         sub-issues. Link them with `blocks` / `is blocked by` issue links.
         Each sub-issue inherits `auto_refine_{N-1}` + `ready_for_agent_review`
         (the counter is NEVER reset). Each sub-issue must itself pass the
         clarity criteria (summary + acceptance criteria).
       * If you cannot produce at least 2 sensible sub-issues, do a body update
         instead. Do not force a bad split.
     - Remove the `agent_reviewing` label.
     - Remove the current `auto_refine_{N}` label.
     - Add `auto_refine_{N-1}` and `ready_for_agent_review` so the refined
       issue is re-reviewed on the next hourly run.

STEP 4 -- Stop. Do not implement the issue, open a PR, or run tests. Your only
job is classification + (optionally) refinement.

Notes:
- You have GitHub issue write scope for this repo only (labels, comments, body
  edits, sub-issues, issue links). Do not touch PRs, code, or settings.
- If a referenced spec or AGENTS.md rule is ambiguous, treat that as a finding
  against the issue ("cannot confirm consistency against spec X"), not as a
  reason to edit the spec.
- When N reaches 0, the next failure will escalate to `needs_refinement` for a
  human. The countdown is the sole termination guarantee.
```
