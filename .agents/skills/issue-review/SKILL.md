# Issue Review Checklist

A deterministic checklist for reviewing a GitHub issue before approving it for
agent implementation, plus the label-based state machine that coordinates
review across hourly automation runs. GitHub labels are the **sole source of
truth** -- there is no KV store or external state.

## When to use

Invoke this skill when asked to review a GitHub issue for readiness, clarity,
and implementability -- specifically the issue-review automation run, or when a
human asks "is this issue ready to implement?".

## Labels (state machine)

| Label | Meaning |
|---|---|
| `ready_for_agent_review` | Pending review -- eligible for the next run. |
| `agent_reviewing` | In-flight claim token -- a conversation is reviewing this. Persists through crashes. |
| `agent_approved` | Done -- approved for implementation. |
| `needs_refinement` | Done -- escalate to a human. |
| `auto_refine_<N>` (N >= 1) | Refinement budget remaining. Decremented on each failed review. **No bare `auto_refine`** -- absence of an `auto_refine_<N>` label means N = 0 (single iteration: no fixes, comment + final label only). |

### Dispatch-side transitions (deterministic, script -- not the LLM)

1. **Enumerate** issues with `ready_for_agent_review` AND NOT `agent_reviewing`, up to `max_issues_per_run` (default 5).
2. **Claim** each: remove `ready_for_agent_review`, `agent_approved`, `needs_refinement`; add `agent_reviewing`. **Leave** any `auto_refine_<N>`. Parse N (minimum if multiple present; default 0 if none).
3. **Start** one conversation per claimed issue, passing the issue URL + N.
4. **Rescue** (each run, after enumeration): issues with `agent_reviewing` AND `updated:<2h-ago` (stale -- conversation died) -> remove `agent_reviewing`, re-add `ready_for_agent_review`. N is preserved because `auto_refine_<N>` was never removed at claim time.

### Conversation-side transitions (LLM -- see prompt)

Always post a findings comment first, then:

| Outcome | Label changes |
|---|---|
| **Pass** | remove `agent_reviewing` + `auto_refine_<N>`; add `agent_approved`. |
| **Fail, N <= 0** | remove `agent_reviewing` + `auto_refine_<N>`; add `needs_refinement`. |
| **Fail, N > 0** | **refine** (see below), then: remove `agent_reviewing` + `auto_refine_<N>`; add `auto_refine_<N-1>` + `ready_for_agent_review`. |

### Refine step (N > 0, fail)

The refine step **reads all comments** (prior findings + human comments) and
**attempts to fix the found problems**, then re-queues at N-1. Fixes may be:

- **Body update** -- rewrite the issue body to address the findings: add
  missing acceptance criteria, clarify ambiguous terms, resolve inconsistencies.
  You may **replace** content that is no longer relevant or where a decision
  has changed -- do not just accumulate append-only notes, or repeated
  refinement will bloat the issue into incoherence. The goal is a clean,
  coherent issue body that a fresh reader can understand without reading the
  comment history. Preserve the original intent and any still-relevant context;
  replace only what is stale or superseded.
- **Split** -- if scope is genuinely too large for one PR, create 2-6
  sub-issues. Sub-issues **inherit `auto_refine_<N-1>` + `ready_for_agent_review`**
  (the counter is never reset) and are linked with `blocks` / `is blocked by`
  issue links.

If the issue cannot be cleanly decomposed (fewer than 2 sensible sub-issues, or
a sub-issue that itself fails clarity), fall through to the **body-update** path
rather than forcing a bad split. If even a body update can't address the
findings, re-queue anyway at N-1 -- the countdown ensures eventual escalation.

> **Note:** This refine behavior is intentionally experimental. Allowing the
> agent to rewrite issue bodies (rather than append-only) risks losing context
> if the agent makes poor edits. The findings comments remain the auditable
> record of what each review concluded, so the history is never truly lost --
> but if a body rewrite goes wrong, a human may need to restore from the issue
> edit history. The countdown bounds how many times this can happen before
> escalation.

## Review procedure

Read the issue body, comments, and any linked issues/PRs. Evaluate the issue
against the four categories below. Record a finding for **every** failing
criterion -- an issue is approved only if **all** criteria pass.

### 1. Clarity and completeness

- [ ] **Summary states the problem** -- the *what* and *why* are stated, not just
  the *how*. A solution described without the underlying problem is incomplete.
- [ ] **Acceptance criteria present** -- there is an explicit, testable list of
  what "done" means. "Implement X" with no criteria fails this check.
- [ ] **Scope is bounded to a single change** -- the issue describes one
  cohesive change that could ship in one PR. Multiple unrelated concerns bundled
  together fails this check (suggest splitting).
- [ ] **Terms are defined** -- domain terms, acronyms, and ambiguous words are
  defined or linked. Undefined jargon the implementer may not share fails this
  check.

### 2. Consistency with project invariants

- [ ] **No conflict with `AGENTS.md`** -- the issue does not contradict the
  stack, layering, REST, auth, RBAC, or testing rules in `AGENTS.md`.
- [ ] **No conflict with specs** -- if the affected resource has a
  `specs/<name>.qnt` spec, the proposed behavior is consistent with it. Flag any
  behavioral change that would require a spec update (per AGENTS.md section 7).
- [ ] **No conflict with existing API/conventions** -- REST verb/naming
  (AGENTS.md section 3), governed-entity/column rules (section 11), or
  link-table rules (section 11.1) are respected. A new governed entity must
  name the four-step change.

### 3. Implementability and dependencies

- [ ] **Prerequisites resolved** -- issues this depends on are closed or
  otherwise unblocked. Open `blocked by` links fail this check.
- [ ] **Sufficient detail to start** -- an implementer can begin without first
  having to ask clarifying questions. Missing data shapes, field names, or
  flows fail this check.
- [ ] **Testable** -- it is clear how to verify the change (unit/e2e/spec). Issues
  with no verifiable outcome fail this check.

### 4. Complexity sanity-check (secondary, never the sole trigger)

- [ ] **Estimated blast radius stated or estimable** -- the issue indicates the
  likely affected areas (e.g. "adds a new governed entity -> column + migration +
  registry + schema + spec"). This is informational, **not** a refinement
  trigger on its own.
- [ ] **If large, a decomposition is suggested** -- for genuinely large changes,
  the issue proposes a breakdown or sub-issues. Large-but-clear issues do **not**
  need refinement; only large-and-ambiguous ones do.

## Classification

After evaluating all criteria, classify the issue:

- **`agent_approved`** -- every criterion passes.
- **`needs_refinement`** (N <= 0) -- one or more criteria fail and no refinement
  budget remains (or was never set). Post the findings comment and apply the
  `needs_refinement` label.
- **Refine then re-queue** (N > 0) -- one or more criteria fail and refinement
  budget remains. Post the findings comment, then perform the refine step
  (body update and/or split), then re-queue at N-1.

## Output templates

### Findings comment (always posted)

```markdown
## Agent review findings

**Verdict:** {approved | needs_refinement | refine_attempted (N -> N-1)}

### Findings
- [PASS/FAIL] **[criterion name]**: [detail, with a quote or reference to the issue text]
- ...

### Next steps
1. [if failing: concrete action to make this implementable; if passing: "Ready for implementation."]
```

### Body-edit rules (refine step)

- Rewrite the issue body to produce a clean, coherent issue that a fresh reader
  can understand without reading the comment history.
- You may **replace** content that is no longer relevant or where a decision has
  changed -- do not just append notes on top of notes, or repeated refinement
  will bloat the issue into incoherence.
- Preserve the original intent and any still-relevant context; replace only what
  is stale or superseded.
- The findings comments (posted every review) remain the auditable record of
  what each review concluded. The issue edit history also retains prior body
  versions, so a human can restore if a rewrite goes wrong.
- Keep sub-issue granularity reasonable: target 1-6 sub-issues; if you cannot
  produce at least 2, do not split -- do a body update instead.
- Each sub-issue must itself pass the clarity criteria (summary + acceptance
  criteria) so the next run can approve it.
- Sub-issues inherit `auto_refine_<N-1>` + `ready_for_agent_review` -- the
  counter is **never reset**.
