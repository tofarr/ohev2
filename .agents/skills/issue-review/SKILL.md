# Issue Review Checklist

A deterministic checklist for reviewing a GitHub issue before approving it for
agent implementation, plus the label-based state machine that coordinates
review across hourly automation runs. GitHub labels are the **sole source of
truth** -- there is no KV store or external state.

## When to use

Invoke this skill when asked to review a GitHub issue for readiness, clarity,
and implementability -- specifically the issue-review automation run, or when a
human asks "is this issue ready to implement?".

This skill reviews issues only; it does not touch PRs or code. When a review
fails, it posts findings and escalates to a human -- it does not attempt to
rewrite the issue body. Refining an issue is an interactive, human-in-the-loop
process handled by the `refine-issue` skill.

## Labels (state machine)

| Label | Meaning |
|---|---|
| `ready_for_agent_review` | Pending review -- eligible for the next run. |
| `agent_reviewing` | In-flight claim token -- a conversation is reviewing this. Persists through crashes. |
| `agent_approved` | Done -- approved for implementation. |
| `needs_refinement` | Done -- escalate to a human (use the `refine-issue` skill interactively). |

### Dispatch-side transitions (deterministic, script -- not the LLM)

1. **Enumerate** issues with `ready_for_agent_review` AND NOT `agent_reviewing`, up to `max_issues_per_run` (default 5).
2. **Claim** each: remove `ready_for_agent_review`, `agent_approved`, `needs_refinement`; add `agent_reviewing`.
3. **Start** one conversation per claimed issue, passing the issue URL.
4. **Rescue** (each run, after enumeration): issues with `agent_reviewing` AND `updated:<2h-ago` (stale -- conversation died) -> remove `agent_reviewing`, re-add `ready_for_agent_review`.

### Conversation-side transitions (LLM -- see prompt)

Always post a findings comment first, then:

| Outcome | Label changes |
|---|---|
| **Pass** | remove `agent_reviewing`; add `agent_approved`. |
| **Fail** | remove `agent_reviewing`; add `needs_refinement`. |

A failed review is terminal from the automation's perspective -- the issue is
escalated to a human, who runs the `refine-issue` skill to address the findings
interactively and then re-applies `ready_for_agent_review` to re-queue.

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
- **`needs_refinement`** -- one or more criteria fail. Post the findings
  comment and apply the `needs_refinement` label. The findings comment is the
  hand-off: it lists every failing criterion with enough detail for the
  `refine-issue` skill (or a human) to address each one interactively.

## Output templates

### Findings comment (always posted)

```markdown
## Agent review findings

**Verdict:** {approved | needs_refinement}

### Findings
- [PASS/FAIL] **[criterion name]**: [detail, with a quote or reference to the issue text]
- ...

### Next steps
1. [if failing: concrete action to make this implementable; if passing: "Ready for implementation."]
```

When the verdict is `needs_refinement`, the "Next steps" section must list each
failing criterion with a specific question or gap to resolve. This is what the
`refine-issue` skill walks through with the author interactively.
