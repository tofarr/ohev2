# Review Criteria -- Interview Questions

These are the criteria from the `issue-review` skill, re-expressed as interview
questions for defining an issue. An issue produced by answering these questions
is pre-aligned to pass review.

## 1. Clarity and completeness

### Summary states the problem

- "What is the current state, and what is wrong with it?"
- "Why does this need to change? Who is affected?"
- Ensure the *what* and *why* are stated, not just the *how*. A solution
  described without the underlying problem is incomplete.

### Acceptance criteria present

- "What does 'done' look like? List the specific, testable outcomes."
- "If an implementer finished this, what would you check to confirm it's
  correct?"
- "Implement X" with no criteria fails review. Push for an explicit list.

### Scope is bounded to a single change

- "Does this describe one cohesive change that could ship in one PR?"
- "Are there multiple unrelated concerns bundled together?"
- If multiple concerns surface, flag it for decomposition (see Step 4 of
  the skill procedure).

### Terms are defined

- "Are there domain terms, acronyms, or ambiguous words an implementer might
  not share?"
- "Can you define them, or link to where they're documented?"

## 2. Consistency with project invariants

### No conflict with AGENTS.md

- Read the repo's `AGENTS.md` (if present).
- "Does this change conflict with the stack, layering, REST, auth, RBAC, or
  testing rules?"
- If adding a new governed entity, confirm the four-step change is named
  (column + migration + registry + schema, per AGENTS.md section 11).

### No conflict with specs

- Check for a `specs/<name>.qnt` spec for the affected resource.
- "Does the proposed behavior require a spec update?"
- Flag behavioral changes that would need a spec update per AGENTS.md
  section 7.

### No conflict with existing API/conventions

- "Does this respect REST verb/naming conventions (AGENTS.md section 3)?"
- "Are governed-entity / column rules (section 11) respected?"
- "Are link-table rules (section 11.1) respected if this involves a join
  table?"

## 3. Implementability and dependencies

### Prerequisites resolved

- "Does this depend on other issues being done first?"
- "Are those issues closed or unblocked?"
- Open `blocked by` links fail review. If there are dependencies, create or
  link them.

### Sufficient detail to start

- "Can an implementer begin without having to ask clarifying questions?"
- "Are data shapes, field names, and flows specified?"

### Testable

- "How will this change be verified (unit / e2e / spec)?"
- "What is the observable outcome that confirms success?"

## 4. Complexity sanity-check (secondary)

### Estimated blast radius

- "What areas of the codebase are likely affected?"
- "Does this touch a governed entity, requiring a column + migration +
  registry + schema + spec change?"

### Decomposition

- "For genuinely large changes, is there a proposed breakdown or sub-issues?"
- Large-but-clear issues do NOT need refinement; only large-and-ambiguous
  ones do. Do not push decomposition on a clear, cohesive issue.
