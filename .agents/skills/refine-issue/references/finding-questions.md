# Finding Questions -- Interactive Refinement

For each type of review finding (failing criterion), the question to ask the
user and the edit to propose. These mirror the `issue-review` checklist so
every failing criterion has a clear path to resolution.

## 1. Clarity and completeness

### Summary does not state the problem

**Finding:** the issue describes a solution but not the underlying problem.

**Ask:**
- "What is the current state, and what is wrong with it?"
- "Why does this need to change? Who is affected?"

**Proposed edit:** add a `## Summary` section (or expand the existing one)
stating the *what* and *why* before the *how*.

### Acceptance criteria missing

**Finding:** no explicit, testable list of what "done" means.

**Ask:**
- "What does 'done' look like? List the specific, testable outcomes."
- "If an implementer finished this, what would you check to confirm it?"

**Proposed edit:** add a `## Acceptance criteria` section with a testable
checklist.

### Scope not bounded (multiple concerns bundled)

**Finding:** the issue describes multiple unrelated changes that cannot ship in
one PR.

**Ask:**
- "These seem like separate concerns. Should we split this into sub-issues?"
- "Which part is the core change, and which are separate?"

**Proposed edit:** propose a decomposition into 2-6 sub-issues (see Step 3 of
the skill procedure). Do not force a split if the concerns are actually
related.

### Terms undefined

**Finding:** domain jargon, acronyms, or ambiguous words are used without
definition.

**Ask:**
- "Can you define [term], or link to where it's documented?"
- "Would an implementer who isn't familiar with this domain understand this?"

**Proposed edit:** add definitions inline or in a `## Glossary` section, or
link to documentation.

## 2. Consistency with project invariants

### Conflict with AGENTS.md

**Finding:** the issue contradicts a rule in `AGENTS.md`.

**Ask:**
- "This seems to conflict with [AGENTS.md rule]. Is the intent to change the
  rule, or should the issue conform to it?"
- "If conforming, how should the issue be adjusted?"

**Proposed edit:** adjust the issue body to conform, OR explicitly document the
rule change as part of the issue (with user confirmation that a rule change is
intended).

### Conflict with specs

**Finding:** the proposed behavior conflicts with a `specs/<name>.qnt` spec, or
requires a spec update.

**Ask:**
- "This change affects [spec]. Does the spec need updating?"
- "What is the expected new behavior in spec terms?"

**Proposed edit:** add a `## Spec impact` section noting the required spec
update.

### Conflict with API/conventions

**Finding:** REST verb/naming, governed-entity, or link-table rules are
violated.

**Ask:**
- "The proposed API doesn't follow [convention]. Should it be adjusted, or is
  there a reason for the deviation?"

**Proposed edit:** align the issue with the convention, or document the
justified deviation explicitly.

## 3. Implementability and dependencies

### Prerequisites unresolved

**Finding:** the issue depends on open issues.

**Ask:**
- "This depends on #NNN, which is still open. Should we wait, or is this
  unblocked?"
- "Are there other prerequisites?"

**Proposed edit:** add/update a `## Dependencies` section, or confirm the
dependency is actually resolved.

### Insufficient detail to start

**Finding:** an implementer would need to ask clarifying questions.

**Ask:**
- "What data shape / field names / flow should the implementer use?"
- "Is there a specific file or module this should touch?"

**Proposed edit:** add the missing detail to the `## Proposed change` section.

### Not testable

**Finding:** it is unclear how to verify the change.

**Ask:**
- "How will this be verified (unit / e2e / spec)?"
- "What is the observable outcome that confirms success?"

**Proposed edit:** add a `## Testing approach` section.

## 4. Complexity (secondary, never the sole trigger)

### Blast radius not stated

**Finding:** the issue does not indicate affected areas.

**Ask:**
- "What areas of the codebase are likely affected?"

**Proposed edit:** add a scope/blast-radius note. This is informational and
alone does not block approval.

### Decomposition not suggested

**Finding:** the issue is large and ambiguous.

**Ask:**
- "This is a large change. Can it be broken into smaller, independently
  shippable pieces?"

**Proposed edit:** propose a decomposition (see Step 3). Only for
large-and-ambiguous issues; large-but-clear issues do not need refinement.
