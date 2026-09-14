---
name: define-issue
description: >
  This skill should be used when the user asks to "define an issue", "draft an
  issue", "create an issue", "write a GitHub issue", "turn this idea into an
  issue", or provides a one-line statement they want expanded into a full
  GitHub issue. It interactively walks the user from a single statement to a
  complete, review-ready issue by generating a plan, asking targeted questions,
  and creating the issue on GitHub once the user approves the final body.
---

# Define Issue

Interactively guide an author from a single sentence to a complete, review-ready
GitHub issue. The skill is a structured interview: start from the author's
one-line intent, produce a draft plan, ask targeted questions to fill the gaps,
and create the issue on GitHub only after the user approves the final body.

## When to use

Invoke this skill when a user provides a short statement or idea and wants it
expanded into a full GitHub issue. The user must be present to answer questions
-- this skill is never run autonomously.

## Core principles

- **Human-in-the-loop, always.** Never create the issue on GitHub, edit an
  issue body, or apply labels without explicit user approval at each step.
  Every question waits for an answer; every draft body waits for sign-off.
- **Preserve the author's intent.** The original one-line statement becomes the
  issue title (or its seed). Subsequent questions refine, never replace, the
  author's goal.
- **Anchor to the review checklist.** The `issue-review` skill reviews against
  four criteria (clarity and completeness, consistency with project invariants,
  implementability and dependencies, complexity). Questions target the same
  criteria so a defined issue is pre-aligned to pass review. See
  `references/review-criteria.md` for the full checklist and the specific
  questions to ask for each.
- **Push toward decomposition.** When the scope described by the author is too
  large for a single PR, proactively suggest splitting into sub-issues. Propose
  a breakdown and get the user's approval before creating anything.
- **Create once, at the end.** The GitHub issue is created only after the final
  body is approved. Do not create a half-finished issue and edit it
  incrementally -- a draft belongs in the conversation, not in the repo.

## Procedure

### Step 1 -- Capture the one-line statement

Ask the user for a single sentence describing what they want. If they already
provided one, use it. This becomes the seed for the issue title and the core
intent that every subsequent question must serve.

### Step 2 -- Produce a draft plan

From the one-liner, generate a structured draft containing:

- **Problem** -- what is the current state and why is it a problem?
- **Proposed change** -- what should be different?
- **Open questions** -- what is not yet clear (list explicitly; these drive the
  interview).

Present the draft plan to the user and confirm it captures their intent. Revise
the plan based on their feedback before proceeding to questions.

### Step 3 -- Run the targeted interview

Work through the open questions and the review-criteria gaps one at a time. For
each criterion in `references/review-criteria.md` that is not yet satisfied,
ask a specific question. Ask one question (or a small tightly-related group) at
a time and wait for the answer -- do not dump all questions at once.

Key areas to cover (full question sets in `references/review-criteria.md`):

- **Problem and motivation** -- the *what* and *why*, not just the *how*.
- **Acceptance criteria** -- an explicit, testable list of what "done" means.
- **Scope** -- is this one cohesive change or does it need to be split?
- **Terms** -- domain jargon, acronyms, ambiguous words.
- **Consistency** -- conflicts with `AGENTS.md`, specs, or API conventions.
- **Dependencies** -- blocked-by links, prerequisites.
- **Testability** -- how will the change be verified?

### Step 4 -- Decomposition check

Evaluate the scope once the picture is complete. If it is genuinely too large
for one PR:

1. Propose a split into 2-6 sub-issues, each a cohesive single-PR change.
2. Present the proposed breakdown to the user and get explicit approval.
3. For each sub-issue, produce a full body (problem, acceptance criteria,
   scope) following this same procedure.
4. Create the sub-issues linked with `blocks` / `is blocked by` relationships.

Do not force a split -- if the issue is large but cohesive and clear, leave it
as one issue. A bad split is worse than a large issue.

### Step 5 -- Present the final draft

Assemble the complete issue body from the interview answers and present it to
the user for approval. The body must follow the structure in
`references/issue-template.md`:

- Title (derived from the original one-liner)
- Summary (problem + motivation)
- Acceptance criteria (testable list)
- Scope / non-goals
- Dependencies (if any)
- Testing approach

Wait for explicit approval. If the user requests changes, revise and
re-present.

### Step 6 -- Create the issue on GitHub

Only after the user approves the final body:

1. Create the issue on GitHub (title + body).
2. If sub-issues were approved in Step 4, create each one and link them with
   `blocks` / `is blocked by`.
3. Apply the `ready_for_agent_review` label so the issue flows directly into
   the issue-review automation.
4. Post the issue URL(s) back to the user.

## Behavior rules

- Ask questions one at a time (or a small tightly-related group). Never present
  a wall of questions.
- Wait for the answer to each question before moving on.
- If the user's answer reveals a larger scope, surface that immediately and
  discuss decomposition before continuing the interview.
- Never create the issue, edit a body, or apply labels without explicit
  per-action user approval.
- If the repo has an `AGENTS.md`, read it and check the proposed issue against
  its rules (stack, layering, REST, auth, RBAC, testing). Surface conflicts as
  questions, not as silent edits.
- If the affected resource has a `specs/<name>.qnt` spec, note that behavioral
  changes will require a spec update (per AGENTS.md section 7) and include it
  in the issue body.

## Reference Files

- **`references/review-criteria.md`** -- the full issue-review checklist with
  the specific questions to ask for each criterion.
- **`references/issue-template.md`** -- the issue body structure and template.
