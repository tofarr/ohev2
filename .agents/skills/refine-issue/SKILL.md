---
name: refine-issue
description: >
  This skill should be used when the user asks to "refine an issue", "fix
  review findings on an issue", "address review comments", "clean up an issue
  that failed review", or references an issue with the `needs_refinement`
  label that needs work before it can be re-queued for agent review. It
  interactively walks the user through each review finding, proposes edits,
  gets per-edit sign-off, and pushes toward decomposition when the issue is
  too complex for a single PR.
---

# Refine Issue

Interactively refine a GitHub issue that failed the `issue-review` automation.
Read the issue body and its review findings comments, walk the user through each
failing criterion one by one, propose targeted edits, and apply them only after
per-edit user sign-off. When the issue is too complex for a single PR, push
toward decomposition into sub-issues.

## When to use

Invoke this skill when a user references an issue that has failed review (has
the `needs_refinement` label, or has `## Agent review findings` comments with
FAIL entries) and wants to address the findings. The user must be present to
answer questions and approve edits -- this skill is never run autonomously.

This skill refines **issues only**. It does not touch PRs, code, or code-review
comments on pull requests.

## Core principles

- **Human-in-the-loop, always.** Never rewrite the issue body, create
  sub-issues, or apply labels without explicit per-action user approval. Every
  proposed edit waits for sign-off before it is applied.
- **One finding at a time.** Walk through each FAIL finding individually. Do
  not dump all findings and ask the user to address them at once. Present the
  finding, propose a fix, get approval, apply, move to the next.
- **No autonomous rewrites.** Unlike the removed `auto_refine` loop, this skill
  never guesses what the author meant. It asks. The agent proposes edits based
  on the user's answers, but the user has final say on every change.
- **Preserve original intent.** Edits refine the issue toward clarity; they do
  not change the author's goal. If a finding suggests the goal itself is wrong,
  surface that as a question rather than silently redirecting.
- **Push toward decomposition.** When findings reveal the issue is too large or
  bundles unrelated concerns, proactively propose a split into sub-issues. Get
  user approval before creating anything.

## Procedure

### Step 1 -- Load the issue and findings

1. Read the issue body and all comments from GitHub (via the GitHub API).
2. Identify the review findings comments (look for `## Agent review findings`
   headers, or any comment listing FAIL criteria).
3. Extract the list of failing criteria. If no formal findings comment exists,
   read the comments for any review feedback and treat each actionable item as
   a finding.
4. Present a summary to the user: the issue title, the failing criteria, and the
   plan to walk through them one by one. Confirm the user is ready to proceed.

### Step 2 -- Walk through each finding

For each failing criterion, in order:

1. **Present the finding.** Quote the finding text and the relevant issue text
   it refers to. Explain why it failed review.
2. **Ask a targeted question.** Ask the user what the intended behavior / detail
   is, so the edit reflects their intent rather than a guess. Use the question
   sets in `references/finding-questions.md` matched to each criterion type.
3. **Propose an edit.** Based on the user's answer, propose a specific edit to
   the issue body (or a structural change like a split). Show the user the
   before/after of the proposed change.
4. **Get sign-off.** Wait for explicit approval. If the user requests changes,
   revise the proposal and re-present.
5. **Apply the edit.** Only after approval, update the issue body on GitHub
   (via the GitHub API). Confirm the edit was applied.

Repeat for each finding. If a later finding changes the context for an earlier
edit, revisit and re-confirm the earlier edit with the user.

### Step 3 -- Decomposition check

After addressing the individual findings, evaluate the overall scope:

- If the findings revealed the issue bundles multiple unrelated concerns, or is
  too large for a single PR, propose a split into 2-6 sub-issues.
- For each proposed sub-issue, draft a full body (problem, acceptance criteria,
  scope) following the `define-issue` skill's template.
- Present the proposed breakdown to the user and get explicit approval.
- Only after approval, create the sub-issues on GitHub and link them with
  `blocks` / `is blocked by` relationships. Close or repurpose the original
  issue as appropriate (with user approval).

Do not force a split. If the issue is large but now clear and cohesive after
the edits, leave it as one issue.

### Step 4 -- Final review

Present the final issue body to the user for a last look. Confirm it reads as a
clean, coherent issue that a fresh reader can understand without reading the
comment history. The findings comments remain as the auditable record of what
each review concluded -- do not delete them.

### Step 5 -- Re-queue for review

Only after the user confirms the refined issue is ready:

1. Remove the `needs_refinement` label.
2. Apply the `ready_for_agent_review` label so the issue is picked up by the
   next hourly review automation run.
3. Confirm the re-queue to the user.

## Behavior rules

- Ask questions one at a time. Never present a wall of questions.
- Wait for the answer to each question before proposing an edit.
- Never apply an edit without showing the user the proposed change and getting
  explicit approval.
- If the user's answer to a finding reveals a deeper ambiguity, follow up with
  additional questions until the intent is clear.
- If the repo has an `AGENTS.md`, check proposed edits against its rules
  (stack, layering, REST, auth, RBAC, testing). Surface conflicts as
  questions.
- If the affected resource has a `specs/<name>.qnt` spec, note behavioral
  changes that require a spec update (per AGENTS.md section 7) and include the
  spec update in the issue body.
- Do not delete or edit prior findings comments -- they are the audit trail.
- Do not touch PRs, code, or repository settings. This skill only edits issue
  bodies, creates sub-issues, and manages issue labels.

## Reference Files

- **`references/finding-questions.md`** -- question sets matched to each
  review criterion type, to drive the interactive refinement of each finding.
