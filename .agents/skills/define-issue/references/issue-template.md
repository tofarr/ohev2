# Issue Body Template

The structure every issue produced by `define-issue` must follow. This matches
what the `issue-review` skill expects, so a well-defined issue is pre-aligned
to pass review.

## Structure

```markdown
## Summary

[1-3 paragraphs stating the problem -- the *what* and *why*. Not just the
*how*. Who is affected, and why the current state is a problem.]

## Proposed change

[What should be different. Describe the change at a level an implementer can
act on without asking clarifying questions. Include data shapes, field names,
and flows where relevant.]

## Acceptance criteria

- [ ] [Specific, testable outcome 1]
- [ ] [Specific, testable outcome 2]
- [ ] ...

## Scope

**In scope:**
- [item]

**Out of scope (non-goals):**
- [item]

## Dependencies

- [Blocked by #NNN (if any) -- or "None"]
- [Blocks #NNN (if any) -- or "None"]

## Testing approach

[How to verify: unit / e2e / spec. What is the observable outcome that
confirms success?]

## Spec impact

[If the affected resource has a `specs/<name>.qnt` spec, note that a
behavioral change requires a spec update per AGENTS.md section 7. Otherwise
state "None".]
```

## Notes

- The title should be derived from the original one-line statement and stay
  concise (a single imperative sentence).
- Acceptance criteria must be a testable checklist, not a narrative.
- If the issue is one of several sub-issues from a decomposition, note the
  parent relationship in the Summary and link with `blocks` / `is blocked by`.
- Do not include implementation details (code, file paths beyond what defines
  the scope). The issue describes *what* and *why*, not *how to code it*.
