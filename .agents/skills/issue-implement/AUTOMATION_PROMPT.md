# Issue Implementation Automation — Prompts

This file holds the prompt templates sent to the OpenHands conversations
spawned by the hourly issue-implement automation (`main.py`). Keep it in sync
with `.agents/skills/issue-implement/SKILL.md`.

## How these prompts are used

The automation runs hourly via cron. Each run:

1. Enumerates open issues with `agent_approved` AND `ready_for_implementation`
   and no open linked PR, up to `MAX_ISSUES_PER_RUN` (default 3).
2. For each issue, looks for the canonical marker comment
   (`<!-- openhands-automation: implementation -->`):
   - **No marker** → starts an implementation conversation with the
     **Implementation prompt** below, then posts the marker comment.
   - **Marker present** → validates the conversation id, queries the agent
     server for `execution_status`, and either skips (still running / not
     found) or resolves an outcome (terminal). On a failure with retry budget
     remaining it starts a fresh implementation conversation, updates the
     marker, and spawns a fire-and-forget **Check-up prompt** conversation.

GitHub labels + the marker comment are the **sole source of truth** — no KV
store, no external state. The script owns all label swaps; the conversations
only implement / summarize.

## Implementation prompt

```
Please implement {ISSUE_URL}. Create a PR when you are finished with an
appropriate title and description linked to the issue. Mark the PR with the
labels `agent_generated` and `ready_for_review`.

The repository is already cloned into your workspace on branch `main`; its
AGENTS.md and .agents/skills/ are loaded. Follow them. When the PR is open,
stop — do not attempt to merge it or run the full CI suite unless AGENTS.md
requires it for the change.
```

## Check-up prompt

```
It looks like a conversation was created to handle {ISSUE_URL}, but it has
been running for quite some time. Please examine conversation {CONVERSATION_ID}
and its events with a view to figuring out what happened. If there was an
error, please try to summarize a reason and post a comment back to the issue
explaining it.

The conversation events are available via the agent server REST API:
  GET {AGENT_SERVER_URL}/api/conversations/{CONVERSATION_ID}/events/search
Authenticate with the X-Session-API-Key header (the SESSION_API_KEY env var).
Use sort_order=TIMESTAMP_DESC to read the most recent events first. Do not modify the
implementation conversation — only read it and post your summary comment to
the issue.
```
