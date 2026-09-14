#!/usr/bin/env python3
"""Issue implementation automation dispatch script.

Runs hourly via cron. For each open issue labelled `agent_approved` AND
`ready_for_implementation` (and with no open linked PR), this either starts a
fresh implementation conversation or checks up on an existing one, using a
label-based countdown (`agent_remaining_attempts_<N>`) to bound retries.

GitHub labels + a canonical marker comment are the sole source of truth -- no
KV store, so multiple automation servers can track the same repo independently.
Conversation liveness is derived from the agent server at run time.

Environment (injected by the automation service at run time):
  AGENT_SERVER_URL               -- OpenHands agent server base URL
  SESSION_API_KEY                -- auth key for the agent server
  AUTOMATION_CALLBACK_URL        -- completion callback endpoint
  AUTOMATION_CALLBACK_API_KEY    -- callback auth key
  AUTOMATION_RUN_ID              -- this run's id (for the callback)
GITHUB_TOKEN is fetched from the agent server secret store at run time.

Optional config (env):
  OHE_REPO               -- target repo (default: tofarr/ohev2)
  OHE_AGENT_PROFILE      -- agent profile name (default: default)
  OHE_WORKSPACE_ROOT     -- root for cloned repo workspaces
  MAX_ISSUES_PER_RUN     -- max issues acted on per run (default: 3)
  STALE_THRESHOLD        -- no-new-events -> stalled, seconds (default: 1200)
  CONV_TIMEOUT           -- per-conversation timeout seconds (default: 600)
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from uuid import UUID

# --- Config ---
REPO = os.environ.get("OHE_REPO", "tofarr/ohev2")
MAX_ISSUES_PER_RUN = int(os.environ.get("MAX_ISSUES_PER_RUN", "3"))
STALE_THRESHOLD_S = int(os.environ.get("STALE_THRESHOLD", "1200"))
CONVERSATION_TIMEOUT_S = int(os.environ.get("CONV_TIMEOUT", "600"))
WORKSPACE_ROOT = os.environ.get("OHE_WORKSPACE_ROOT", "/tmp/issue-implement-workspaces")

REMAINING_RE = re.compile(r"^agent_remaining_attempts_(\d+)$")
# Strict UUID extraction from a conversation URL. Never trust a free-form string.
CONV_ID_RE = re.compile(
    r"/api/conversations/"
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
MARKER_PREFIX = "<!-- openhands-automation: implementation -->"
MARKER_BODY_RE = re.compile(r"An Agent is working on this in conversation: (\S+)", re.IGNORECASE)

LABEL_READY = "ready_for_implementation"
LABEL_APPROVED = "agent_approved"
LABEL_AGENT_GENERATED = "agent_generated"
LABEL_READY_FOR_REVIEW = "ready_for_review"
INITIAL_ATTEMPTS = 3

# Conversation execution statuses (mirror openhands.sdk ConversationExecutionStatus).
STATUS_TERMINAL = {"finished", "error", "stuck"}
STATUS_RUNNING = {"running", "paused", "waiting_for_confirmation", "idle"}


# --- No-LLM helpers (from the automation skill) ---


def get_secret(name: str) -> str:
    url = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    key = os.environ.get("SESSION_API_KEY") or os.environ.get("OH_SESSION_API_KEYS_0", "")
    with urllib.request.urlopen(
        urllib.request.Request(
            f"{url}/api/settings/secrets/{name}",
            headers={"X-Session-API-Key": key},
        )
    ) as r:
        return r.read().decode().strip()


def fire_callback(status: str = "COMPLETED", error: str | None = None) -> None:
    url = os.environ.get("AUTOMATION_CALLBACK_URL", "")
    if not url:
        return
    body: dict[str, object] = {"status": status, "run_id": os.environ.get("AUTOMATION_RUN_ID", "")}
    if error:
        body["error"] = error
    try:
        urllib.request.urlopen(
            urllib.request.Request(
                url,
                data=json.dumps(body).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {os.environ.get('AUTOMATION_CALLBACK_API_KEY', '')}",
                },
            )
        )
    except Exception as e:
        print(f"Callback error: {e}", file=sys.stderr)


# --- GitHub API helpers ---


def gh_request(method: str, path: str, token: str, body: dict | None = None) -> dict:
    url = f"https://api.github.com/repos/{REPO}/{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        method=method,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else {}


def gh_get_issues_with_labels(token: str, labels: list[str]) -> list[dict]:
    label_query = " ".join(f'label:"{label}"' for label in labels)
    query = f"repo:{REPO} is:issue is:open {label_query}"
    url = f"https://api.github.com/search/issues?q={urllib.parse.quote(query)}&per_page=50"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode()).get("items", [])


def parse_attempts(labels: list[str]) -> int:
    ns = [int(m.group(1)) for label in labels for m in [REMAINING_RE.match(label)] if m]
    return min(ns) if ns else 0


def set_labels(token: str, issue_number: int, add: list[str], remove: list[str]) -> None:
    for label in remove:
        try:
            gh_request(
                "DELETE",
                f"issues/{issue_number}/labels/{urllib.parse.quote(label)}",
                token,
            )
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    if add:
        gh_request("POST", f"issues/{issue_number}/labels", token, {"labels": add})


def list_comments(token: str, issue_number: int) -> list[dict]:
    return gh_request("GET", f"issues/{issue_number}/comments", token)  # type: ignore[return-value]


def post_comment(token: str, issue_number: int, body: str) -> dict:
    return gh_request("POST", f"issues/{issue_number}/comments", token, {"body": body})


def edit_comment(token: str, comment_id: int, body: str) -> dict:
    return gh_request("PATCH", f"issues/comments/{comment_id}", token, {"body": body})


def has_open_linked_pr(token: str, issue_number: int) -> bool:
    """True if the issue has an open PR that references it.

    Uses the timeline `cross-referenced` events (source_issue is a PR) plus
    PR-body `Fixes #N` / `Closes #N` parsing. A merged PR is handled by a
    separate process that closes the issue, so we only care about open PRs.
    """
    open_pr_numbers: set[int] = set()

    # 1. cross-referenced timeline events where the source is a PR.
    try:
        timeline = gh_request(
            "GET",
            f"issues/{issue_number}/timeline",
            token,
        )
    except urllib.error.HTTPError:
        timeline = []
    for event in timeline if isinstance(timeline, list) else []:
        if event.get("event") != "cross-referenced":
            continue
        src = event.get("source", {}).get("issue", {})
        if not src.get("pull_request_urls") and not src.get("pull_request"):
            continue
        pr_num = src.get("number")
        if pr_num is not None:
            open_pr_numbers.add(pr_num)

    # 2. PR bodies containing Fixes/Closes #N across the repo's open PRs.
    try:
        prs = gh_request("GET", "pulls?state=open&per_page=100", token)
    except urllib.error.HTTPError:
        prs = []
    fix_re = re.compile(r"(?:fixes|closes|resolves)\s+#?" + str(issue_number), re.I)
    for pr in prs if isinstance(prs, list) else []:
        if fix_re.search(pr.get("body") or ""):
            open_pr_numbers.add(pr.get("number"))

    if not open_pr_numbers:
        return False

    # Verify each candidate PR is actually open (state == open).
    for pr_num in open_pr_numbers:
        try:
            pr = gh_request("GET", f"pulls/{pr_num}", token)
        except urllib.error.HTTPError:
            continue
        if pr.get("state") == "open":
            return True
    return False


def find_marker_comment(comments: list[dict]) -> dict | None:
    """Return the latest canonical marker comment, or None."""
    marker_comments = [c for c in comments if MARKER_PREFIX in (c.get("body") or "")]
    if not marker_comments:
        return None
    # GitHub returns comments oldest-first; take the last.
    return marker_comments[-1]


def extract_conversation_url(comment: dict) -> str | None:
    body = comment.get("body") or ""
    m = MARKER_BODY_RE.search(body)
    return m.group(1) if m else None


def extract_conversation_id(url: str) -> str | None:
    m = CONV_ID_RE.search(url)
    if not m:
        return None
    try:
        UUID(m.group(1))
    except ValueError:
        return None
    return m.group(1)


# --- OpenHands conversation helpers ---


def agent_request(method: str, path: str, body: dict | None = None) -> dict:
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    key = os.environ.get("SESSION_API_KEY", "")
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        f"{base}{path}",
        method=method,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-Session-API-Key": key,
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise
        raise


def resolve_agent_profile_id() -> str:
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    key = os.environ.get("SESSION_API_KEY", "")
    name = os.environ.get("OHE_AGENT_PROFILE", "default")
    req = urllib.request.Request(
        f"{base}/api/agent-profiles/{name}",
        headers={"X-Session-API-Key": key},
    )
    with urllib.request.urlopen(req) as r:
        data = json.loads(r.read().decode())
    profile = data.get("profile", data)
    pid = profile.get("id")
    if not pid:
        raise RuntimeError(f"agent profile '{name}' has no id")
    return pid


def clone_repo(repo: str, dest: str, token: str) -> None:
    if os.path.isdir(os.path.join(dest, ".git")):
        return
    os.makedirs(dest, exist_ok=True)
    url = f"https://{token}@github.com/{repo}.git"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", "main", url, dest],
        check=True,
        capture_output=True,
    )


def start_conversation(prompt: str, repo: str, token: str, tags: dict[str, str]) -> str:
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    key = os.environ.get("SESSION_API_KEY", "")

    workspace_dir = os.path.join(WORKSPACE_ROOT, repo.replace("/", "_"))
    clone_repo(repo, workspace_dir, token)
    profile_id = resolve_agent_profile_id()

    body = {
        "workspace": {"kind": "LocalWorkspace", "working_dir": workspace_dir},
        "agent_profile_id": profile_id,
        "initial_message": {
            "role": "user",
            "content": [{"type": "text", "text": prompt}],
            "run": True,
        },
        "secrets": {"GITHUB_TOKEN": {"kind": "StaticSecret", "value": token}},
        "tags": tags,
    }
    req = urllib.request.Request(
        f"{base}/api/conversations",
        method="POST",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Session-API-Key": key,
        },
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())["id"]


def get_conversation_status(conv_id: str) -> str | None:
    """Return the conversation's execution_status, or None if not found."""
    try:
        data = agent_request("GET", f"/api/conversations/{conv_id}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    return data.get("execution_status")


def last_event_timestamp(conv_id: str) -> str | None:
    """Return the ISO timestamp of the most recent event, or None."""
    try:
        data = agent_request(
            "GET",
            f"/api/conversations/{conv_id}/events/search?limit=1&sort_order=TIMESTAMP_DESC",
        )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    items = data.get("items") or []
    if not items:
        return None
    return items[0].get("timestamp")


def is_stalled(conv_id: str) -> bool:
    """True if the conversation has had no new events for > STALE_THRESHOLD_S."""
    ts = last_event_timestamp(conv_id)
    if not ts:
        return True
    # Event timestamps are naive server-local ISO strings.
    try:
        parsed = time.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        try:
            parsed = time.strptime(ts, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            parsed = time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    age = time.time() - time.mktime(parsed)
    return age > STALE_THRESHOLD_S


# --- Prompt rendering ---


def read_prompt_template(name: str) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "AUTOMATION_PROMPT.md")
    with open(path) as f:
        raw = f.read()
    marker = f"## {name} prompt"
    start = raw.index(marker)
    block_start = raw.index("```\n", start) + 4
    block_end = raw.index("\n```", block_start)
    return raw[block_start:block_end]


def render_impl_prompt(issue_url: str) -> str:
    tmpl = read_prompt_template("Implementation")
    return tmpl.replace("{ISSUE_URL}", issue_url)


def render_checkup_prompt(issue_url: str, conv_id: str) -> str:
    tmpl = read_prompt_template("Check-up")
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    return (
        tmpl.replace("{ISSUE_URL}", issue_url)
        .replace("{CONVERSATION_ID}", conv_id)
        .replace("{AGENT_SERVER_URL}", base)
    )


# --- Marker comment ---


def marker_body(conv_url: str) -> str:
    return f"{MARKER_PREFIX}\nAn Agent is working on this in conversation: {conv_url}"


def conversation_url(conv_id: str) -> str:
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    return f"{base}/api/conversations/{conv_id}"


# --- Per-issue flow ---


def fresh_start(token: str, issue: dict) -> None:
    num = issue["number"]
    labels = [label["name"] for label in issue.get("labels", [])]
    issue_url = issue["html_url"]

    # Set initial attempts on the issue if no budget label is present.
    if not any(REMAINING_RE.match(label) for label in labels):
        set_labels(token, num, add=[f"agent_remaining_attempts_{INITIAL_ATTEMPTS}"], remove=[])

    prompt = render_impl_prompt(issue_url)
    conv_id = start_conversation(
        prompt,
        REPO,
        token,
        {"automation": "issue-implement", "repo": REPO, "issue": str(num)},
    )
    print(f"  started implementation conversation {conv_id} for #{num}")

    # Post the marker immediately so the next run sees it.
    post_comment(token, num, marker_body(conversation_url(conv_id)))


def check_up(token: str, issue: dict, marker: dict) -> None:
    num = issue["number"]
    labels = [label["name"] for label in issue.get("labels", [])]
    issue_url = issue["html_url"]

    conv_url = extract_conversation_url(marker)
    if not conv_url:
        print(f"  #{num}: marker has no conversation URL, skipping")
        return
    conv_id = extract_conversation_id(conv_url)
    if not conv_id:
        print(f"  #{num}: invalid conversation id in marker, skipping")
        return

    status = get_conversation_status(conv_id)
    if status is None:
        print(f"  #{num}: conversation {conv_id} not found, skipping")
        return
    print(f"  #{num}: conversation {conv_id} status={status}")

    if status == "deleting":
        return
    if status in STATUS_RUNNING and not is_stalled(conv_id):
        print(f"  #{num}: still running, skipping")
        return

    # Terminal or stalled -> resolve outcome from execution_status.
    resolve_outcome(token, issue, conv_id, status, labels, issue_url, marker)


def resolve_outcome(
    token: str,
    issue: dict,
    conv_id: str,
    status: str | None,
    labels: list[str],
    issue_url: str,
    marker: dict,
) -> None:
    num = issue["number"]
    n = parse_attempts(labels)

    # Success: finished and an open PR now exists -> the open-PR filter will
    # exclude the issue from future runs. Nothing more to do.
    if status == "finished" and has_open_linked_pr(token, num):
        print(f"  #{num}: finished with open PR, success")
        return

    # Failure (error / stuck / finished-without-PR / stalled).
    if n > 0:
        print(f"  #{num}: failure, retrying (N={n} -> {n - 1})")
        set_labels(
            token,
            num,
            add=[f"agent_remaining_attempts_{n - 1}"],
            remove=[f"agent_remaining_attempts_{n}"],
        )
        # Spawn a fire-and-forget check-up conversation to summarize.
        checkup_prompt = render_checkup_prompt(issue_url, conv_id)
        try:
            checkup_id = start_conversation(
                checkup_prompt,
                REPO,
                token,
                {
                    "automation": "issue-implement-checkup",
                    "repo": REPO,
                    "issue": str(num),
                },
            )
            print(f"  #{num}: spawned check-up conversation {checkup_id}")
        except Exception as e:
            print(f"  #{num}: ERROR spawning check-up: {e}", file=sys.stderr)

        # Start a fresh implementation conversation and update the marker.
        impl_prompt = render_impl_prompt(issue_url)
        new_conv_id = start_conversation(
            impl_prompt,
            REPO,
            token,
            {"automation": "issue-implement", "repo": REPO, "issue": str(num)},
        )
        print(f"  #{num}: started fresh implementation conversation {new_conv_id}")
        edit_comment(token, marker["id"], marker_body(conversation_url(new_conv_id)))
    else:
        give_up(token, num, conv_id)


def give_up(token: str, issue_number: int, conv_id: str) -> None:
    print(f"  #{issue_number}: giving up after exhausting attempts")
    set_labels(token, issue_number, remove=[LABEL_READY])
    body = (
        "## Agent implementation gave up\n\n"
        f"The issue-implement automation exhausted its retry budget "
        f"(conversation `{conv_id}`). A human should take over. Re-add "
        f"`ready_for_implementation` to re-queue.\n\n"
        "_This comment was posted by an AI agent (OpenHands) on behalf of the "
        "repo owner._"
    )
    post_comment(token, issue_number, body)


# --- Main dispatch ---


def main() -> None:
    token = get_secret("GITHUB_TOKEN")
    print(f"=== Issue implement dispatch: repo={REPO} max={MAX_ISSUES_PER_RUN} ===")

    issues = gh_get_issues_with_labels(token, [LABEL_APPROVED, LABEL_READY])
    print(f"Found {len(issues)} candidate issues")

    acted = 0
    for issue in issues:
        if acted >= MAX_ISSUES_PER_RUN:
            print(f"  hit per-run cap ({MAX_ISSUES_PER_RUN}), stopping")
            break
        num = issue["number"]

        # Drop issues with an open linked PR.
        if has_open_linked_pr(token, num):
            print(f"  #{num}: open linked PR, skipping")
            continue

        comments = list_comments(token, num)
        marker = find_marker_comment(comments)
        try:
            if marker is None:
                print(f"  #{num}: no marker -> fresh start")
                fresh_start(token, issue)
            else:
                print(f"  #{num}: marker present -> check up")
                check_up(token, issue, marker)
            acted += 1
        except Exception as e:
            print(f"  #{num}: ERROR: {e}", file=sys.stderr)

    print(f"Acted on {acted} issues.")


if __name__ == "__main__":
    try:
        main()
        fire_callback("COMPLETED")
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        fire_callback("FAILED", str(e))
        sys.exit(1)
