#!/usr/bin/env python3
"""PR review automation dispatch script.

Runs hourly via cron. For each open PR labelled `ready_for_review` (and not
`agent_reviewing`, with no CHANGES_REQUESTED reviews and all CI checks
passing), this either starts a fresh review conversation or checks up on an
existing one, using a label-based countdown (`agent_attempts_remaining_<N>`)
to bound review/fix retries.

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
  MAX_PRS_PER_RUN        -- max PRs acted on per run (default: 3)
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
MAX_PRS_PER_RUN = int(os.environ.get("MAX_PRS_PER_RUN", "3"))
STALE_THRESHOLD_S = int(os.environ.get("STALE_THRESHOLD", "1200"))
CONVERSATION_TIMEOUT_S = int(os.environ.get("CONV_TIMEOUT", "600"))
WORKSPACE_ROOT = os.environ.get("OHE_WORKSPACE_ROOT", "/tmp/pr-review-workspaces")

ATTEMPTS_RE = re.compile(r"^agent_attempts_remaining_(\d+)$")
# Strict UUID extraction from a conversation URL. Never trust a free-form string.
CONV_ID_RE = re.compile(
    r"/api/conversations/"
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)
MARKER_PREFIX = "<!-- openhands-automation: pr-review -->"
MARKER_BODY_RE = re.compile(r"An Agent is reviewing this PR in conversation: (\S+)", re.IGNORECASE)
MARKER_SHA_RE = re.compile(r"Base SHA: ([0-9a-fA-F]{7,40})", re.IGNORECASE)

LABEL_READY = "ready_for_review"
LABEL_REVIEWING = "agent_reviewing"
LABEL_REVIEWED = "agent_reviewed"
LABEL_CHANGES_REQUESTED = "agent_changes_requested"
INITIAL_ATTEMPTS = 3

# Conversation execution statuses (mirror openhands.sdk ConversationExecutionStatus).
STATUS_TERMINAL = {"finished", "error", "stuck"}
STATUS_RUNNING = {"running", "paused", "waiting_for_confirmation", "idle"}

# CI check conclusions that count as "failing".
CI_FAILING_CONCLUSIONS = {
    "failure",
    "timed_out",
    "cancelled",
    "action_required",
}


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


def gh_get_prs_with_label(token: str, label: str) -> list[dict]:
    query = f"repo:{REPO} is:pr is:open label:{label}"
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
    ns = [int(m.group(1)) for label in labels for m in [ATTEMPTS_RE.match(label)] if m]
    return min(ns) if ns else 0


def set_labels(token: str, pr_number: int, add: list[str], remove: list[str]) -> None:
    for label in remove:
        try:
            gh_request(
                "DELETE",
                f"issues/{pr_number}/labels/{urllib.parse.quote(label)}",
                token,
            )
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    if add:
        gh_request("POST", f"issues/{pr_number}/labels", token, {"labels": add})


def list_comments(token: str, pr_number: int) -> list[dict]:
    return gh_request("GET", f"issues/{pr_number}/comments", token)  # type: ignore[return-value]


def post_comment(token: str, pr_number: int, body: str) -> dict:
    return gh_request("POST", f"issues/{pr_number}/comments", token, {"body": body})


def edit_comment(token: str, comment_id: int, body: str) -> dict:
    return gh_request("PATCH", f"issues/comments/{comment_id}", token, {"body": body})


def get_pr(token: str, pr_number: int) -> dict:
    return gh_request("GET", f"pulls/{pr_number}", token)


def get_pr_reviews(token: str, pr_number: int) -> list[dict]:
    data = gh_request("GET", f"pulls/{pr_number}/reviews?per_page=100", token)
    return data if isinstance(data, list) else []


def has_changes_requested(token: str, pr_number: int) -> bool:
    return any(
        review.get("state") == "CHANGES_REQUESTED" for review in get_pr_reviews(token, pr_number)
    )


def has_approve_review(token: str, pr_number: int) -> bool:
    return any(review.get("state") == "APPROVED" for review in get_pr_reviews(token, pr_number))


def ci_is_green(token: str, sha: str) -> bool:
    """True when all check-runs and statuses are success/neutral."""
    if not _check_runs_pass(token, sha):
        return False
    return _statuses_pass(token, sha)


def _check_runs_pass(token: str, sha: str) -> bool:
    try:
        data = gh_request("GET", f"commits/{sha}/check-runs?per_page=100", token)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True
        raise
    runs = data.get("check_runs") if isinstance(data, dict) else None
    if not runs:
        return True
    for run in runs:
        if run.get("status") != "completed":
            return False
        if run.get("conclusion") in CI_FAILING_CONCLUSIONS:
            return False
    return True


def _statuses_pass(token: str, sha: str) -> bool:
    try:
        data = gh_request("GET", f"commits/{sha}/statuses?per_page=100", token)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True
        raise
    if not isinstance(data, list) or not data:
        return True
    return all(status.get("state") in ("success", "neutral") for status in data)


def find_linked_issue(token: str, pr: dict) -> str | None:
    """Return the HTML URL of the issue this PR addresses, or None."""
    num = pr["number"]
    body = pr.get("body") or ""
    fix_re = re.compile(r"(?:fixes|closes|resolves)\s+#?(\d+)", re.I)
    m = fix_re.search(body)
    if m:
        return f"https://github.com/{REPO}/issues/{m.group(1)}"

    try:
        timeline = gh_request("GET", f"issues/{num}/timeline", token)
    except urllib.error.HTTPError:
        timeline = []
    for event in timeline if isinstance(timeline, list) else []:
        if event.get("event") != "cross-referenced":
            continue
        src = event.get("source", {}).get("issue", {})
        # An issue (not a PR) cross-referenced into this PR's timeline.
        if src.get("number") is not None and not (
            src.get("pull_request_urls") or src.get("pull_request")
        ):
            return f"https://github.com/{REPO}/issues/{src['number']}"
    return None


# --- Marker comment ---


def find_marker_comment(comments: list[dict]) -> dict | None:
    """Return the latest canonical marker comment, or None."""
    marker_comments = [c for c in comments if MARKER_PREFIX in (c.get("body") or "")]
    if not marker_comments:
        return None
    return marker_comments[-1]


def extract_conversation_url(comment: dict) -> str | None:
    body = comment.get("body") or ""
    m = MARKER_BODY_RE.search(body)
    return m.group(1) if m else None


def extract_base_sha(comment: dict) -> str | None:
    body = comment.get("body") or ""
    m = MARKER_SHA_RE.search(body)
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


def marker_body(conv_url: str, base_sha: str) -> str:
    return (
        f"{MARKER_PREFIX}\n"
        f"An Agent is reviewing this PR in conversation: {conv_url}\n"
        f"Base SHA: {base_sha}"
    )


def conversation_url(conv_id: str) -> str:
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    return f"{base}/api/conversations/{conv_id}"


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
    with urllib.request.urlopen(req) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else {}


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


def checkout_pr_head(repo: str, pr_number: str, head_sha: str, dest: str, token: str) -> str:
    """Clone the repo and check out the PR head. Returns the branch name."""
    if not os.path.isdir(os.path.join(dest, ".git")):
        os.makedirs(dest, exist_ok=True)
        url = f"https://{token}@github.com/{repo}.git"
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", "main", url, dest],
            check=True,
            capture_output=True,
        )
    branch = f"pr-{pr_number}"
    subprocess.run(
        ["git", "fetch", "origin", f"pull/{pr_number}/head:{branch}", "--depth", "50"],
        check=True,
        capture_output=True,
        cwd=dest,
    )
    subprocess.run(["git", "checkout", branch], check=True, capture_output=True, cwd=dest)
    subprocess.run(["git", "checkout", head_sha], check=True, capture_output=True, cwd=dest)
    return branch


def start_review_conversation(
    prompt: str, repo: str, token: str, tags: dict[str, str], workspace_dir: str
) -> str:
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    key = os.environ.get("SESSION_API_KEY", "")
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


def render_review_prompt(
    pr_url: str,
    pr_number: int,
    pr_head_sha: str,
    pr_branch: str,
    issue_url: str,
    n: int,
) -> str:
    tmpl = read_prompt_template("Review")
    return (
        tmpl.replace("{PR_URL}", pr_url)
        .replace("{REPO}", REPO)
        .replace("{PR_HEAD_SHA}", pr_head_sha)
        .replace("{PR_BRANCH}", pr_branch)
        .replace("{PR_NUMBER}", str(pr_number))
        .replace("{ISSUE_URL}", issue_url)
        .replace("{N}", str(n))
    )


def render_checkup_prompt(pr_url: str, conv_id: str) -> str:
    tmpl = read_prompt_template("Check-up")
    base = os.environ.get("AGENT_SERVER_URL", "").rstrip("/")
    return (
        tmpl.replace("{PR_URL}", pr_url)
        .replace("{CONVERSATION_ID}", conv_id)
        .replace("{AGENT_SERVER_URL}", base)
    )


# --- Per-PR flow ---


def fresh_start(token: str, pr: dict) -> None:
    num = pr["number"]
    labels = [label["name"] for label in pr.get("labels", [])]

    full_pr = get_pr(token, num)
    head_sha = full_pr["head"]["sha"]
    pr_branch = full_pr["head"]["ref"]
    pr_url = full_pr["html_url"]

    if not ci_is_green(token, head_sha):
        print(f"  #{num}: CI not green, skipping")
        return

    # Claim the PR.
    set_labels(token, num, add=[LABEL_REVIEWING], remove=[LABEL_READY])

    if not any(ATTEMPTS_RE.match(label) for label in labels):
        set_labels(token, num, add=[f"agent_attempts_remaining_{INITIAL_ATTEMPTS}"], remove=[])

    issue_url = find_linked_issue(token, full_pr) or "none"
    n = (
        parse_attempts(labels)
        if any(ATTEMPTS_RE.match(lbl) for lbl in labels)
        else INITIAL_ATTEMPTS
    )

    workspace_dir = os.path.join(WORKSPACE_ROOT, f"{REPO.replace('/', '_')}_pr{num}")
    checkout_pr_head(REPO, str(num), head_sha, workspace_dir, token)

    prompt = render_review_prompt(pr_url, num, head_sha, pr_branch, issue_url, n)
    conv_id = start_review_conversation(
        prompt,
        REPO,
        token,
        {"automation": "pr-review", "repo": REPO, "pr": str(num)},
        workspace_dir,
    )
    print(f"  #{num}: started review conversation {conv_id}")

    post_comment(token, num, marker_body(conversation_url(conv_id), head_sha))


def check_up(token: str, pr: dict, marker: dict) -> None:
    num = pr["number"]
    pr_url = pr["html_url"]

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

    # Terminal or stalled -> resolve outcome from GitHub state.
    labels = [label["name"] for label in pr.get("labels", [])]
    resolve_outcome(token, pr, conv_id, status, labels, pr_url, marker)


def resolve_outcome(
    token: str,
    pr: dict,
    conv_id: str,
    status: str | None,
    labels: list[str],
    pr_url: str,
    marker: dict,
) -> None:
    num = pr["number"]
    n = parse_attempts(labels)

    # Approved -> done.
    if has_approve_review(token, num):
        print(f"  #{num}: approved, done")
        set_labels(
            token,
            num,
            add=[LABEL_REVIEWED],
            remove=[LABEL_REVIEWING, f"agent_attempts_remaining_{n}"],
        )
        return

    # Changes requested -> done, human takeover.
    if has_changes_requested(token, num):
        print(f"  #{num}: changes requested, done")
        set_labels(
            token,
            num,
            add=[LABEL_CHANGES_REQUESTED],
            remove=[LABEL_REVIEWING, f"agent_attempts_remaining_{n}"],
        )
        return

    # Check for fixes applied (head SHA changed since marker base SHA).
    full_pr = get_pr(token, num)
    head_sha = full_pr["head"]["sha"]
    base_sha = extract_base_sha(marker)
    fixes_applied = base_sha is not None and head_sha != base_sha

    if fixes_applied:
        print(f"  #{num}: fixes applied (sha {base_sha} -> {head_sha[:7]}), re-queue")
        requeue(token, pr, conv_id, n, pr_url, marker, head_sha, full_pr, is_failure=False)
        return

    # Failure (ERROR / STUCK / stalled, no review and no new commits).
    print(f"  #{num}: failure, no fixes applied")
    requeue(token, pr, conv_id, n, pr_url, marker, head_sha, full_pr, is_failure=True)


def requeue(
    token: str,
    pr: dict,
    conv_id: str,
    n: int,
    pr_url: str,
    marker: dict,
    head_sha: str,
    full_pr: dict,
    is_failure: bool,
) -> None:
    num = pr["number"]
    pr_branch = full_pr["head"]["ref"]
    issue_url = find_linked_issue(token, full_pr) or "none"

    # At N=0: give up only on *failure* (no fixes, no approve). When the agent
    # applied its own fixes (is_failure=False), re-queue for a final re-review
    # of those fixes — never leave a "request changes" state for self-applied
    # fixes. The floor is N=0; further fixes at N=0 keep re-queueing, bounded
    # by the per-run cap and the expectation that the agent eventually approves
    # or stalls (no SHA change -> failure -> give_up).
    if n <= 0 and is_failure:
        give_up(token, num, conv_id)
        return

    next_n = max(n - 1, 0)
    print(f"  #{num}: retrying (N={n} -> {next_n})")
    remove_labels = [LABEL_REVIEWING]
    if n > 0:
        remove_labels.append(f"agent_attempts_remaining_{n}")
    set_labels(
        token,
        num,
        add=[f"agent_attempts_remaining_{next_n}", LABEL_READY],
        remove=remove_labels,
    )

    if is_failure:
        # Spawn a fire-and-forget check-up conversation to summarize.
        checkup_prompt = render_checkup_prompt(pr_url, conv_id)
        try:
            workspace_dir = os.path.join(
                WORKSPACE_ROOT, f"{REPO.replace('/', '_')}_pr{num}_checkup"
            )
            os.makedirs(workspace_dir, exist_ok=True)
            checkout_pr_head(REPO, str(num), head_sha, workspace_dir, token)
            checkup_id = start_review_conversation(
                checkup_prompt,
                REPO,
                token,
                {
                    "automation": "pr-review-checkup",
                    "repo": REPO,
                    "pr": str(num),
                },
                workspace_dir,
            )
            print(f"  #{num}: spawned check-up conversation {checkup_id}")
        except Exception as e:
            print(f"  #{num}: ERROR spawning check-up: {e}", file=sys.stderr)

    # Start a fresh review conversation and update the marker.
    prompt = render_review_prompt(pr_url, num, head_sha, pr_branch, issue_url, next_n)
    workspace_dir = os.path.join(WORKSPACE_ROOT, f"{REPO.replace('/', '_')}_pr{num}")
    checkout_pr_head(REPO, str(num), head_sha, workspace_dir, token)
    new_conv_id = start_review_conversation(
        prompt,
        REPO,
        token,
        {"automation": "pr-review", "repo": REPO, "pr": str(num)},
        workspace_dir,
    )
    print(f"  #{num}: started fresh review conversation {new_conv_id}")
    edit_comment(token, marker["id"], marker_body(conversation_url(new_conv_id), head_sha))


def give_up(token: str, pr_number: int, conv_id: str) -> None:
    print(f"  #{pr_number}: giving up after exhausting attempts")
    # Remove any lingering agent_attempts_remaining_<N> label (best-effort:
    # delete the N=0 variant; other variants should not exist at this point).
    set_labels(
        token,
        pr_number,
        add=[LABEL_CHANGES_REQUESTED],
        remove=[LABEL_REVIEWING, "agent_attempts_remaining_0"],
    )
    body = (
        "## Agent review gave up\n\n"
        "The pr-review automation exhausted its retry budget "
        f"(conversation `{conv_id}`). A human should take over. Remove "
        "`agent_changes_requested` and re-add `ready_for_review` to re-queue.\n\n"
        "_This comment was posted by an AI agent (OpenHands) on behalf of the "
        "repo owner._"
    )
    post_comment(token, pr_number, body)


# --- Stale-claim rescue ---


def rescue_stale(token: str, reviewing_prs: list[dict]) -> None:
    """Re-queue PRs claimed by a conversation that has stalled.

    Iterates over PRs that currently have the `agent_reviewing` label. If the
    conversation has had no new events for > STALE_THRESHOLD, the claim is
    released: `agent_reviewing` is removed and `ready_for_review` re-added so
    the PR re-enters the fresh-start scan set. The attempts budget is
    preserved (it was never removed at claim time).
    """
    for pr in reviewing_prs:
        num = pr["number"]
        comments = list_comments(token, num)
        marker = find_marker_comment(comments)
        if not marker:
            # Claimed but no marker — stale claim from a crashed run. Re-queue.
            print(f"  #{num}: stale claim (no marker), re-queueing")
            set_labels(token, num, add=[LABEL_READY], remove=[LABEL_REVIEWING])
            continue
        conv_url = extract_conversation_url(marker)
        if not conv_url:
            print(f"  #{num}: stale claim (bad marker), re-queueing")
            set_labels(token, num, add=[LABEL_READY], remove=[LABEL_REVIEWING])
            continue
        conv_id = extract_conversation_id(conv_url)
        if not conv_id:
            print(f"  #{num}: stale claim (bad conv id), re-queueing")
            set_labels(token, num, add=[LABEL_READY], remove=[LABEL_REVIEWING])
            continue
        if not is_stalled(conv_id):
            continue
        print(f"  #{num}: stale claim (stalled conversation), re-queueing")
        set_labels(token, num, add=[LABEL_READY], remove=[LABEL_REVIEWING])


# --- Main dispatch ---


def main() -> None:
    token = get_secret("GITHUB_TOKEN")
    print(f"=== PR review dispatch: repo={REPO} max={MAX_PRS_PER_RUN} ===")

    # PRs waiting for review (eligible for fresh start).
    ready_prs = gh_get_prs_with_label(token, LABEL_READY)
    print(f"Found {len(ready_prs)} PRs with {LABEL_READY}")

    # PRs currently being reviewed (need check-up or rescue).
    reviewing_prs = gh_get_prs_with_label(token, LABEL_REVIEWING)
    print(f"Found {len(reviewing_prs)} PRs with {LABEL_REVIEWING}")

    # Rescue stalled claims first (re-queues them into ready_prs for next run).
    rescue_stale(token, reviewing_prs)

    acted = 0

    # Process in-flight reviews: check up on conversations that have finished
    # or stalled, resolving the outcome (approve / changes / re-queue / give-up).
    for pr in reviewing_prs:
        if acted >= MAX_PRS_PER_RUN:
            print(f"  hit per-run cap ({MAX_PRS_PER_RUN}), stopping")
            break
        num = pr["number"]
        comments = list_comments(token, num)
        marker = find_marker_comment(comments)
        if not marker:
            # No marker on a reviewing PR — rescue_stale already re-queued it.
            continue
        try:
            print(f"  #{num}: marker present -> check up")
            check_up(token, pr, marker)
            acted += 1
        except Exception as e:
            print(f"  #{num}: ERROR: {e}", file=sys.stderr)

    # Process fresh starts: PRs with ready_for_review that have no marker.
    for pr in ready_prs:
        if acted >= MAX_PRS_PER_RUN:
            print(f"  hit per-run cap ({MAX_PRS_PER_RUN}), stopping")
            break
        num = pr["number"]
        labels = [label["name"] for label in pr.get("labels", [])]

        if LABEL_REVIEWING in labels:
            continue
        if has_changes_requested(token, num):
            print(f"  #{num}: has CHANGES_REQUESTED review, skipping")
            continue

        comments = list_comments(token, num)
        marker = find_marker_comment(comments)
        try:
            if marker is None:
                print(f"  #{num}: no marker -> fresh start")
                fresh_start(token, pr)
            else:
                # Has ready_for_review AND a marker — a rescue re-queued it.
                # Treat as a fresh start (the old conversation is stale).
                print(f"  #{num}: marker present but re-queued -> fresh start")
                fresh_start(token, pr)
            acted += 1
        except Exception as e:
            print(f"  #{num}: ERROR: {e}", file=sys.stderr)

    print(f"Acted on {acted} PRs.")


if __name__ == "__main__":
    try:
        main()
        fire_callback("COMPLETED")
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        fire_callback("FAILED", str(e))
        sys.exit(1)
