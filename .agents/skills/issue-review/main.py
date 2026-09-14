#!/usr/bin/env python3
"""Issue review automation dispatch script.

Runs hourly via cron. For each issue labeled `ready_for_agent_review` (and not
`agent_reviewing`), claims it via label swap, starts an OpenHands conversation
with the review prompt, and lets the conversation apply the outcome labels.

Also rescues stale claims: issues stuck in `agent_reviewing` for >2h get
re-queued.

GitHub labels are the sole source of truth -- no KV store or external state.

Environment (injected by the automation service at run time):
  AGENT_SERVER_URL       -- OpenHands agent server base URL
  SESSION_API_KEY        -- auth key for the agent server
  AUTOMATION_CALLBACK_URL         -- completion callback endpoint
  AUTOMATION_CALLBACK_API_KEY     -- callback auth key
  AUTOMATION_RUN_ID     -- this run's id (for the callback)
GITHUB_TOKEN is fetched from the agent server secret store at run time.

Optional config (env):
  OHE_REPO               -- target repo (default: tofarr/ohev2)
  OHE_AGENT_PROFILE      -- agent profile name (default: default)
  OHE_WORKSPACE_ROOT     -- root for cloned repo workspaces
  MAX_ISSUES_PER_RUN     -- max issues per run (default: 5)
  STALE_HOURS            -- stale-claim rescue threshold (default: 2)
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

# --- Config ---
REPO = os.environ.get("OHE_REPO", "tofarr/ohev2")
MAX_ISSUES_PER_RUN = int(os.environ.get("MAX_ISSUES_PER_RUN", "5"))
STALE_HOURS = int(os.environ.get("STALE_HOURS", "2"))
CONVERSATION_TIMEOUT_S = int(os.environ.get("CONV_TIMEOUT", "600"))
WORKSPACE_ROOT = os.environ.get("OHE_WORKSPACE_ROOT", "/tmp/issue-review-workspaces")

AUTO_REFINE_RE = re.compile(r"^auto_refine_(\d+)$")

LABEL_READY = "ready_for_agent_review"
LABEL_REVIEWING = "agent_reviewing"
LABEL_APPROVED = "agent_approved"
LABEL_NEEDS_REFINE = "needs_refinement"


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


def gh_get_issues_with_labels(
    token: str, labels: list[str], exclude_label: str | None = None
) -> list[dict]:
    label_query = " ".join(f'label:"{label}"' for label in labels)
    query = f"repo:{REPO} is:issue is:open {label_query}"
    if exclude_label:
        query += f' -label:"{exclude_label}"'
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


def parse_n(labels: list[str]) -> int:
    ns = [int(m.group(1)) for label in labels for m in [AUTO_REFINE_RE.match(label)] if m]
    return min(ns) if ns else 0


def set_labels(token: str, issue_number: int, add: list[str], remove: list[str]) -> None:
    for label in remove:
        try:
            gh_request("DELETE", f"issues/{issue_number}/labels/{urllib.parse.quote(label)}", token)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
    if add:
        gh_request("POST", f"issues/{issue_number}/labels", token, {"labels": add})


# --- OpenHands conversation helpers ---


def resolve_agent_profile_id() -> str:
    """Resolve the agent profile id to use for spawned conversations.

    The agent server requires one of `agent`, `agent_settings`, or
    `agent_profile_id` on the create payload. We resolve by name (defaulting
    to the `default` profile) and return its stored id.
    """
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
    """Clone the target repo into dest so AGENTS.md/.agents/specs load."""
    if os.path.isdir(os.path.join(dest, ".git")):
        return
    os.makedirs(dest, exist_ok=True)
    url = f"https://{token}@github.com/{repo}.git"
    subprocess.run(
        ["git", "clone", "--depth", "1", url, dest],
        check=True,
        capture_output=True,
    )


def start_conversation(prompt: str, repo: str, token: str) -> str:
    """Start an OpenHands conversation via the agent server API. Returns conversation id.

    Clones the repo into a per-issue workspace so AGENTS.md and
    .agents/skills/ load for the review. GITHUB_TOKEN is passed as a
    conversation secret (StaticSecret-typed) so the agent can read/write
    issue labels.
    """
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
        "tags": {"automation": "issue-review", "repo": repo},
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


def read_prompt_template() -> str:
    # The prompt template lives in the skill directory shipped with this script.
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "AUTOMATION_PROMPT.md")
    with open(path) as f:
        raw = f.read()
    # Extract the fenced code block (between ``` markers)
    start = raw.index("```\n") + 4
    end = raw.rindex("\n```")
    return raw[start:end]


def render_prompt(template: str, issue_url: str, n: int) -> str:
    return template.replace("{ISSUE_URL}", issue_url).replace("{N}", str(n))


# --- Rescue stale claims ---


def rescue_stale_claims(token: str) -> int:
    """Re-queue issues stuck in agent_reviewing for > STALE_HOURS."""
    issues = gh_get_issues_with_labels(token, [LABEL_REVIEWING])
    now = time.time()
    rescued = 0
    for issue in issues:
        updated = time.mktime(time.strptime(issue["updated_at"], "%Y-%m-%dT%H:%M:%SZ"))
        if now - updated > STALE_HOURS * 3600:
            num = issue["number"]
            print(f"  rescuing stale #{num}")
            set_labels(token, num, add=[LABEL_READY], remove=[LABEL_REVIEWING])
            rescued += 1
    return rescued


# --- Main dispatch ---


def main() -> None:
    token = get_secret("GITHUB_TOKEN")
    print(f"=== Issue review dispatch: repo={REPO} max={MAX_ISSUES_PER_RUN} ===")

    # 1. Rescue stale claims first
    rescued = rescue_stale_claims(token)
    print(f"Rescued {rescued} stale claims")

    # 2. Enumerate ready issues (not currently under review)
    issues = gh_get_issues_with_labels(token, [LABEL_READY], exclude_label=LABEL_REVIEWING)
    print(f"Found {len(issues)} issues ready for review")
    if not issues:
        print("Nothing to do.")
        return

    # 3. Claim and dispatch up to MAX_ISSUES_PER_RUN
    prompt_template = read_prompt_template()
    dispatched = 0
    for issue in issues[:MAX_ISSUES_PER_RUN]:
        num = issue["number"]
        labels = [label["name"] for label in issue.get("labels", [])]
        n = parse_n(labels)
        issue_url = issue["html_url"]

        # Claim: swap ready -> reviewing
        set_labels(
            token,
            num,
            add=[LABEL_REVIEWING],
            remove=[LABEL_READY, LABEL_APPROVED, LABEL_NEEDS_REFINE],
        )
        print(f"  claimed #{num} (N={n})")

        # Render the prompt and start a conversation
        prompt = render_prompt(prompt_template, issue_url, n)
        try:
            conv_id = start_conversation(prompt, REPO, token)
            print(f"  started conversation {conv_id} for #{num}")
            dispatched += 1
        except Exception as e:
            print(f"  ERROR starting conversation for #{num}: {e}", file=sys.stderr)
            # Un-claim so it's retried next run
            set_labels(token, num, add=[LABEL_READY], remove=[LABEL_REVIEWING])

    print(f"Dispatched {dispatched} conversations.")


if __name__ == "__main__":
    try:
        main()
        fire_callback("COMPLETED")
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        fire_callback("FAILED", str(e))
        sys.exit(1)
