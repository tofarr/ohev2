#!/usr/bin/env bash
# Deploy the pr-review automation.
#
# This script:
# 1. Creates the required GitHub labels (if missing).
# 2. Tars up the automation code (.agents/skills/pr-review/).
# 3. Uploads the tarball to the automation service.
# 4. Creates/updates the cron automation pointing at the uploaded tarball.
#
# Prerequisites:
#   - GITHUB_TOKEN env var (with repo scope for the target repo)
#   - OPENHANDS_AUTOMATION_API_KEY env var (for the automation service)
#   - curl, jq, tar
#
# Usage:
#   bash deploy.sh
#
# After deployment, PRs labelled `ready_for_review` (from issue-implement) with
# passing CI and no CHANGES_REQUESTED reviews are reviewed on the next hourly
# run.

set -euo pipefail

REPO="${OHE_REPO:-tofarr/ohev2}"
AUTOMATION_HOST="${OPENHANDS_HOST:-http://127.0.0.1:8000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== PR Review Automation Deployment ==="
echo "Repo: $REPO"
echo "Automation host: $AUTOMATION_HOST"
echo ""

# --- 1. Create GitHub labels ---

echo "--- Creating GitHub labels ---"
LABELS=(
  "agent_reviewing:F59E0B:Agent is reviewing this issue or PR"
  "agent_attempts_remaining_0:EF4444:Review budget exhausted"
  "agent_attempts_remaining_1:F59E0B:1 review/fix attempt remaining"
  "agent_attempts_remaining_2:F59E0B:2 review/fix attempts remaining"
  "agent_attempts_remaining_3:3B82F6:3 review/fix attempts remaining (initial)"
  "agent_reviewed:10B981:PR approved by the agent"
  "agent_changes_requested:EF4444:Agent requested changes; human takeover"
)
# NOTE: `ready_for_review` is owned by the issue-implement automation and is
# not recreated here. `agent_reviewing` is shared with issue-review; created
# here only if it doesn't already exist.

for entry in "${LABELS[@]}"; do
  IFS=":" read -r name color desc <<< "$entry"
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/labels/$name")
  if [ "$status" = "200" ]; then
    echo "  $name -- exists"
  else
    curl -s -o /dev/null \
      -X POST \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      -H "Content-Type: application/json" \
      -d "{\"name\":\"$name\",\"color\":\"$color\",\"description\":\"$desc\"}" \
      "https://api.github.com/repos/$REPO/labels"
    echo "  $name -- created"
  fi
done
echo ""

# --- 2. Tar up the automation code ---

echo "--- Packaging automation tarball ---"
TARBALL="/tmp/pr-review-automation.tar.gz"
# The tarball must contain main.py, AUTOMATION_PROMPT.md, SKILL.md, plan.md
# at the top level (the entrypoint is python3 main.py).
tar -czf "$TARBALL" \
  -C "$SCRIPT_DIR" \
  main.py \
  AUTOMATION_PROMPT.md \
  SKILL.md \
  plan.md
echo "  Created $TARBALL ($(wc -c < "$TARBALL") bytes)"
echo ""

# --- 3. Upload the tarball ---

echo "--- Uploading tarball ---"
UPLOAD_RESPONSE=$(curl -s \
  -X POST \
  -H "X-Session-API-Key: $OPENHANDS_AUTOMATION_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@$TARBALL" \
  "${AUTOMATION_HOST}/api/automation/v1/uploads?name=pr-review-automation&description=PR%20review%20automation")

TARBALL_PATH=$(echo "$UPLOAD_RESPONSE" | jq -r '.tarball_path // empty')
UPLOAD_ID=$(echo "$UPLOAD_RESPONSE" | jq -r '.id // empty')

if [ -z "$TARBALL_PATH" ]; then
  echo "ERROR: Upload failed. Response:"
  echo "$UPLOAD_RESPONSE"
  exit 1
fi
echo "  Upload ID: $UPLOAD_ID"
echo "  Tarball path: $TARBALL_PATH"
echo ""

# --- 4. Create the automation ---

echo "--- Creating automation ---"
EXISTING=$(curl -s \
  -H "X-Session-API-Key: $OPENHANDS_AUTOMATION_API_KEY" \
  "${AUTOMATION_HOST}/api/automation/v1?limit=50")
EXISTING_ID=$(echo "$EXISTING" | jq -r ".automations[]? | select(.name == \"PR Review Automation\") | .id" | head -1)

if [ -n "$EXISTING_ID" ]; then
  echo "  Found existing automation ($EXISTING_ID), updating..."
  RESPONSE=$(curl -s \
    -X PATCH \
    -H "X-Session-API-Key: $OPENHANDS_AUTOMATION_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"tarball_path\": \"$TARBALL_PATH\",
      \"entrypoint\": \"python3 main.py\",
      \"timeout\": 1800
    }" \
    "${AUTOMATION_HOST}/api/automation/v1/${EXISTING_ID}")
else
  echo "  Creating new automation..."
  RESPONSE=$(curl -s \
    -X POST \
    -H "X-Session-API-Key: $OPENHANDS_AUTOMATION_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"PR Review Automation\",
      \"tarball_path\": \"$TARBALL_PATH\",
      \"entrypoint\": \"python3 main.py\",
      \"trigger\": {
        \"type\": \"cron\",
        \"schedule\": \"0 * * * *\",
        \"timezone\": \"UTC\"
      },
      \"timeout\": 1800
    }" \
    "${AUTOMATION_HOST}/api/automation/v1")
fi

AUTOMATION_ID=$(echo "$RESPONSE" | jq -r '.id // empty')

if [ -z "$AUTOMATION_ID" ]; then
  echo "ERROR: Automation creation/update failed. Response:"
  echo "$RESPONSE"
  exit 1
fi

echo "  Automation ID: $AUTOMATION_ID"
echo ""

# --- 5. Summary ---

echo "=== Deployment complete! ==="
echo ""
echo "The automation runs hourly (cron: '0 * * * *')."
echo ""
echo "To use it:"
echo "  1. PRs flow in from issue-implement with 'ready_for_review'."
echo "  2. The automation verifies CI is green and no CHANGES_REQUESTED"
echo "     reviews exist, then starts a review conversation."
echo "  3. The reviewer uses the code-review skill + cross-checks the"
echo "     original issue, then approves, auto-fixes+pushes, or requests"
echo "     changes."
echo "  4. Auto-fixes trigger a full re-review on the next run (countdown:"
echo "     'agent_attempts_remaining_<N>', 3 chances)."
echo "  5. At attempts=0 the PR is labelled 'agent_changes_requested' for a"
echo "     human."
echo ""
echo "Labels created:"
echo "  agent_reviewing              -- claim token (shared with issue-review)"
echo "  agent_attempts_remaining_0/1/2/3 -- review/fix budget (PR-level)"
echo "  agent_reviewed               -- PR approved by the agent"
echo "  agent_changes_requested      -- human takeover"
echo ""
echo "To trigger a manual run now:"
echo "  curl -X POST -H 'X-Session-API-Key: \$OPENHANDS_AUTOMATION_API_KEY' \\"
echo "    ${AUTOMATION_HOST}/api/automation/v1/${AUTOMATION_ID}/dispatch"
echo ""
echo "To view runs:"
echo "  curl -H 'X-Session-API-Key: \$OPENHANDS_AUTOMATION_API_KEY' \\"
echo "    ${AUTOMATION_HOST}/api/automation/v1/${AUTOMATION_ID}/runs"
