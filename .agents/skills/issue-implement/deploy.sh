#!/usr/bin/env bash
# Deploy the issue-implement automation.
#
# This script:
# 1. Creates the required GitHub labels (if missing).
# 2. Tars up the automation code (.agents/skills/issue-implement/).
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
# After deployment, label issues with `agent_approved` (from issue-review) AND
# `ready_for_implementation` (manually) to have them implemented on the next
# hourly run.

set -euo pipefail

REPO="${OHE_REPO:-tofarr/ohev2}"
AUTOMATION_HOST="${OPENHANDS_HOST:-http://127.0.0.1:8000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Issue Implement Automation Deployment ==="
echo "Repo: $REPO"
echo "Automation host: $AUTOMATION_HOST"
echo ""

# --- 1. Create GitHub labels ---

echo "--- Creating GitHub labels ---"
LABELS=(
  "ready_for_implementation:22C55E:Manually applied: ready for agent implementation"
  "agent_remaining_attempts_0:EF4444:Retry budget exhausted"
  "agent_remaining_attempts_1:F59E0B:1 retry remaining"
  "agent_remaining_attempts_2:F59E0B:2 retries remaining"
  "agent_remaining_attempts_3:3B82F6:3 retries remaining (initial)"
  "agent_generated:8B5CF6:PR opened by an agent"
  "ready_for_review:10B981:PR ready for human review"
)
# NOTE: `agent_approved` is owned by the issue-review automation and is not
# recreated here.

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
TARBALL="/tmp/issue-implement-automation.tar.gz"
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
  "${AUTOMATION_HOST}/api/automation/v1/uploads?name=issue-implement-automation&description=Issue%20implementation%20automation")

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
EXISTING_ID=$(echo "$EXISTING" | jq -r ".automations[]? | select(.name == \"Issue Implement Automation\") | .id" | head -1)

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
      \"name\": \"Issue Implement Automation\",
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
echo "  1. Issues flow in from issue-review with 'agent_approved'."
echo "  2. A human adds 'ready_for_implementation' to queue implementation."
echo "  3. The automation starts a conversation, posts a marker comment,"
echo "     and retries up to 3 times on failure (decrementing"
echo "     'agent_remaining_attempts_<N>')."
echo "  4. At attempts=0 it removes 'ready_for_implementation' and posts a"
echo "     'gave up' comment for a human."
echo ""
echo "Labels created:"
echo "  ready_for_implementation  -- queue for implementation (human-applied)"
echo "  agent_remaining_attempts_0/1/2/3 -- retry budget (issue-level)"
echo "  agent_generated           -- PR opened by an agent (PR-level)"
echo "  ready_for_review          -- PR ready for human review (PR-level)"
echo ""
echo "To trigger a manual run now:"
echo "  curl -X POST -H 'X-Session-API-Key: \$OPENHANDS_AUTOMATION_API_KEY' \\"
echo "    ${AUTOMATION_HOST}/api/automation/v1/${AUTOMATION_ID}/dispatch"
echo ""
echo "To view runs:"
echo "  curl -H 'X-Session-API-Key: \$OPENHANDS_AUTOMATION_API_KEY' \\"
echo "    ${AUTOMATION_HOST}/api/automation/v1/${AUTOMATION_ID}/runs"
