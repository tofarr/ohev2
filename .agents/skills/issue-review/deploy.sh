#!/usr/bin/env bash
# Deploy the issue-review automation.
#
# This script:
# 1. Creates the required GitHub labels (if missing).
# 2. Tars up the automation code (.agents/skills/issue-review/).
# 3. Uploads the tarball to the automation service.
# 4. Creates the cron automation pointing at the uploaded tarball.
#
# Prerequisites:
#   - GITHUB_TOKEN env var (with repo scope for the target repo)
#   - OPENHANDS_AUTOMATION_API_KEY env var (for the automation service)
#   - curl, jq, tar
#
# Usage:
#   bash deploy.sh
#
# After deployment, label issues with `ready_for_agent_review` (optionally
# `auto_refine_3`) to have them reviewed on the next hourly run.

set -euo pipefail

REPO="${OHE_REPO:-tofarr/ohev2}"
AUTOMATION_HOST="${OPENHANDS_HOST:-http://127.0.0.1:8000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Issue Review Automation Deployment ==="
echo "Repo: $REPO"
echo "Automation host: $AUTOMATION_HOST"
echo ""

# --- 1. Create GitHub labels ---

echo "--- Creating GitHub labels ---"
LABELS=(
  "ready_for_agent_review:3B82F6:Pending agent review"
  "agent_reviewing:F59E0B:Currently being reviewed by an agent"
  "agent_approved:22C55E:Approved for agent implementation"
  "needs_refinement:EF4444:Needs human refinement"
  "auto_refine_1:8B5CF6:Auto-refine budget: 1 remaining"
  "auto_refine_2:8B5CF6:Auto-refine budget: 2 remaining"
  "auto_refine_3:8B5CF6:Auto-refine budget: 3 remaining"
)

for entry in "${LABELS[@]}"; do
  IFS=":" read -r name color desc <<< "$entry"
  # Check if label exists
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
TARBALL="/tmp/issue-review-automation.tar.gz"
# The tarball must contain main.py, AUTOMATION_PROMPT.md, and SKILL.md
# at the top level (the entrypoint is python3 main.py).
tar -czf "$TARBALL" \
  -C "$SCRIPT_DIR" \
  main.py \
  AUTOMATION_PROMPT.md \
  SKILL.md
echo "  Created $TARBALL ($(wc -c < "$TARBALL") bytes)"
echo ""

# --- 3. Upload the tarball ---

echo "--- Uploading tarball ---"
UPLOAD_RESPONSE=$(curl -s \
  -X POST \
  -H "X-Session-API-Key: $OPENHANDS_AUTOMATION_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary "@$TARBALL" \
  "${AUTOMATION_HOST}/api/automation/v1/uploads?name=issue-review-automation&description=Issue%20review%20and%20refinement%20automation")

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
# Check if an automation with this name already exists
EXISTING=$(curl -s \
  -H "X-Session-API-Key: $OPENHANDS_AUTOMATION_API_KEY" \
  "${AUTOMATION_HOST}/api/automation/v1?limit=50")
EXISTING_ID=$(echo "$EXISTING" | jq -r ".automations[]? | select(.name == \"Issue Review Automation\") | .id" | head -1)

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
      \"name\": \"Issue Review Automation\",
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
echo "  1. Label issues with 'ready_for_agent_review' to queue them."
echo "  2. Optionally add 'auto_refine_3' to give the agent 3 refinement"
echo "     attempts before escalating to 'needs_refinement'."
echo "  3. Without an auto_refine_N label, a failing issue goes straight"
echo "     to 'needs_refinement' (single iteration)."
echo ""
echo "Labels created:"
echo "  ready_for_agent_review  -- queue for review"
echo "  agent_reviewing         -- in-flight (claim token)"
echo "  agent_approved          -- passed review"
echo "  needs_refinement        -- failed, needs human"
echo "  auto_refine_1/2/3       -- refinement budget"
echo ""
echo "To trigger a manual run now:"
echo "  curl -X POST -H 'X-Session-API-Key: \$OPENHANDS_AUTOMATION_API_KEY' \\"
echo "    ${AUTOMATION_HOST}/api/automation/v1/${AUTOMATION_ID}/dispatch"
echo ""
echo "To view runs:"
echo "  curl -H 'X-Session-API-Key: \$OPENHANDS_AUTOMATION_API_KEY' \\"
echo "    ${AUTOMATION_HOST}/api/automation/v1/${AUTOMATION_ID}/runs"
