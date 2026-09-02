#!/bin/sh
# Regression fixture: the hardened contract validator must reject weakened
# copies of the CI workflow. All mutations operate on temporary copies created
# with mktemp; the real .github/workflows/ci.yml is never modified.
set -eu

V=scripts/workflow-contract.sh
BASE=.github/workflows/ci.yml

"$V" "$BASE" || { echo "real workflow rejected by contract" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

expect_reject() {
  name=$1
  file=$2
  if "$V" "$file" >/dev/null 2>&1; then
    echo "contract accepted weakened workflow: $name" >&2
    exit 1
  fi
}

# 1. Comment out the agent UX run: line, leaving its text inside a comment.
sed 's|^[[:space:]]*run: node tests/agent-ux\.test\.js$|#&|' "$BASE" > "$tmp/m1.yml"
expect_reject "agent UX run commented out" "$tmp/m1.yml"

# 2. Elevate contents: read to contents: write.
sed 's|contents: read|contents: write|' "$BASE" > "$tmp/m2.yml"
expect_reject "contents write permission" "$tmp/m2.yml"

# 3. Replace one pinned action SHA with a mutable tag.
sed 's|actions/checkout@[0-9a-f]\{40\}|actions/checkout@v4|' "$BASE" > "$tmp/m3.yml"
expect_reject "mutable action tag" "$tmp/m3.yml"

# 4. Remove the pull_request trigger.
sed '/^[[:space:]]*pull_request:[[:space:]]*$/d' "$BASE" > "$tmp/m4.yml"
expect_reject "pull_request trigger removed" "$tmp/m4.yml"

# 5. Remove one command from the generated-asset parity block.
sed '/^[[:space:]]*diff -q content\/assets\/css\/style\.css public\/assets\/css\/style\.css$/d' "$BASE" > "$tmp/m5.yml"
expect_reject "parity command removed" "$tmp/m5.yml"

echo "ci workflow contract mutation tests: ok"