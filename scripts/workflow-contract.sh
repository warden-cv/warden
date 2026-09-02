#!/bin/sh
# Structurally validates the read-only CI workflow so the required triggers,
# permissions, and gates cannot silently disappear from .github/workflows/ci.yml.
# Runs as a CI step so a regression fails the pipeline. Direct, unmasked: every
# grep propagates its failure through set -e.
set -eu

W=.github/workflows/ci.yml
[ -f "$W" ] || { echo "missing $W" >&2; exit 1; }

grep -q 'on:' "$W"
grep -q 'push:' "$W"
grep -q 'pull_request:' "$W"
grep -q 'permissions:' "$W"
grep -q 'contents: read' "$W"

check() {
  grep -Fq "$1" "$W" || { echo "workflow gate missing: $1" >&2; exit 1; }
}

check 'gofmt -l'
check 'go vet ./...'
check 'go test ./...'
check 'go test -race ./...'
check 'go build -trimpath'
check 'node --check content/assets/js/script.js'
check 'node --check public/assets/js/script.js'
check 'tests/agent-ux.test.js'
check 'tests/markdown-render-smoke.js'
check 'tests/frontend-security-smoke.js'
check 'diff -q content/assets/js/script.js public/assets/js/script.js'
check 'diff -q content/assets/css/style.css public/assets/css/style.css'
check 'workflow-contract.sh'
check 'git-history-hygiene.sh'

echo "ci workflow contract: ok"