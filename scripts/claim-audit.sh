#!/bin/sh
set -eu

if rg -ni 'not yet a completed security audit|campaign proceeds|campaign in progress|later module|BH[0-9]+.*planned' README.md docs content templates HARDENING-CHECKPOINTS.md; then
  echo "stale campaign or product claim found" >&2
  exit 1
fi
echo "warden claim audit: ok"
