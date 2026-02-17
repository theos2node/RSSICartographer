#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/theos2node/RSSICartographer.git"
TMP_BASE="${TMPDIR:-/tmp}"
WORK_DIR="${TMP_BASE%/}/rssicartographer-$(date +%s)"

cleanup() {
  if [[ -d "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR"
  fi
}

trap cleanup EXIT

git clone --depth 1 "$REPO_URL" "$WORK_DIR" >/dev/null 2>&1
cd "$WORK_DIR"
./run.sh "$@"
