#!/usr/bin/env bash
# session-log.sh
# Called by the Stop hook in .claude/settings.json.
# Reads a JSON payload from stdin and appends a [SESSION_END] entry to the
# session audit log.
set -euo pipefail

LOG_DIR=".github/logs"
mkdir -p "$LOG_DIR"

INPUT=$(cat)

SESSION=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('session_id','unknown'))" \
  2>/dev/null || echo "unknown")

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[$TS] [SESSION_END] session=$SESSION agent=copilot-coding-agent" >> "$LOG_DIR/session-audit.log"
