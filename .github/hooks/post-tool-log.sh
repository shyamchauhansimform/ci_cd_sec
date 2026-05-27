#!/usr/bin/env bash
# post-tool-log.sh
# Called by the PostToolUse hook in .claude/settings.json.
# Reads a JSON payload from stdin and appends a [POST_TOOL] entry to the tool
# execution log.
set -euo pipefail

LOG_DIR=".github/logs"
mkdir -p "$LOG_DIR"

INPUT=$(cat)

TOOL=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name','unknown'))" \
  2>/dev/null || echo "unknown")

SESSION=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('session_id','unknown'))" \
  2>/dev/null || echo "unknown")

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[$TS] [POST_TOOL] tool=$TOOL session=$SESSION" >> "$LOG_DIR/tool-executions.log"
