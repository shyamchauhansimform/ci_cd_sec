#!/usr/bin/env bash
# pre-tool-log.sh
# Called by the PreToolUse hook in .claude/settings.json.
# Reads a JSON payload from stdin and appends a [PRE_TOOL] entry to the tool
# execution log. Also writes a [SESSION_START] entry to the session audit log
# the first time this session ID appears.
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

# Write SESSION_START once per session (first time this session ID appears)
SESSION_LOG="$LOG_DIR/session-audit.log"
if ! grep -qsF "session=$SESSION" "$SESSION_LOG" 2>/dev/null; then
  echo "[$TS] [SESSION_START] session=$SESSION agent=copilot-coding-agent" >> "$SESSION_LOG"
fi

echo "[$TS] [PRE_TOOL] tool=$TOOL session=$SESSION" >> "$LOG_DIR/tool-executions.log"
