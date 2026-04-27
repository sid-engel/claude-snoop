#!/usr/bin/env bash
# claude-snoop — entry point
# Kicks off Claude Code with the orchestration instructions

set -e

usage() {
  echo "Usage: $0 --target <IP/subnet> [--title <report title>]"
  echo ""
  echo "Examples:"
  echo "  $0 --target 192.168.1.0/24"
  echo "  $0 --target 192.168.1.0/24 --title 'Acme Corp'"
  exit 1
}

TARGET=""
TITLE=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --target) TARGET="$2"; shift 2 ;;
    --title)  TITLE="$2";  shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "[error] --target is required"
  usage
fi

if [[ -z "$TITLE" ]]; then
  TITLE="Network Audit — $TARGET"
fi

# Check dependencies
if ! command -v nmap &>/dev/null; then
  echo "[error] nmap is not installed or not in PATH"
  exit 1
fi

if ! command -v claude &>/dev/null; then
  echo "[error] Claude Code is not installed or not in PATH"
  exit 1
fi

mkdir -p output

echo "🐾 claude-snoop"
echo "   Target : $TARGET"
echo "   Title  : $TITLE"
echo ""

# Hand off to Claude Code — it reads CLAUDE.md and takes it from here
claude --print "Run a full claude-snoop audit. Target: $TARGET. Report title: $TITLE. Follow the instructions in CLAUDE.md."
