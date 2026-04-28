#!/usr/bin/env bash
# claude-snoop — entry point
# Kicks off Claude Code with the orchestration instructions

set -e

usage() {
  echo "Usage: $0 --target <IP/subnet> [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --target <IP/subnet>     Target IP, range, or subnet (required)"
  echo "  --title <title>          Report title (default: 'Network Audit — <TARGET>')"
  echo "  --workers <N>            Parallel port scan workers (default: 4)"
  echo ""
  echo "Examples:"
  echo "  $0 --target 192.168.1.0/24"
  echo "  $0 --target 192.168.1.0/24 --title 'Acme Corp' --workers 8"
  exit 1
}

TARGET=""
TITLE=""
WORKERS="4"

while [[ $# -gt 0 ]]; do
  case $1 in
    --target)  TARGET="$2"; shift 2 ;;
    --title)   TITLE="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
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
echo "   Target  : $TARGET"
echo "   Title   : $TITLE"
echo "   Workers : $WORKERS"
echo ""

# Hand off to Claude Code — it reads CLAUDE.md and takes it from here
claude "Run a full claude-snoop audit. Target: $TARGET. Report title: $TITLE. Workers: $WORKERS. Follow the instructions in CLAUDE.md."
