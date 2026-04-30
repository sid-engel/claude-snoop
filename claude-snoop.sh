#!/usr/bin/env bash
# claude-snoop — entry point
# Kicks off Claude Code with the orchestration instructions

set -e

usage() {
  echo "Usage: $0 --target <IP/subnet> [--title <title>] [--workers N] [--external true|false] [--root true|false]"
  echo ""
  echo "Required:"
  echo "  --target <IP/subnet>     Target IP, range, or subnet"
  echo ""
  echo "Optional:"
  echo "  --title <title>          Report title (default: 'Network Audit — <TARGET>')"
  echo "  --workers <N>            Parallel port scan workers (default: 4)"
  echo "  --external true|false    Scan public IP for open ports (default: true)"
  echo "  --root true|false        Enable OS detection with nmap -O flag (default: false, requires root)"
  echo ""
  echo "Examples:"
  echo "  $0 --target 192.168.1.0/24"
  echo "  $0 --target 192.168.1.0/24 --title 'Acme Corp' --workers 8"
  echo "  $0 --target 192.168.1.0/24 --external false"
  echo "  sudo $0 --target 192.168.1.0/24 --root true"
  exit 1
}

TARGET=""
TITLE=""
WORKERS="4"
EXTERNAL="true"
ROOT="false"

while [[ $# -gt 0 ]]; do
  case $1 in
    --target)   TARGET="$2"; shift 2 ;;
    --title)    TITLE="$2"; shift 2 ;;
    --workers)  WORKERS="$2"; shift 2 ;;
    --external) EXTERNAL="$2"; shift 2 ;;
    --root)     ROOT="$2"; shift 2 ;;
    -h|--help)  usage ;;
    *)          echo "Unknown argument: $1"; usage ;;
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
echo "   Target   : $TARGET"
echo "   Title    : $TITLE"
echo "   Workers  : $WORKERS"
echo "   External : $EXTERNAL"
echo "   Root/OS  : $ROOT"
echo ""

# Hand off to Claude Code — it reads CLAUDE.md and takes it from here
claude "Run a full claude-snoop audit. Target: $TARGET. Report title: $TITLE. Workers: $WORKERS. External scan: $EXTERNAL. Root mode: $ROOT. Follow the instructions in CLAUDE.md."
