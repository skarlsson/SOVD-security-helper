#!/bin/bash
# =============================================================================
# Stop SOVD Security Helper
#
# Reads the PID file written by start.sh and kills exactly those processes.
# Safe to run even if the helper is not running.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/.pids"

# -- Colors -------------------------------------------------------------------
_GREEN='\033[0;32m'
_YELLOW='\033[1;33m'
_BLUE='\033[0;34m'
_NC='\033[0m'

info()  { echo -e "${_BLUE}[INFO]${_NC} $1"; }
ok()    { echo -e "${_GREEN}[ OK ]${_NC} $1"; }
warn()  { echo -e "${_YELLOW}[WARN]${_NC} $1"; }

# -- Stop ---------------------------------------------------------------------
if [[ ! -f "$PID_FILE" ]]; then
    warn "No PID file found at $PID_FILE — nothing to stop."
    exit 0
fi

info "Reading PIDs from $PID_FILE"

# SIGTERM first
while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    if kill -0 "$pid" 2>/dev/null; then
        info "Stopping PID $pid"
        kill "$pid" 2>/dev/null || true
    fi
done < "$PID_FILE"

sleep 1

# SIGKILL stragglers
while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    if kill -0 "$pid" 2>/dev/null; then
        warn "Force killing PID $pid"
        kill -9 "$pid" 2>/dev/null || true
    fi
done < "$PID_FILE"

rm -f "$PID_FILE"
ok "Security helper stopped"
