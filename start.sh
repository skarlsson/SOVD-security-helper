#!/bin/bash
# =============================================================================
# Start SOVD Security Helper
#
# Builds (if needed), launches the helper service, and cleans up on Ctrl+C.
# PID is recorded in logs/.pids so stop.sh can kill it cleanly.
#
# Usage: ./start.sh [--port PORT] [--token TOKEN] [--config PATH]
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
PID_FILE="$LOG_DIR/.pids"
BIN="$SCRIPT_DIR/target/debug/sovd-security-helper"

# Defaults
PORT="${PORT:-9100}"
TOKEN="${SOVD_HELPER_TOKEN:-dev-secret-123}"
CONFIG="$SCRIPT_DIR/config/secrets.toml"

# -- Colors -------------------------------------------------------------------
_RED='\033[0;31m'
_GREEN='\033[0;32m'
_YELLOW='\033[1;33m'
_BLUE='\033[0;34m'
_NC='\033[0m'

info()  { echo -e "${_BLUE}[INFO]${_NC} $1"; }
ok()    { echo -e "${_GREEN}[ OK ]${_NC} $1"; }
warn()  { echo -e "${_YELLOW}[WARN]${_NC} $1"; }
error() { echo -e "${_RED}[ERR ]${_NC} $1"; }

# -- Parse CLI overrides (passthrough to the binary) -------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)   PORT="$2";   shift 2 ;;
        --token)  TOKEN="$2";  shift 2 ;;
        --config) CONFIG="$2"; shift 2 ;;
        *) error "Unknown arg: $1"; exit 1 ;;
    esac
done

# -- Stop stale instance if PID file exists -----------------------------------
if [[ -f "$PID_FILE" ]]; then
    warn "Stale PID file found — cleaning up previous instance"
    "$SCRIPT_DIR/stop.sh"
fi

# -- Build if needed ----------------------------------------------------------
if [[ ! -f "$BIN" ]]; then
    info "Binary not found, building..."
    (cd "$SCRIPT_DIR" && cargo build)
fi

# -- Prepare log dir ----------------------------------------------------------
mkdir -p "$LOG_DIR"

# -- Cleanup handler ----------------------------------------------------------
cleanup() {
    echo ""
    info "Shutting down security helper..."

    if [[ -f "$PID_FILE" ]]; then
        while IFS= read -r pid; do
            [[ -z "$pid" ]] && continue
            if kill -0 "$pid" 2>/dev/null; then
                info "Stopping PID $pid"
                kill "$pid" 2>/dev/null || true
            fi
        done < "$PID_FILE"

        sleep 1

        while IFS= read -r pid; do
            [[ -z "$pid" ]] && continue
            if kill -0 "$pid" 2>/dev/null; then
                warn "Force killing PID $pid"
                kill -9 "$pid" 2>/dev/null || true
            fi
        done < "$PID_FILE"

        rm -f "$PID_FILE"
    fi

    ok "Security helper stopped"
}

trap cleanup SIGINT SIGTERM EXIT

# -- Start --------------------------------------------------------------------
info "Starting SOVD Security Helper on port $PORT..."
"$BIN" --port "$PORT" --token "$TOKEN" --config "$CONFIG" \
    > "$LOG_DIR/helper.log" 2>&1 &
HELPER_PID=$!

echo "$HELPER_PID" > "$PID_FILE"

# Wait a moment and verify it started
sleep 0.5
if ! kill -0 "$HELPER_PID" 2>/dev/null; then
    error "Helper failed to start. Check: $LOG_DIR/helper.log"
    rm -f "$PID_FILE"
    exit 1
fi

# -- Status banner ------------------------------------------------------------
echo ""
echo "=============================================="
echo -e "${_GREEN}Security Helper Running${_NC}"
echo "=============================================="
echo ""
echo "  URL:    http://localhost:$PORT"
echo "  Token:  ${TOKEN:0:4}..."
echo "  Config: $CONFIG"
echo "  PID:    $HELPER_PID"
echo ""
echo "  Test:"
echo "    curl http://localhost:$PORT/info"
echo "    curl -X POST http://localhost:$PORT/calculate \\"
echo "      -H 'Authorization: Bearer $TOKEN' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"seed\":\"aabbccdd\",\"level\":1,\"ecu_type\":\"engine\",\"algorithm\":\"xor\"}'"
echo ""
echo "  Logs: $LOG_DIR/helper.log"
echo ""
echo "  Press Ctrl+C to stop"
echo "=============================================="

# -- Wait (exit if process dies) ----------------------------------------------
while true; do
    sleep 2
    if ! kill -0 "$HELPER_PID" 2>/dev/null; then
        error "Helper process died unexpectedly"
        exit 1
    fi
done
