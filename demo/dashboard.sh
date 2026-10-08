#!/bin/sh
# Run the SICA dashboard in the background so it keeps running after the
# terminal is closed.
#
#   sh demo/dashboard.sh start    start it (and open the browser)
#   sh demo/dashboard.sh stop     stop it
#   sh demo/dashboard.sh status   is it running?
#
# Output goes to demo/dashboard.log.

DEMO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DEMO")"
PID_FILE="$DEMO/dashboard.pid"
LOG_FILE="$DEMO/dashboard.log"
URL="http://127.0.0.1:${SICA_PORT:-8050}"

if [ -x "$ROOT/.venv/bin/python3" ]; then
    PYTHON="$ROOT/.venv/bin/python3"
else
    PYTHON="python3"
fi

running() {
    [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

case "$1" in
    start)
        if running; then
            echo "Dashboard is already running (PID $(cat "$PID_FILE")): $URL"
            exit 0
        fi
        nohup "$PYTHON" "$DEMO/app.py" > "$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        sleep 2
        if running; then
            echo "Dashboard started (PID $(cat "$PID_FILE")): $URL"
            echo "You can close this terminal. Stop it with: sh demo/dashboard.sh stop"
            open "$URL" 2>/dev/null
        else
            rm -f "$PID_FILE"
            echo "Dashboard failed to start. Last lines of $LOG_FILE:"
            tail -n 5 "$LOG_FILE"
            exit 1
        fi
        ;;
    stop)
        if running; then
            kill "$(cat "$PID_FILE")"
            echo "Dashboard stopped."
        else
            echo "Dashboard is not running."
        fi
        rm -f "$PID_FILE"
        ;;
    status)
        if running; then
            echo "Dashboard is running (PID $(cat "$PID_FILE")): $URL"
        else
            echo "Dashboard is not running."
        fi
        ;;
    *)
        echo "Usage: sh demo/dashboard.sh start|stop|status"
        exit 1
        ;;
esac
