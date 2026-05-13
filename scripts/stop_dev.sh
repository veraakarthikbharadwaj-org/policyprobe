#!/bin/bash
#
# PolicyProbe Development Server Stop Script
#
# This script stops both the frontend and backend servers.
# Run from anywhere: ./scripts/stop_dev.sh
#

printf '==========================================\n'
printf '  Stopping PolicyProbe Servers\n'
printf '==========================================\n'
printf '\n'

# Helper: gracefully stop a process listening on a given port
stop_port() {
    local port="$1"
    local label="$2"
    # Use fuser to find and signal the process; prefer SIGTERM, then SIGKILL
    if fuser "${port}/tcp" > /dev/null 2>&1; then
        fuser -k -TERM "${port}/tcp" > /dev/null 2>&1
        sleep 1
        # If still running, escalate to SIGKILL
        if fuser "${port}/tcp" > /dev/null 2>&1; then
            fuser -k -KILL "${port}/tcp" > /dev/null 2>&1
        fi
        printf 'Stopped: %s (port %s)\n' "$label" "$port"
    else
        printf 'Not running: %s (port %s)\n' "$label" "$port"
    fi
}

# Stop backend on port 5500
stop_port 5500 "Backend"

# Stop frontend on port 5001
stop_port 5001 "Frontend"

printf '\n'
printf '==========================================\n'
printf '  All servers stopped\n'
printf '==========================================\n'
