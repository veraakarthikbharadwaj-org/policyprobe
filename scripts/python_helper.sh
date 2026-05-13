#!/bin/bash
#
# Python Version Detection Helper
#
# This script finds a suitable Python interpreter (3.10+) and exports PYTHON_CMD.
# Source this script from other scripts: source "$(dirname "${BASH_SOURCE[0]}")/python_helper.sh"
#
# Override with: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh
#

# Minimum required Python version
PYTHON_MIN_MAJOR=3
PYTHON_MIN_MINOR=10

# Function to check if a Python version meets minimum requirements
check_python_version() {
    local python_cmd="$1"

    # Check if command exists
    if ! command -v "$python_cmd" &> /dev/null; then
        return 1
    fi

    # Get version and validate
    local version_output
    version_output=$("$python_cmd" --version 2>&1) || return 1

    # Parse version (e.g., "Python 3.12.1" -> "3.12.1")
    local version
    version=$(echo "$version_output" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [ -z "$version" ]; then
        return 1
    fi

    # Extract major and minor versions
    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    # Check if version meets minimum
    if [ "$major" -gt "$PYTHON_MIN_MAJOR" ]; then
        return 0
    elif [ "$major" -eq "$PYTHON_MIN_MAJOR" ] && [ "$minor" -ge "$PYTHON_MIN_MINOR" ]; then
        return 0
    fi

    return 1
}

# Function to find a suitable Python interpreter
find_python() {
    # Allow override via environment variable
    if [ -n "$PYTHON_PATH" ]; then
        if check_python_version "$PYTHON_PATH"; then
            echo "$PYTHON_PATH"
            return 0
        else
            echo "ERROR: PYTHON_PATH ($PYTHON_PATH) does not meet minimum version requirement (Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+)" >&2
            return 1
        fi
    fi

    # List of Python commands to try (prefer newer versions)
    local python_candidates=(
        "python3"
        "python3.14"
        "python3.13"
        "python3.12"
        "python3.11"
        "python3.10"
        "python"
    )

    for cmd in "${python_candidates[@]}"; do
        if check_python_version "$cmd"; then
            echo "$cmd"
            return 0
        fi
    done

    return 1
}

# Main: Find and # HITL approval gate: require explicit confirmation before exporting and applying PYTHON_CMD
if [ "${PYTHON_HELPER_AUTO_APPROVE:-0}" != "1" ]; then
    echo "------------------------------------------"
    echo "  HITL Approval Required"
    echo "------------------------------------------"
    echo "  The following operation is about to be performed:"
    echo "    export PYTHON_CMD=$PYTHON_CMD"
    echo ""
    printf "  Do you approve this operation? [y/N]: "
    read -r HITL_RESPONSE
    case "$HITL_RESPONSE" in
        [yY][eE][sS]|[yY])
            : # approved
            ;;
        *)
            echo "  Operation cancelled by user (HITL approval denied)." >&2
            exit 1
            ;;
    esac
    echo "------------------------------------------"
fi

export PYTHON_CMD

# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    echo "Using: $PYTHON_VERSION ($PYTHON_CMD)"
find_python)

if [ -z "$PYTHON_CMD" ]; then
    echo "=========================================="
    echo "  ERROR: No suitable Python found!"
    echo "=========================================="
    echo ""
    echo "  This project requires Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR} or newer."
    echo ""
    echo "  Options:"
    echo "    1. Install Python ${PYTHON_MIN_MAJOR}.${PYTHON_MIN_MINOR}+ from https://python.org"
    echo "    2. Use pyenv: pyenv install 3.12"
    echo "    3. Specify a Python path: PYTHON_PATH=/path/to/python ./scripts/setup_env.sh"
    echo ""
    echo "=========================================="
    exit 1
fi

# Sanitize PYTHON_CMD: allow only safe filesystem path characters before exporting
if [[ ! "$PYTHON_CMD" =~ ^[a-zA-Z0-9/_.-]+$ ]]; then
    echo "ERROR: PYTHON_CMD contains unsafe characters and will not be exported." >&2
    exit 1
fi
export PYTHON_CMD

# Display found Python version (only if not being sourced silently)
if [ "${PYTHON_HELPER_QUIET:-0}" != "1" ]; then
    PYTHON_VERSION=$("$PYTHON_CMD" --version 2>&1)
    # Sanitize version string: allow only alphanumeric, spaces, dots, and parentheses
    PYTHON_VERSION_SAFE=$(printf '%s' "$PYTHON_VERSION" | tr -cd 'a-zA-Z0-9 ._()-')
    PYTHON_CMD_SAFE=$(printf '%s' "$PYTHON_CMD" | tr -cd 'a-zA-Z0-9/_.-')
    echo "Using: $PYTHON_VERSION_SAFE ($PYTHON_CMD_SAFE)"
fi
