#!/bin/bash

# IP Address Checker - macOS Shell Wrapper
# Makes it easy to run the Python checker from terminal

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/ip_checker.py"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 first."
    echo "Install via: brew install python3"
    exit 1
fi

# Check if the Python script exists
if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Error: ip_checker.py not found in $SCRIPT_DIR"
    exit 1
fi

# Run the Python script with all passed arguments
python3 "$PYTHON_SCRIPT" "$@"
