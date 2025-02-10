#!/bin/bash

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BACKEND_DIR="$(dirname "$SCRIPT_DIR")"

# Activate virtual environment
source "$BACKEND_DIR/venv/bin/activate"

# Run the Python script with all arguments passed to this script
python "$SCRIPT_DIR/export_resources.py" "$@"

# Deactivate virtual environment
deactivate
