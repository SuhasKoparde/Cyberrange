#!/bin/bash
# Kali Linux deployment helper script (run as a normal user)
# Usage: sudo ./deploy/kali_deploy.sh or run commands manually
set -euo pipefail

# Adjust these variables as needed
APP_DIR="$PWD"
VENV_DIR="$APP_DIR/venv"
PYTHON=python3

echo "Updating apt and installing packages..."
sudo apt update
sudo apt install -y git ${PYTHON}-venv ${PYTHON}-dev build-essential libssl-dev libffi-dev python3-pip

# Create virtualenv if missing
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtualenv..."
  $PYTHON -m venv "$VENV_DIR"
fi

# Activate and install requirements
echo "Activating virtualenv and installing Python packages..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
pip install -r requirements.txt

# Run database initialization if provided
if [ -f ./init_challenges.py ]; then
  echo "Initializing challenges/database..."
  python init_challenges.py || true
fi

# Start via gunicorn (recommended for Linux)
echo "Starting application with gunicorn on port 8000..."
# ensure gunicorn is installed
pip install gunicorn

# This uses 3 workers; adjust bind address/port as needed
gunicorn --workers 3 --bind 0.0.0.0:8000 app:app &

echo "Application started on port 8000 (background)."

# Deactivate venv and exit
deactivate || true

exit 0
