#!/bin/bash
# Kali Linux deployment helper script (run as a normal user)
# Usage: sudo ./deploy/kali_deploy.sh or run commands manually
set -euo pipefail

# Adjust these variables as needed
APP_DIR="$PWD"
VENV_DIR="$APP_DIR/venv"
PYTHON=python3

echo "=========================================="
echo "CyberRange Deployment Script"
echo "=========================================="
echo ""

echo "[1/6] Updating apt and installing packages..."
sudo apt update
sudo apt install -y git ${PYTHON}-venv ${PYTHON}-dev build-essential libssl-dev libffi-dev python3-pip

# Create virtualenv if missing
if [ ! -d "$VENV_DIR" ]; then
  echo "[2/6] Creating virtualenv..."
  $PYTHON -m venv "$VENV_DIR"
else
  echo "[2/6] Virtual environment already exists"
fi

# Activate and install requirements
echo "[3/6] Installing Python packages..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "[4/6] Initializing database and creating challenges..."
# Run database initialization - THIS IS CRITICAL FOR SETUP
if [ -f ./init_challenges.py ]; then
  python init_challenges.py
  if [ $? -eq 0 ]; then
    echo "✓ Challenges initialized successfully"
  else
    echo "✗ Failed to initialize challenges"
    exit 1
  fi
fi

# Run guide population
echo "[5/6] Populating challenge execution guides..."
if [ -f ./populate_challenge_guides.py ]; then
  python populate_challenge_guides.py
  if [ $? -eq 0 ]; then
    echo "✓ Challenge guides populated successfully"
  else
    echo "✗ Failed to populate guides"
    exit 1
  fi
fi

# Start via gunicorn (recommended for Linux)
echo "[6/6] Starting application with gunicorn on port 8000..."
pip install gunicorn

echo ""
echo "=========================================="
echo "✓ Deployment Complete!"
echo "=========================================="
echo ""
echo "Application is starting on port 8000..."
echo "Access it at: http://localhost:8000"
echo ""
echo "Default Credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Starting Gunicorn server..."
echo "This uses 3 workers; adjust bind address/port as needed"
echo ""

# This uses 3 workers; adjust bind address/port as needed
gunicorn --workers 3 --bind 0.0.0.0:8000 --access-logfile - app:app

# Note: gunicorn runs in foreground; use Ctrl+C to stop
