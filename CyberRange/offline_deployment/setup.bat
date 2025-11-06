@echo off
echo Installing Offline Cyber Range...
echo.

REM Check Python installation
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Python found, installing dependencies...
pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Installation complete!
echo.
echo To start the cyber range:
echo   python offline_app.py
echo.
echo Then open your browser to: http://localhost:5000
echo Login: admin / admin123
echo.
pause
