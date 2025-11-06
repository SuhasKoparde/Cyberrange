@echo off
echo ========================================
echo    Cyber Range Setup Script
echo ========================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo Checking Vagrant installation...
vagrant --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Vagrant is not installed
    echo Download from https://www.vagrantup.com/downloads
    echo VMs will not be available without Vagrant
)

echo Checking VirtualBox installation...
VBoxManage --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] VirtualBox is not installed
    echo Download from https://www.virtualbox.org/wiki/Downloads
    echo VMs will not be available without VirtualBox
)

echo.
echo Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Python dependencies
    pause
    exit /b 1
)

echo.
echo ========================================
echo    Setup Complete!
echo ========================================
echo.
echo To start the cyber range:
echo   1. Run: python app.py
echo   2. Open browser to: http://localhost:5000
echo   3. Login with: admin / admin123
echo.
echo To deploy VMs (optional):
echo   python scripts/vm_manager.py deploy
echo.
pause
