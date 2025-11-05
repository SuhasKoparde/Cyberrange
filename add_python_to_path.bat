@echo off
echo ========================================
echo    Adding Python to PATH
echo ========================================
echo.

echo Searching for Python installation...

:: Common Python installation paths
set "PYTHON_PATHS=C:\Python* C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python* C:\Program Files\Python* C:\Program Files (x86)\Python*"

for %%p in (%PYTHON_PATHS%) do (
    if exist "%%p\python.exe" (
        echo Found Python at: %%p
        set "PYTHON_DIR=%%p"
        goto :found
    )
)

echo [ERROR] Python installation not found in common locations.
echo Please check where Python is installed and run this manually:
echo   setx PATH "%%PATH%%;C:\path\to\python"
pause
exit /b 1

:found
echo.
echo Adding Python to PATH...
setx PATH "%PATH%;%PYTHON_DIR%" >nul 2>&1
setx PATH "%PATH%;%PYTHON_DIR%\Scripts" >nul 2>&1

echo.
echo ========================================
echo    PATH Updated Successfully!
echo ========================================
echo.
echo Python has been added to your PATH.
echo Please CLOSE this window and open a NEW PowerShell window.
echo Then run: python --version
echo.
pause
