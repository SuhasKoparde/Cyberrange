@echo off
echo Creating VM-ready Cyber Range Package...
echo.

REM Create the offline package
python offline_setup.py

echo.
echo Creating VM deployment archive...

REM Create a compressed package for easy VM transfer
if exist "CyberRange_VM_Package.zip" del "CyberRange_VM_Package.zip"

REM Use PowerShell to create zip (available on Windows 10+)
powershell -Command "Compress-Archive -Path 'offline_deployment' -DestinationPath 'CyberRange_VM_Package.zip'"

echo.
echo [SUCCESS] VM package created successfully!
echo.
echo Package file: CyberRange_VM_Package.zip
echo Folder: offline_deployment\
echo.
echo To deploy in VM:
echo 1. Copy CyberRange_VM_Package.zip to your VM
echo 2. Extract the zip file
echo 3. Run setup.bat in the extracted folder
echo 4. Run start.bat to launch cyber range
echo.
echo Access: http://localhost:5000
echo Login: admin / admin123
echo.
pause
