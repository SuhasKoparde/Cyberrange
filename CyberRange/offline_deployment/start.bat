@echo off
echo Starting Offline Cyber Range...
echo.
echo Opening browser to http://localhost:5000
echo Login: admin / admin123
echo.
echo Press Ctrl+C to stop the server
echo.

start http://localhost:5000
python offline_app.py
