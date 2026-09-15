@echo off
REM Double-click to open ai-session-monitor. If the dashboard is already running
REM on 127.0.0.1:8787 it just opens the browser; otherwise it starts the daemon
REM windowless (pythonw, same as the production daemon) and then opens the browser.
cd /d "%~dp0"
powershell -NoProfile -Command "try { Invoke-WebRequest -Uri 'http://127.0.0.1:8787/' -UseBasicParsing -TimeoutSec 2 | Out-Null; exit 0 } catch { exit 1 }"
if %errorlevel%==0 goto open
start "" pythonw monitor.py
timeout /t 3 >nul
:open
start "" "http://127.0.0.1:8787"
