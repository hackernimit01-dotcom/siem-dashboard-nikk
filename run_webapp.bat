@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo Virtual environment python not found at .venv\Scripts\python.exe
  echo Run install_webapp.bat first.
  exit /b 1
)

if not exist ".venv\Scripts\waitress-serve.exe" (
  echo waitress-serve not found in .venv\Scripts
  echo Run install_webapp.bat first.
  exit /b 1
)

if "%HOST%"=="" set HOST=0.0.0.0
if "%PORT%"=="" set PORT=5000

echo Starting SIEM dashboard on http://127.0.0.1:%PORT%
echo Host bind: %HOST%
echo Press Ctrl+C to stop.
start "" "http://127.0.0.1:%PORT%"

".venv\Scripts\waitress-serve.exe" --host=%HOST% --port=%PORT% wsgi:application
