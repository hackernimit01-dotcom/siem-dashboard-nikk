@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_LAUNCHER="
where py >nul 2>&1
if %ERRORLEVEL%==0 set "PYTHON_LAUNCHER=py -3"
if not defined PYTHON_LAUNCHER (
  where python >nul 2>&1
  if %ERRORLEVEL%==0 set "PYTHON_LAUNCHER=python"
)

if not defined PYTHON_LAUNCHER (
  echo Python 3 is not installed or not on PATH.
  echo Install Python 3.11+ and run this file again.
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo [1/4] Creating virtual environment...
  call %PYTHON_LAUNCHER% -m venv .venv
  if %ERRORLEVEL% neq 0 (
    echo Failed to create virtual environment.
    exit /b 1
  )
) else (
  echo [1/4] Virtual environment already exists.
)

echo [2/4] Upgrading pip...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if %ERRORLEVEL% neq 0 (
  echo Failed to upgrade pip.
  exit /b 1
)

echo [3/4] Installing Python dependencies...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
  echo Failed to install dependencies.
  exit /b 1
)

echo [4/4] Setup complete.
echo.
echo To run next time, use: run_webapp.bat
echo Starting now...
echo.
call ".\run_webapp.bat"
