$ErrorActionPreference = "Stop"

Set-Location -Path $PSScriptRoot

$pythonExe = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonExe)) {
    throw "Virtual environment python not found at .venv\Scripts\python.exe. Run install_webapp.bat first."
}

$waitressExe = Join-Path $PSScriptRoot ".venv\Scripts\waitress-serve.exe"
if (-not (Test-Path $waitressExe)) {
    throw "waitress-serve not found in .venv\Scripts. Run install_webapp.bat first."
}

if (-not $env:HOST) { $env:HOST = "0.0.0.0" }
if (-not $env:PORT) { $env:PORT = "5000" }

Write-Host "Starting SIEM dashboard on http://127.0.0.1:$($env:PORT)"
Write-Host "Host bind: $($env:HOST)"
Write-Host "Press Ctrl+C to stop."
Start-Process "http://127.0.0.1:$($env:PORT)"

& $waitressExe "--host=$($env:HOST)" "--port=$($env:PORT)" "wsgi:application"
