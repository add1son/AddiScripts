@echo off
REM --- PS Script Wrapper ---
REM Bypasses execution policy restrictions temporarily for this process only.
REM Safely handles UNC network shares and enforces administrative privileges.

set "PSScriptName=$script_name.ps1"

REM 1. Enforce Administrator Privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo ERROR: This script must be run as Administrator.
    echo Please right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

REM 2. Fix for UNC Share / Working Directory issues
pushd "%~dp0"

REM 3. Ensure the target PowerShell script exists before executing
if not exist "%PSScriptName%" (
    echo.
    echo ERROR: Target script not found: %PSScriptName%
    echo Ensure the .ps1 file is located in the same directory as this batch file.
    echo.
    popd
    pause
    exit /b 1
)

REM 4. Launch PowerShell script with process-scoped bypass
echo Running PowerShell script: %PSScriptName%
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PSScriptName%"

REM 5. Capture the script exit code and restore directory state
set "PSExitCode=%errorlevel%"
popd

REM 6. Final Status Check
echo.
if %PSExitCode% equ 0 (
    echo script completed successfully.
) else (
    echo ERROR: PowerShell script failed with exit code: %PSExitCode%
)
echo.

pause
exit /b %PSExitCode%
