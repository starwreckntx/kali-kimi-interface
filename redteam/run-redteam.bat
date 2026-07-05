@echo off
REM Boundary Integrity Evaluator — Windows frontdesk launcher
REM Requires: PowerShell 5.1+ (built into Windows)
REM Usage: run-redteam.bat [init|run|report]

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: run-redteam.bat [init ^| run ^| report]
    echo.
    echo   init  - Create config.json and probes.json templates
    echo   run   - Execute probes and generate report
    echo   report - Generate report from existing results JSON
    exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%~dp0redteam.ps1" %*
exit /b %errorlevel%
