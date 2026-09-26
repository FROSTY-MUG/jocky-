@echo off
rem ==============================================================================
rem JOCKY Diversification Runner - Windows CMD Batch Wrapper (diversify.bat)
rem
rem Purpose:
rem   Thin batch wrapper delegating execution to ci/ps/diversify.ps1.
rem
rem Inputs:
rem   Forwarded command-line arguments to PowerShell script.
rem
rem Outputs:
rem   Process output forwarded from PowerShell.
rem
rem Exit Codes:
rem   Exit code forwarded from PowerShell (%ERRORLEVEL%).
rem
rem Blueprint Section:
rem   §0.4 Binary Diversification & Polymorphism; §4 CI/CD Polymorphism.
rem ==============================================================================

setlocal
set "ARG1=%~1"
if /i "%ARG1%"=="--help" goto show_help
if /i "%ARG1%"=="-h" goto show_help

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ps\diversify.ps1" %*
exit /b %ERRORLEVEL%

:show_help
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ps\diversify.ps1" -Help
exit /b %ERRORLEVEL%
