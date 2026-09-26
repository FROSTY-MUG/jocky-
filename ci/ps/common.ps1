<#
.SYNOPSIS
    JOCKY CI Common PowerShell Module (common.ps1)

.DESCRIPTION
    Provides standardized logging, environment checking, and error handling
    primitives for JOCKY Windows CI/CD PowerShell scripts. Works with both
    Windows PowerShell 5.1 and PowerShell Core 7+ (pwsh).

.INPUTS
    Dot-sourced by CI scripts: `. (Join-Path $PSScriptRoot "common.ps1")`

.OUTPUTS
    Formatted log output to host console and standard error streams.

.EXITCODES
    0 - Success.
    1 - Invalid parameters or unexpected execution error.
    2 - Compilation failure.
    3 - Verification failure.

.BLUEPRINT
    §4 CI/CD Polymorphism & Attestation; §0.4 Binary Diversification.
#>

$global:EXIT_SUCCESS = 0
$global:EXIT_INVALID_ARGS = 1
$global:EXIT_BUILD_FAILED = 2
$global:EXIT_VERIFY_FAILED = 3

function Write-LogInfo {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-LogSuccess {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-LogWarn {
    param([string]$Message)
    Write-Warning "[WARN] $Message"
}

function Write-LogError {
    param([string]$Message)
    [Console]::Error.WriteLine("[ERROR] $Message")
}

function Assert-ToolAvailable {
    param([string]$ToolName)
    if (-not (Get-Command $ToolName -ErrorAction SilentlyContinue)) {
        Write-LogError "Required executable '$ToolName' was not found on system PATH."
        exit $global:EXIT_INVALID_ARGS
    }
}
