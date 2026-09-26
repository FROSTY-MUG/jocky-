<#
.SYNOPSIS
    JOCKY SBOM Generation Tool for Windows (sbom.ps1)

.DESCRIPTION
    Generates an SPDX 2.3 Software Bill of Materials (SBOM) in JSON format for
    compiled JOCKY modules on Windows, recording BLAKE3 and SHA-256 digests.

.PARAMETER Artifact
    Path to compiled binary artifact (.jkm, .o, .obj) [Required]

.PARAMETER Output
    Output path for SPDX JSON (default: stdout)

.PARAMETER Name
    Package name (default: jocky-module)

.PARAMETER Version
    Package version (default: 0.1.0)

.PARAMETER Help
    Display this usage and help message

.EXITCODES
    0 - Successfully generated SBOM.
    1 - Missing artifact or Python runtime error.

.BLUEPRINT
    §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.
#>

[CmdletBinding()]
param(
    [string]$Artifact = "",
    [string]$Output = "",
    [string]$Name = "jocky-module",
    [string]$Version = "0.1.0",
    [switch]$Help
)

$commonScript = Join-Path $PSScriptRoot "common.ps1"
if (Test-Path $commonScript) {
    . $commonScript
} else {
    function Write-LogInfo { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
    function Write-LogSuccess { param($Message) Write-Host "[OK] $Message" -ForegroundColor Green }
    function Write-LogError { param($Message) [Console]::Error.WriteLine("[ERROR] $Message") }
}

function Show-Usage {
    Write-Host "Usage: sbom.ps1 -Artifact <path> [-Output <path>] [-Name <name>] [-Version <ver>] [-Help]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Artifact <path>  Path to compiled binary artifact [Required]"
    Write-Host "  -Output <path>    Output path for SPDX JSON (default: stdout)"
    Write-Host "  -Name <name>      Package name (default: jocky-module)"
    Write-Host "  -Version <ver>    Package version (default: 0.1.0)"
    Write-Host "  -Help             Display this help message and exit"
}

if ($Help -or ($PSBoundParameters.ContainsKey('Help'))) {
    Show-Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Artifact)) {
    Write-LogError "Missing required parameter: -Artifact <path>"
    Show-Usage
    exit 1
}

if (-not (Test-Path $Artifact)) {
    Write-LogError "Artifact not found: $Artifact"
    exit 1
}

$sbomPy = Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) "py") "sbom.py"

$pyArgs = @("$sbomPy", "--artifact", "$Artifact", "--name", "$Name", "--version", "$Version")
if (-not [string]::IsNullOrWhiteSpace($Output)) {
    $pyArgs += @("--output", "$Output")
}

python @pyArgs
if ($LASTEXITCODE -ne 0) {
    Write-LogError "SBOM generation failed with exit code $LASTEXITCODE"
    exit 1
}

exit 0
