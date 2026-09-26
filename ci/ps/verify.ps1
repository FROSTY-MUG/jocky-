<#
.SYNOPSIS
    JOCKY Container Attestation Verifier for Windows (verify.ps1)

.DESCRIPTION
    Verifies the Ed25519 cryptographic signature and structural integrity of a .jkm module
    against a trusted public key, detecting byte-level tampering or unauthorized forgery.

.PARAMETER Container
    Path to the .jkm container to verify [Required]

.PARAMETER Pubkey
    Path to the trusted Ed25519 public key [Required]

.PARAMETER VerboseOutput
    Display full CBOR manifest and symbol map

.PARAMETER Help
    Display this usage and help message

.EXITCODES
    0 - Signature valid and container integrity confirmed.
    1 - Signature invalid, container tampered, or missing arguments.

.BLUEPRINT
    §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.
#>

[CmdletBinding()]
param(
    [string]$Container = "",
    [string]$Pubkey = "",
    [switch]$VerboseOutput,
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
    Write-Host "Usage: verify.ps1 -Container <file.jkm> -Pubkey <file.pub> [-VerboseOutput] [-Help]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Container <file.jkm>  Path to .jkm container file [Required]"
    Write-Host "  -Pubkey <file.pub>     Path to Ed25519 public key [Required]"
    Write-Host "  -VerboseOutput         Print verbose manifest and symbol mappings"
    Write-Host "  -Help                  Display this help message and exit"
}

if ($Help -or ($PSBoundParameters.ContainsKey('Help'))) {
    Show-Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Container) -or [string]::IsNullOrWhiteSpace($Pubkey)) {
    Write-LogError "Missing required parameters: both -Container and -Pubkey are required."
    Show-Usage
    exit 1
}

if (-not (Test-Path $Container)) {
    Write-LogError "Container file not found: $Container"
    exit 1
}

if (-not (Test-Path $Pubkey)) {
    Write-LogError "Public key file not found: $Pubkey"
    exit 1
}

Write-LogInfo "Verifying container $Container against public key $Pubkey..."
$cmdArgs = @("run", "--bin", "jocky-verify", "--", "$Container", "--pubkey", "$Pubkey")
if ($VerboseOutput) {
    $cmdArgs += "--verbose"
}

cargo @cmdArgs
if ($LASTEXITCODE -eq 0) {
    Write-LogSuccess "Attestation verified successfully."
    exit 0
} else {
    Write-LogError "Attestation verification FAILED. Container may be tampered or signature invalid."
    exit 1
}
