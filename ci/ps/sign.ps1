<#
.SYNOPSIS
    JOCKY Module Ed25519 Signer for Windows (sign.ps1)

.DESCRIPTION
    Compiles and signs JOCKY .jkm binary modules using Ed25519 private keys,
    or generates fresh cryptographic keypairs for attestation workflows.

.PARAMETER Source
    Path to JOCKY source code (.jky)

.PARAMETER Key
    Path to Ed25519 private key (.key)

.PARAMETER Out
    Destination path for signed .jkm container

.PARAMETER Target
    LLVM target architecture triple (default: x86_64-unknown-linux-gnu)

.PARAMETER Seed
    Deterministic diversification seed (optional)

.PARAMETER Keygen
    Output path to generate a new Ed25519 keypair and exit

.PARAMETER Help
    Display this usage and help message

.EXITCODES
    0 - Operation succeeded.
    1 - Missing required arguments or file not found.
    2 - Compiler or signing failure.

.BLUEPRINT
    §2.3 Binary Packaging & Attestation; §4 CI/CD Polymorphism.
#>

[CmdletBinding()]
param(
    [string]$Source = "",
    [string]$Key = "",
    [string]$Out = "",
    [string]$Target = "x86_64-unknown-linux-gnu",
    [long]$Seed = 0,
    [string]$Keygen = "",
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
    Write-Host "Usage: sign.ps1 [options]"
    Write-Host ""
    Write-Host "Signing Options:"
    Write-Host "  -Source <file.jky>   Path to JOCKY source code"
    Write-Host "  -Key <file.key>      Path to Ed25519 private key"
    Write-Host "  -Out <file.jkm>      Output path for signed .jkm module"
    Write-Host "  -Target <triple>     Compilation target triple (default: x86_64-unknown-linux-gnu)"
    Write-Host "  -Seed <seed>         Diversification seed (optional)"
    Write-Host ""
    Write-Host "Keygen Options:"
    Write-Host "  -Keygen <file.key>   Generate new Ed25519 keypair and exit"
    Write-Host "  -Help                Display this help message and exit"
}

if ($Help -or ($PSBoundParameters.ContainsKey('Help'))) {
    Show-Usage
    exit 0
}

if (-not [string]::IsNullOrWhiteSpace($Keygen)) {
    Write-LogInfo "Generating Ed25519 keypair at $Keygen..."
    cargo run --bin jockyc -- keygen --out "$Keygen"
    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Key generation failed with exit code $LASTEXITCODE"
        exit 2
    }
    Write-LogSuccess "Keypair generated successfully."
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Source) -or [string]::IsNullOrWhiteSpace($Key) -or [string]::IsNullOrWhiteSpace($Out)) {
    Write-LogError "Missing required parameters: -Source, -Key, and -Out are all required for signing."
    Show-Usage
    exit 1
}

if (-not (Test-Path $Source)) {
    Write-LogError "Source file not found: $Source"
    exit 1
}

if (-not (Test-Path $Key)) {
    Write-LogError "Private key file not found: $Key"
    exit 1
}

Write-LogInfo "Compiling and signing $Source -> $Out..."
$buildArgs = @("run", "--bin", "jockyc", "--", "build", "$Source", "--target", "$Target", "--sign", "--key", "$Key", "--out", "$Out")
if ($PSBoundParameters.ContainsKey('Seed')) {
    $buildArgs += @("--seed", "$Seed")
}

cargo @buildArgs
if ($LASTEXITCODE -ne 0) {
    Write-LogError "Compiler execution failed with exit code $LASTEXITCODE"
    exit 2
}

Write-LogSuccess "Signed module created: $Out"
exit 0
