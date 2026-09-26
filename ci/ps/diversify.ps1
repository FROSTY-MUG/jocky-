<#
.SYNOPSIS
    JOCKY Polymorphic Diversification Runner for Windows (diversify.ps1)

.DESCRIPTION
    Compiles a JOCKY source program (.jky) into N uniquely diversified,
    cryptographically attested binary modules (.jkm) across distinct seeds
    for Windows (COFF) or Linux (ELF) targets.

.PARAMETER Source
    Path to JOCKY source file (.jky) [Required unless -Help is specified]

.PARAMETER Count
    Number of polymorphic variants to emit (default: 3)

.PARAMETER OutDir
    Destination directory for generated .jkm files (default: dist/variants)

.PARAMETER Target
    LLVM compilation target triple (default: x86_64-unknown-linux-gnu)

.PARAMETER BaseSeed
    Starting integer seed for PRNG diversification (default: 1000)

.PARAMETER Help
    Display this usage and help message

.OUTPUTS
    Emits compiled .jkm container files in OutDir.

.EXITCODES
    0 - All variants successfully generated.
    1 - Missing arguments or invalid source file.
    2 - Build error during compiler execution.

.BLUEPRINT
    §0.4 Binary Diversification & Polymorphism; §4 CI/CD Polymorphism.
#>

[CmdletBinding()]
param(
    [string]$Source = "",
    [int]$Count = 3,
    [string]$OutDir = "dist/variants",
    [string]$Target = "x86_64-unknown-linux-gnu",
    [long]$BaseSeed = 1000,
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
    Write-Host "Usage: diversify.ps1 -Source <file.jky> [-Count <N>] [-OutDir <dir>] [-Target <triple>] [-BaseSeed <seed>] [-Help]"
    Write-Host ""
    Write-Host "Parameters:"
    Write-Host "  -Source <file.jky>   Path to JOCKY source file (.jky) [Required]"
    Write-Host "  -Count <N>           Number of variants to emit (default: 3)"
    Write-Host "  -OutDir <dir>        Output directory for .jkm files (default: dist/variants)"
    Write-Host "  -Target <triple>     Compilation target triple (default: x86_64-unknown-linux-gnu)"
    Write-Host "  -BaseSeed <seed>     Starting seed integer (default: 1000)"
    Write-Host "  -Help                Show this help message and exit"
}

if ($Help -or ($PSBoundParameters.ContainsKey('Help'))) {
    Show-Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Source)) {
    Write-LogError "Missing required parameter: -Source <file.jky>"
    Show-Usage
    exit 1
}

if (-not (Test-Path $Source)) {
    Write-LogError "Source file not found: $Source"
    exit 1
}

if (-not (Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
}

$stem = [System.IO.Path]::GetFileNameWithoutExtension($Source)
Write-LogInfo "Generating $Count polymorphic variants for $Source (Target: $Target)..."

for ($i = 0; $i -lt $Count; $i++) {
    $seed = $BaseSeed + $i
    $outFile = Join-Path $OutDir "${stem}_seed${seed}.jkm"
    Write-LogInfo "  -> Building variant $($i+1)/$Count (seed: $seed) => $outFile"

    cargo run --bin jockyc -- build "$Source" `
        --target "$Target" `
        --seed $seed `
        --out "$outFile"

    if ($LASTEXITCODE -ne 0) {
        Write-LogError "Compiler execution failed for seed $seed with exit code $LASTEXITCODE"
        exit 2
    }
}

Write-LogSuccess "Successfully generated $Count polymorphic variants in $OutDir."
exit 0
