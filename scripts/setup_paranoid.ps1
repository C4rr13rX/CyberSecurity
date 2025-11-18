<#!
.SYNOPSIS
    End-to-end bootstrapper that installs prerequisites, builds the suite (with installer), and runs the installer.
.DESCRIPTION
    Wraps install_dependencies.ps1, build_windows.ps1 (with -Package), and install_suite.ps1 into a single hardened workflow.
    The script enforces elevation, captures a transcript log, and surfaces clear status for every phase so that end-to-end
    provisioning of the Paranoid Antivirus Suite can be re-run safely.
.PARAMETER Configuration
    Build configuration passed to build_windows.ps1 (Debug/Release/RelWithDebInfo/MinSizeRel). Defaults to Release.
.PARAMETER SkipDependencies
    Skips install_dependencies.ps1 (useful if the toolchain is already present).
.PARAMETER SkipBuild
    Skips the build/packaging phase.
.PARAMETER SkipInstall
    Skips launching install_suite.ps1 (useful when only the installer artifact is required).
.PARAMETER SilentInstall
    Passes -Silent to install_suite.ps1 to run NSIS unattended.
.PARAMETER InstallerPath
    Optional path to an installer executable. When omitted the newest installer under build/ is used.
.PARAMETER LogDirectory
    Optional directory for transcript logs. Defaults to <repo>/logs.
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug","Release","RelWithDebInfo","MinSizeRel")]
    [string]$Configuration = "Release",
    [switch]$SkipDependencies,
    [switch]$SkipBuild,
    [switch]$SkipInstall,
    [switch]$SilentInstall,
    [string]$InstallerPath,
    [string]$LogDirectory
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
$repoRoot = Resolve-Path (Join-Path $scriptRoot "..")

function Assert-Elevation {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "This script must be run from an elevated PowerShell session (Run as Administrator)."
    }
}

function Start-SetupTranscript {
    param([string]$Directory)
    if (-not $Directory) {
        $Directory = Join-Path $repoRoot "logs"
    }
    if (-not (Test-Path $Directory)) {
        New-Item -ItemType Directory -Path $Directory -Force | Out-Null
    }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $path = Join-Path $Directory "setup_$timestamp.log"
    Start-Transcript -Path $path -Append | Out-Null
    return $path
}

function Invoke-Step {
    param(
        [string]$Name,
        [string]$RelativeScript,
        [object[]]$Arguments = @()
    )
    $fullPath = Join-Path $scriptRoot $RelativeScript
    if (-not (Test-Path $fullPath)) {
        throw "Unable to locate $Name script at '$RelativeScript'."
    }
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    & $fullPath @Arguments
    Write-Host "=== $Name completed ===" -ForegroundColor Green
}

Assert-Elevation
$transcriptPath = Start-SetupTranscript -Directory $LogDirectory
Write-Host "Transcript: $transcriptPath" -ForegroundColor DarkGray

Push-Location $repoRoot
try {
    if (-not $SkipDependencies) {
        Invoke-Step -Name "Dependency installation" -RelativeScript "install_dependencies.ps1"
    }
    else {
        Write-Host "[skip] Dependency installation" -ForegroundColor Yellow
    }

    if (-not $SkipBuild) {
        $buildArgs = @("-Configuration", $Configuration, "-Package")
        Invoke-Step -Name "Build & package" -RelativeScript "build_windows.ps1" -Arguments $buildArgs
    }
    else {
        Write-Host "[skip] Build & package" -ForegroundColor Yellow
    }

    if (-not $SkipInstall) {
        $installArgs = @()
        if ($InstallerPath) {
            $installArgs += @("-InstallerPath", $InstallerPath)
        }
        if ($SilentInstall) {
            $installArgs += "-Silent"
        }
        Invoke-Step -Name "Installer execution" -RelativeScript "install_suite.ps1" -Arguments $installArgs
    }
    else {
        Write-Host "[skip] Installer execution" -ForegroundColor Yellow
    }

    Write-Host "Paranoid Antivirus Suite setup completed successfully." -ForegroundColor Green
    Write-Host "Log saved to $transcriptPath" -ForegroundColor DarkGray
}
catch {
    Write-Error "Setup failed: $_"
    throw
}
finally {
    Pop-Location
    Stop-Transcript | Out-Null
}
