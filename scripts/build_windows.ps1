<#!
.SYNOPSIS
    Configures and builds the Paranoid Antivirus Suite on Windows with Visual Studio generators.
.DESCRIPTION
    Detects the highest available Visual Studio installation via vswhere, configures CMake with the
    right generator, compiles the native binary, bundles the UI, and optionally produces the NSIS
    installer through CPack.
.PARAMETER Configuration
    Build configuration (Debug/Release/RelWithDebInfo). Defaults to Release.
.PARAMETER Package
    Generates the installer after a successful build.
.PARAMETER RunTests
    Runs ctest against the generated binaries after building.
#>
[CmdletBinding()]
param(
    [ValidateSet("Debug","Release","RelWithDebInfo","MinSizeRel")]
    [string]$Configuration = "Release",
    [switch]$Package,
    [switch]$RunTests
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$buildDir = Join-Path $repoRoot "build"

function Get-VswherePath {
    $candidate = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio/Installer/vswhere.exe"
    if (Test-Path $candidate) { return $candidate }
    $candidate = Get-Command vswhere.exe -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Source }
    throw "vswhere.exe not found. Run scripts/install_dependencies.ps1 first."
}

function Get-VSGenerator {
    $vswhere = Get-VswherePath
    $vsPath = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath
    if (-not $vsPath) { throw "No supported Visual Studio installation detected." }
    $versionString = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -property installationVersion
    $version = [version]$versionString
    switch ($version.Major) {
        17 { return @{ Generator = "Visual Studio 17 2022"; Year = "2022"; Path = $vsPath } }
        16 { return @{ Generator = "Visual Studio 16 2019"; Year = "2019"; Path = $vsPath } }
        15 { return @{ Generator = "Visual Studio 15 2017"; Year = "2017"; Path = $vsPath } }
        default { throw "Unsupported Visual Studio major version: $version" }
    }
}

function Invoke-ProcessChecked {
    param([string]$FilePath,[string]$Arguments,[string]$WorkingDirectory)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = $Arguments
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    $process.Start() | Out-Null
    $process.WaitForExit()
    Write-Host $process.StandardOutput.ReadToEnd()
    if ($process.ExitCode -ne 0) {
        Write-Error $process.StandardError.ReadToEnd()
        throw "Command '$FilePath $Arguments' failed with exit code $($process.ExitCode)."
    }
}

$vsInfo = Get-VSGenerator
Write-Host "Using Visual Studio $($vsInfo.Year) with generator '$($vsInfo.Generator)'." -ForegroundColor Cyan

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

Write-Host "Configuring CMake..." -ForegroundColor Cyan
Invoke-ProcessChecked -FilePath "cmake" -Arguments "-S `"$repoRoot`" -B `"$buildDir`" -G `"$($vsInfo.Generator)`" -A x64" -WorkingDirectory $repoRoot

Write-Host "Building ($Configuration)..." -ForegroundColor Cyan
Invoke-ProcessChecked -FilePath "cmake" -Arguments "--build `"$buildDir`" --config $Configuration" -WorkingDirectory $repoRoot

Write-Host "Building Ionic/Electron shell..." -ForegroundColor Cyan
$uiDir = Join-Path $repoRoot "ui"
Invoke-ProcessChecked -FilePath "npm" -Arguments "install" -WorkingDirectory $uiDir
Invoke-ProcessChecked -FilePath "npm" -Arguments "run build" -WorkingDirectory $uiDir

if ($RunTests) {
    Write-Host "Running ctest..." -ForegroundColor Cyan
    Invoke-ProcessChecked -FilePath "ctest" -Arguments "-C $Configuration" -WorkingDirectory $buildDir
}

if ($Package) {
    Write-Host "Packaging installer via CPack..." -ForegroundColor Cyan
    Invoke-ProcessChecked -FilePath "cmake" -Arguments "--build `"$buildDir`" --config $Configuration --target package" -WorkingDirectory $repoRoot
}

Write-Host "Build completed successfully." -ForegroundColor Green
