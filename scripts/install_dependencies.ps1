<#!
.SYNOPSIS
    Installs the prerequisite toolchain required to build the Paranoid Antivirus Suite on Windows.
.DESCRIPTION
    Uses winget (preferred) or Chocolatey to install the Visual Studio Build Tools, CMake, Ninja,
    Git, Python, Node.js, NSIS (for the installer), and Qt runtime bits that Electron depends on.
    The script is idempotent and will skip packages that are already installed.
.NOTES
    Run from an elevated PowerShell prompt.
#>
[CmdletBinding()]
param()

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Get-VsInstallPaths {
    $paths = @()
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\SxS\VS7",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VS7"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $props = Get-ItemProperty $root
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -match "^\d+(\.\d+)?$" -and $prop.Value) {
                $paths += $prop.Value
            }
        }
    }
    if ($paths.Count -eq 0) {
        $programDirs = @("${env:ProgramFiles(x86)}", "${env:ProgramFiles}") | Where-Object { $_ }
        foreach ($dir in $programDirs) {
            $base = Join-Path $dir "Microsoft Visual Studio"
            if (-not (Test-Path $base)) { continue }
            Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $paths += $_.FullName
                Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                    $paths += $_.FullName
                }
            }
        }
    }
    return $paths | Sort-Object -Unique
}

function Test-VcToolchainPresent {
    foreach ($path in Get-VsInstallPaths) {
        $vcTools = Join-Path $path "VC\Tools\MSVC"
        if (-not (Test-Path $vcTools)) { continue }
        $clExe = Get-ChildItem -Path $vcTools -Recurse -Filter cl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($clExe) {
            return $true
        }
    }
    return $false
}

function Invoke-PackageInstall {
    param(
        [string]$WingetId,
        [string]$ChocoId,
        [string]$DisplayName,
        [string[]]$ExtraArgs = @()
    )

    if (Test-Command winget) {
        Write-Host "Installing $DisplayName via winget..." -ForegroundColor Cyan
        winget install --id $WingetId --source winget --accept-package-agreements --accept-source-agreements --silent @ExtraArgs
    }
    elseif (Test-Command choco) {
        Write-Host "Installing $DisplayName via Chocolatey..." -ForegroundColor Cyan
        if ($ExtraArgs.Count -gt 0) {
            choco install $ChocoId -y $ExtraArgs
        }
        else {
            choco install $ChocoId -y
        }
    }
    else {
        throw "Neither winget nor Chocolatey is available. Install one of them and re-run."
    }
}

$packages = @(
    @{ Display = "Visual Studio 2022 Build Tools"; Winget = "Microsoft.VisualStudio.2022.BuildTools"; Choco = "visualstudio2022buildtools"; Args = @("--override", "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive") },
    @{ Display = "CMake"; Winget = "Kitware.CMake"; Choco = "cmake"; Args = @() },
    @{ Display = "Ninja"; Winget = "Ninja-build.Ninja"; Choco = "ninja"; Args = @() },
    @{ Display = "Git"; Winget = "Git.Git"; Choco = "git"; Args = @() },
    @{ Display = "Python"; Winget = "Python.Python.3"; Choco = "python"; Args = @() },
    @{ Display = "Node.js LTS"; Winget = "OpenJS.NodeJS.LTS"; Choco = "nodejs-lts"; Args = @() },
    @{ Display = "NSIS"; Winget = "NSIS.NSIS"; Choco = "nsis"; Args = @() },
    @{ Display = "Qt Runtime"; Winget = "TheQtCompany.Qt5.LTS.Minimal"; Choco = "qt5-default"; Args = @() }
)

foreach ($pkg in $packages) {
    try {
        Invoke-PackageInstall -WingetId $pkg.Winget -ChocoId $pkg.Choco -DisplayName $pkg.Display -ExtraArgs $pkg.Args
    }
    catch {
        Write-Warning "Failed to install $($pkg.Display): $_"
        throw
    }
}

if (-not (Test-VcToolchainPresent)) {
    Write-Host "Visual Studio C++ Build Tools workload missing or incomplete. Reinstalling via winget..." -ForegroundColor Yellow
    Invoke-PackageInstall -WingetId "Microsoft.VisualStudio.2022.BuildTools" -ChocoId "visualstudio2022buildtools" -DisplayName "Visual Studio 2022 Build Tools" -ExtraArgs @("--override", "--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive")
    if (-not (Test-VcToolchainPresent)) {
        throw "Visual Studio Build Tools installation is still missing the Microsoft.VisualStudio.Workload.VCTools workload. Install it manually and re-run this script."
    }
}

Write-Host "All dependencies installed. Re-open your terminal to ensure PATH updates are applied." -ForegroundColor Green
