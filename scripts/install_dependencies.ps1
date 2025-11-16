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

function Invoke-PackageInstall {
    param(
        [string]$WingetId,
        [string]$ChocoId,
        [string]$DisplayName,
        [string]$ExtraArgs = ""
    )

    if (Test-Command winget) {
        Write-Host "Installing $DisplayName via winget..." -ForegroundColor Cyan
        winget install --id $WingetId --source winget --accept-package-agreements --accept-source-agreements --silent $ExtraArgs
    }
    elseif (Test-Command choco) {
        Write-Host "Installing $DisplayName via Chocolatey..." -ForegroundColor Cyan
        choco install $ChocoId -y
    }
    else {
        throw "Neither winget nor Chocolatey is available. Install one of them and re-run."
    }
}

$packages = @(
    @{ Display = "Visual Studio 2022 Build Tools"; Winget = "Microsoft.VisualStudio.2022.BuildTools"; Choco = "visualstudio2022buildtools"; Args = "--override \"--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive\"" },
    @{ Display = "CMake"; Winget = "Kitware.CMake"; Choco = "cmake"; Args = "" },
    @{ Display = "Ninja"; Winget = "Ninja-build.Ninja"; Choco = "ninja"; Args = "" },
    @{ Display = "Git"; Winget = "Git.Git"; Choco = "git"; Args = "" },
    @{ Display = "Python"; Winget = "Python.Python.3"; Choco = "python"; Args = "" },
    @{ Display = "Node.js LTS"; Winget = "OpenJS.NodeJS.LTS"; Choco = "nodejs-lts"; Args = "" },
    @{ Display = "NSIS"; Winget = "NSIS.NSIS"; Choco = "nsis"; Args = "" },
    @{ Display = "Qt Runtime"; Winget = "TheQtCompany.Qt5.LTS.Minimal"; Choco = "qt5-default"; Args = "" }
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

if (-not (Test-Command vswhere)) {
    Write-Host "Installing vswhere helper..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vswhere.exe" -OutFile "$env:ProgramFiles(x86)\Microsoft Visual Studio\Installer\vswhere.exe"
}

Write-Host "All dependencies installed. Re-open your terminal to ensure PATH updates are applied." -ForegroundColor Green
