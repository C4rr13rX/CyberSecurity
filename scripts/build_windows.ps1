<#!
.SYNOPSIS
    Configures and builds the Paranoid Antivirus Suite on Windows with Visual Studio generators.
.DESCRIPTION
    Detects the highest available Visual Studio installation (via registry and filesystem probes),
    configures CMake with the right generator, compiles the native binary, bundles the UI, and
    optionally produces the NSIS installer through CPack.
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
    [switch]$RunTests,
    [string]$Generator
)

$ErrorActionPreference = "Stop"
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$buildDir = Join-Path (Join-Path $repoRoot "build") "windows"
$script:vsInstallAttempted = $false
$script:vsInstallPath = $null

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Test-VcToolsetPresent {
    param([string]$InstallRoot)
    if (-not $InstallRoot) { return $false }
    $vcTools = Join-Path $InstallRoot "VC\Tools\MSVC"
    return Test-Path $vcTools
}

function Get-VSInstallVersionFromPath {
    param([string]$InstallPath)
    if (-not $InstallPath) { return $null }
    $msbuildRelPaths = @(
        "MSBuild\Current\Bin\MSBuild.exe",
        "MSBuild\Current\Bin\amd64\MSBuild.exe",
        "MSBuild\16.0\Bin\MSBuild.exe"
    )
    foreach ($rel in $msbuildRelPaths) {
        $candidate = Join-Path $InstallPath $rel
        if (-not (Test-Path $candidate)) { continue }
        try {
            $info = (Get-Item $candidate).VersionInfo
            $possibleVersions = @($info.ProductVersionRaw, $info.FileVersion, $info.ProductVersion)
            foreach ($candidateVersion in $possibleVersions) {
                if ($candidateVersion -and ($candidateVersion -match "^\d+(\.\d+){3}$")) {
                    return $candidateVersion
                }
            }
        }
        catch {
            continue
        }
    }
    return $null
}

function Get-FallbackVSInstall {
    $programDirs = @("${env:ProgramFiles}", "${env:ProgramFiles(x86)}") | Where-Object { $_ -and (Test-Path $_) }
    $candidates = @(
        @{ Year = "2022"; Generator = "Visual Studio 17 2022"; Base = "Microsoft Visual Studio\2022"; Editions = @("BuildTools","Community","Professional","Enterprise") },
        @{ Year = "2019"; Generator = "Visual Studio 16 2019"; Base = "Microsoft Visual Studio\2019"; Editions = @("BuildTools","Community","Professional","Enterprise") },
        @{ Year = "2017"; Generator = "Visual Studio 15 2017"; Base = "Microsoft Visual Studio\2017"; Editions = @("BuildTools","Community","Professional","Enterprise") }
    )
    foreach ($candidate in $candidates) {
        foreach ($edition in $candidate.Editions) {
            foreach ($dir in $programDirs) {
                $probe = Join-Path $dir (Join-Path $candidate.Base $edition)
                if (Test-Path $probe) {
                    $msbuild = Join-Path $probe "MSBuild\Current\Bin\MSBuild.exe"
                    $vcDir = Join-Path $probe "VC\Tools\MSVC"
                    if ((Test-Path $msbuild) -and (Test-Path $vcDir)) {
                        $version = Get-VSInstallVersionFromPath -InstallPath $probe
                        if (-not $version) {
                            switch ($candidate.Year) {
                                "2022" { $version = "17.0.0.0" }
                                "2019" { $version = "16.0.0.0" }
                                "2017" { $version = "15.0.0.0" }
                                default { $version = $null }
                            }
                        }
                        return @{ Generator = $candidate.Generator; Year = $candidate.Year; Path = $probe; Version = $version }
                    }
                }
            }
        }
    }
    return $null
}

function Get-VSInstallFromRegistry {
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\VisualStudio\SxS\VS7",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\SxS\VS7"
    )
    $candidates = @()
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        $props = Get-ItemProperty $root
        foreach ($prop in $props.PSObject.Properties) {
            if ($prop.Name -match "^\d+(\.\d+)?$") {
                $candidates += @{ Version = [version]$prop.Name; Path = $prop.Value }
            }
        }
    }
    if ($candidates.Count -eq 0) { return $null }
    $best = $candidates | Sort-Object Version -Descending | Select-Object -First 1
    return $best
}

function Get-VSInstallFromStateStore {
    $instancesRoot = "C:\ProgramData\Microsoft\VisualStudio\Packages\_Instances"
    if (-not (Test-Path $instancesRoot)) { return $null }
    $candidates = @()
    $instanceDirs = Get-ChildItem -Path $instancesRoot -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $instanceDirs) {
        $stateFile = Join-Path $dir.FullName "state.json"
        if (-not (Test-Path $stateFile)) { continue }
        try {
            $state = Get-Content -Raw -Path $stateFile | ConvertFrom-Json
            if ($state.installationPath -and $state.installationVersion) {
                if (Test-VcToolsetPresent -InstallRoot $state.installationPath) {
                    $candidates += @{ Version = [version]$state.installationVersion; Path = $state.installationPath }
                }
                else {
                    Write-Warning "Skipping Visual Studio instance at '$($state.installationPath)' because the C++ toolset is missing."
                }
            }
        }
        catch {
            continue
        }
    }
    if ($candidates.Count -eq 0) { return $null }
    return ($candidates | Sort-Object Version -Descending | Select-Object -First 1)
}

function Map-VersionToGenerator {
    param([version]$Version,[string]$Path)
    switch ($Version.Major) {
        17 { return @{ Generator = "Visual Studio 17 2022"; Year = "2022"; Path = $Path; Version = $Version.ToString() } }
        16 { return @{ Generator = "Visual Studio 16 2019"; Year = "2019"; Path = $Path; Version = $Version.ToString() } }
        15 { return @{ Generator = "Visual Studio 15 2017"; Year = "2017"; Path = $Path; Version = $Version.ToString() } }
        default { return $null }
    }
}

function Get-VSGenerator {
    param([string]$OverrideGenerator)

    if ($PSBoundParameters.ContainsKey("OverrideGenerator") -and $OverrideGenerator) {
        return @{ Generator = $OverrideGenerator; Year = $OverrideGenerator; Path = $null }
    }

    $registryInstall = Get-VSInstallFromRegistry
    if ($registryInstall) {
        $mapped = Map-VersionToGenerator -Version $registryInstall.Version -Path $registryInstall.Path
        if ($mapped -and (Test-VcToolsetPresent -InstallRoot $mapped.Path)) {
            return $mapped
        }
        elseif ($mapped) {
            Write-Warning "Visual Studio at '$($mapped.Path)' is missing the C++ toolset. Ignoring."
        }
    }

    $stateInstall = Get-VSInstallFromStateStore
    if ($stateInstall) {
        $mapped = Map-VersionToGenerator -Version $stateInstall.Version -Path $stateInstall.Path
        if ($mapped -and (Test-VcToolsetPresent -InstallRoot $mapped.Path)) {
            return $mapped
        }
        elseif ($mapped) {
            Write-Warning "Visual Studio at '$($mapped.Path)' is missing the C++ toolset. Ignoring."
        }
    }

    $fallback = Get-FallbackVSInstall
    if ($fallback) {
        Write-Warning "Falling back to Visual Studio install at '$($fallback.Path)' (generator '$($fallback.Generator)')."
        return $fallback
    }

    if (-not $script:vsInstallAttempted) {
        Install-VSBuildTools
        $script:vsInstallAttempted = $true
        return Get-VSGenerator -OverrideGenerator $OverrideGenerator
    }

    throw "No supported Visual Studio installation detected. Install Build Tools 2022 or rerun with -Generator to override."
}

function Install-VSBuildTools {
    if (-not (Test-Command winget)) {
        throw "winget is required to automatically install Visual Studio Build Tools. Install winget or install VS Build Tools manually."
    }
    Write-Host "Installing Visual Studio Build Tools 2022 via winget..." -ForegroundColor Cyan
    $arguments = @(
        "install","--id","Microsoft.VisualStudio.2022.BuildTools","--source","winget",
        "--accept-package-agreements","--accept-source-agreements","--silent",
        "--override","--add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --passive"
    )
    $process = Start-Process -FilePath "winget" -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        throw "winget failed to install Visual Studio Build Tools (exit code $($process.ExitCode)). Install them manually and rerun."
    }
    Write-Host "Visual Studio Build Tools installation finished. Re-checking installations..." -ForegroundColor Cyan
}

function Invoke-WithVsEnvironment {
    param([string]$CommandLine)
    if (-not $script:vsInstallPath) {
        throw "Visual Studio installation path is not available for VsDevCmd."
    }
    $vsDevCmd = Join-Path $script:vsInstallPath "Common7\Tools\VsDevCmd.bat"
    if (-not (Test-Path $vsDevCmd)) {
        throw "VsDevCmd.bat not found at '$vsDevCmd'. Repair the Visual Studio Build Tools installation."
    }
    $comspec = if ($env:COMSPEC) { $env:COMSPEC } else { "cmd.exe" }
    $batchInvocation = "call `"$vsDevCmd`" -no_logo -arch=x64 && $CommandLine"
    & $comspec /c $batchInvocation | Out-Host
    return $LASTEXITCODE
}

function Ensure-BuildDirectory {
    param([string]$Path,[string]$GeneratorName)
    if (Test-Path $Path) {
        $cachePath = Join-Path $Path "CMakeCache.txt"
        if (Test-Path $cachePath) {
            $cacheLine = Get-Content $cachePath | Where-Object { $_ -like "CMAKE_GENERATOR:INTERNAL=*" } | Select-Object -First 1
            if ($cacheLine) {
                $cachedGenerator = ($cacheLine -split "=",2)[1].Trim()
                if ($cachedGenerator -ne $GeneratorName) {
                    Write-Warning "Existing build directory '$Path' uses generator '$cachedGenerator' which conflicts with '$GeneratorName'. Removing it."
                    Remove-Item $Path -Recurse -Force
                }
            }
            else {
                Write-Warning "Unable to determine generator from existing cache at '$cachePath'. Removing build directory."
                Remove-Item $Path -Recurse -Force
            }
        }
    }
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Invoke-ProcessChecked {
    param([string]$FilePath,[string]$Arguments,[string]$WorkingDirectory,[switch]$UseVsEnv)
    $commandLine = "`"$FilePath`" $Arguments"
    $commandLine = "cd /d `"$WorkingDirectory`" && $commandLine"
    if ($UseVsEnv -and $script:vsInstallPath) {
        $exitCode = Invoke-WithVsEnvironment -CommandLine $commandLine
        if ($exitCode -ne 0) {
            throw "Command '$FilePath $Arguments' failed with exit code $exitCode."
        }
        return
    }
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

$vsInfo = Get-VSGenerator -OverrideGenerator $Generator
$script:vsInstallPath = $vsInfo.Path
Ensure-BuildDirectory -Path $buildDir -GeneratorName $vsInfo.Generator
Write-Host "Using Visual Studio $($vsInfo.Year) with generator '$($vsInfo.Generator)'." -ForegroundColor Cyan

$useVsEnv = $vsInfo.Generator -like "Visual Studio*"
Write-Host "Configuring CMake..." -ForegroundColor Cyan
$configureArgs = "-S `"$repoRoot`" -B `"$buildDir`" -G `"$($vsInfo.Generator)`" -A x64"
if ($vsInfo.Path) {
    $instanceSpec = $vsInfo.Path
    if ($vsInfo.Version -and ($vsInfo.Version -match "^\d+(\.\d+){3}$")) {
        $instanceSpec += ",version=$($vsInfo.Version)"
    }
    $configureArgs += " -D CMAKE_GENERATOR_INSTANCE=`"$instanceSpec`""
}
Invoke-ProcessChecked -FilePath "cmake" -Arguments $configureArgs -WorkingDirectory $repoRoot -UseVsEnv:$useVsEnv

Write-Host "Building ($Configuration)..." -ForegroundColor Cyan
Invoke-ProcessChecked -FilePath "cmake" -Arguments "--build `"$buildDir`" --config $Configuration" -WorkingDirectory $repoRoot -UseVsEnv:$useVsEnv

Write-Host "Building Ionic/Electron shell..." -ForegroundColor Cyan
$uiDir = Join-Path $repoRoot "ui"
$shouldBuildUi = $true
if ($env:PARANOID_BUILD_UI) {
    if ($env:PARANOID_BUILD_UI -in @("0","false","False","FALSE")) {
        $shouldBuildUi = $false
    }
}
if ($shouldBuildUi) {
    $npmCmd = Get-Command npm.cmd -ErrorAction SilentlyContinue
    if (-not $npmCmd -or $npmCmd.CommandType -ne 'Application') {
        $npmCmd = Get-Command npm -ErrorAction SilentlyContinue | Where-Object { $_.CommandType -eq 'Application' } | Select-Object -First 1
    }
    if ($npmCmd) {
        $npmPath = $npmCmd.Source
        Invoke-ProcessChecked -FilePath $npmPath -Arguments "install" -WorkingDirectory $uiDir
        Invoke-ProcessChecked -FilePath $npmPath -Arguments "run build" -WorkingDirectory $uiDir
    }
    else {
        Write-Warning "npm is not available on PATH, skipping UI build. Install Node.js and rerun to build the shell."
    }
}
else {
    Write-Warning "PARANOID_BUILD_UI requested to skip UI build. Set it to 1 (or unset) to include the Ionic/Electron shell."
}

if ($RunTests) {
    Write-Host "Running ctest..." -ForegroundColor Cyan
    Invoke-ProcessChecked -FilePath "ctest" -Arguments "-C $Configuration" -WorkingDirectory $buildDir
}

if ($Package) {
    Write-Host "Packaging installer via CPack..." -ForegroundColor Cyan
    Invoke-ProcessChecked -FilePath "cmake" -Arguments "--build `"$buildDir`" --config $Configuration --target package" -WorkingDirectory $repoRoot -UseVsEnv:$useVsEnv
}

Write-Host "Build completed successfully." -ForegroundColor Green
