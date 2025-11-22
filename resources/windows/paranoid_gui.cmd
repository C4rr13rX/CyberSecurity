@echo off
setlocal
set "BIN_DIR=%~dp0"
set "INSTALL_ROOT=%BIN_DIR%.."
set "GUI_ROOT=%INSTALL_ROOT%\share\paranoid_av\gui"
set "RUNTIME_DIR=%GUI_ROOT%\runtime"
set "ELECTRON_EXE=%RUNTIME_DIR%\electron.exe"

if not exist "%ELECTRON_EXE%" (
    echo [Paranoid GUI] Electron runtime missing at "%ELECTRON_EXE%". >&2
    exit /b 2
)

pushd "%GUI_ROOT%" >nul
"%ELECTRON_EXE%" "%GUI_ROOT%" %*
set "EXIT_CODE=%ERRORLEVEL%"
popd >nul
exit /b %EXIT_CODE%
