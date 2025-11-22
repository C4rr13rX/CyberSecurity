cmake_minimum_required(VERSION 3.15)
project(ParanoidAntivirusSuite LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(paranoid_av
    src/main.cpp
    src/ProcessScanner.cpp
    src/HeuristicAnalyzer.cpp
    src/SignatureScanner.cpp
    src/OpenAIAnalyzer.cpp
    src/Crypto.cpp
    src/YaraScanner.cpp
    src/SystemInspector.cpp
    src/ThreatIntel.cpp
    src/FileIntegrityMonitor.cpp
    src/RansomwareMonitor.cpp
    src/QuarantineManager.cpp
    src/TorClient.cpp
    src/DarkWebScanner.cpp
    src/RootkitDetector.cpp
    src/USBDeployer.cpp
    src/WindowsRepairManager.cpp
    src/FirewallManager.cpp
    src/WindowsSecurityCenterBridge.cpp
)

target_include_directories(paranoid_av PRIVATE include)

target_compile_options(paranoid_av PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /EHsc>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

find_package(Threads REQUIRED)
target_link_libraries(paranoid_av PRIVATE Threads::Threads)

if(WIN32)
    target_link_libraries(paranoid_av PRIVATE wscapi ole32 advapi32)
endif()

include(GNUInstallDirs)
install(TARGETS paranoid_av RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY resources/ DESTINATION ${CMAKE_INSTALL_DATADIR}/paranoid_av)
set(PARANOID_VERSION_MAJOR 1)
set(PARANOID_VERSION_MINOR 0)
set(PARANOID_VERSION_PATCH 0)
set(PARANOID_REGISTRY_KEY "ParanoidAntivirusSuite ${PARANOID_VERSION_MAJOR}.${PARANOID_VERSION_MINOR}.${PARANOID_VERSION_PATCH}")
if(WIN32)
    set(PARANOID_GUI_STAGE_DIR "${CMAKE_BINARY_DIR}/gui_stage")
    file(MAKE_DIRECTORY "${PARANOID_GUI_STAGE_DIR}")
    file(MAKE_DIRECTORY "${PARANOID_GUI_STAGE_DIR}/app")
    file(MAKE_DIRECTORY "${PARANOID_GUI_STAGE_DIR}/runtime")
    install(DIRECTORY "${PARANOID_GUI_STAGE_DIR}/app/" DESTINATION "${CMAKE_INSTALL_DATADIR}/paranoid_av/gui")
    install(DIRECTORY "${PARANOID_GUI_STAGE_DIR}/runtime/" DESTINATION "${CMAKE_INSTALL_DATADIR}/paranoid_av/gui/runtime")
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/resources/windows/paranoid_gui.cmd" DESTINATION ${CMAKE_INSTALL_BINDIR})
    set(_paranoid_icon "${CMAKE_CURRENT_SOURCE_DIR}/ui/src/assets/ui/shield.ico")
    if(EXISTS ${_paranoid_icon})
        install(FILES ${_paranoid_icon} DESTINATION ${CMAKE_INSTALL_DATADIR}/paranoid_av/icons)
        set(CPACK_NSIS_INSTALLED_ICON_NAME "share\\\\paranoid_av\\\\icons\\\\shield.ico")
    endif()
    set(CPACK_NSIS_CREATE_ICONS_EXTRA
"CreateShortCut \\\"$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\Paranoid Antivirus Suite.lnk\\\" \\\"$INSTDIR\\\\bin\\\\paranoid_gui.cmd\\\" \\\"\\\" \\\"$INSTDIR\\\\share\\\\paranoid_av\\\\icons\\\\shield.ico\\\"\\nCreateShortCut \\\"$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\Paranoid Antivirus CLI.lnk\\\" \\\"$INSTDIR\\\\bin\\\\paranoid_av.exe\\\" \\\"\\\" \\\"$INSTDIR\\\\share\\\\paranoid_av\\\\icons\\\\shield.ico\\\"\\nCreateShortCut \\\"$SMPROGRAMS\\\\$STARTMENU_FOLDER\\\\Uninstall.lnk\\\" \\\"$INSTDIR\\\\Uninstall.exe\\\" \\\"\\\" \\\"$INSTDIR\\\\share\\\\paranoid_av\\\\icons\\\\shield.ico\\\"\\n"
    )
    set(CPACK_NSIS_MENU_LINKS
        "${CMAKE_INSTALL_BINDIR}/paranoid_gui.cmd" "Paranoid Antivirus Console"
        "${CMAKE_INSTALL_BINDIR}/paranoid_av.exe" "Paranoid Antivirus CLI"
    )
    set(_paranoid_nsis_install
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"DisplayName\\\" \\\"Paranoid Antivirus Suite\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"DisplayVersion\\\" \\\"${PARANOID_VERSION_MAJOR}.${PARANOID_VERSION_MINOR}.${PARANOID_VERSION_PATCH}\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"Publisher\\\" \\\"Paranoid Security Labs\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"UninstallString\\\" \\\"$INSTDIR\\\\Uninstall.exe\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"DisplayIcon\\\" \\\"$INSTDIR\\\\share\\\\paranoid_av\\\\icons\\\\shield.ico\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"URLInfoAbout\\\" \\\"https://paranoidlabs.local\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"HelpLink\\\" \\\"https://support.paranoidlabs.local\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"Contact\\\" \\\"support@paranoidlabs.local\\\""
        "WriteRegStr HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"InstallLocation\\\" \\\"$INSTDIR\\\""
        "WriteRegStr HKLM \\\"Software\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"InstallLocation\\\" \\\"$INSTDIR\\\""
    )
    string(JOIN "\n" CPACK_NSIS_EXTRA_INSTALL_COMMANDS ${_paranoid_nsis_install})
    set(_paranoid_nsis_uninstall
        "DeleteRegKey HKLM64 \\\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\""
        "DeleteRegValue HKLM \\\"Software\\\\WOW6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\${PARANOID_REGISTRY_KEY}\\\" \\\"InstallLocation\\\""
    )
    string(JOIN "\n" CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS ${_paranoid_nsis_uninstall})
endif()

set(CPACK_PACKAGE_NAME "ParanoidAntivirusSuite")
set(CPACK_PACKAGE_VENDOR "Paranoid Security Labs")
set(CPACK_PACKAGE_VERSION_MAJOR ${PARANOID_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PARANOID_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PARANOID_VERSION_PATCH})
set(CPACK_PACKAGE_INSTALL_REGISTRY_KEY "${PARANOID_REGISTRY_KEY}")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced host defense and reconnaissance toolkit")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "Paranoid Antivirus Suite")
    set(CPACK_NSIS_PACKAGE_NAME "Paranoid Antivirus Suite")
    set(CPACK_NSIS_CONTACT "support@paranoidlabs.local")
    set(CPACK_NSIS_HELP_LINK "https://support.paranoidlabs.local")
    set(CPACK_NSIS_URL_INFO_ABOUT "https://paranoidlabs.local")
    set(_paranoid_icon "${CMAKE_CURRENT_SOURCE_DIR}/ui/src/assets/ui/shield.ico")
    if(EXISTS ${_paranoid_icon})
        set(CPACK_NSIS_MUI_ICON ${_paranoid_icon})
    endif()
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)
