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
set(CPACK_PACKAGE_NAME "ParanoidAntivirusSuite")
set(CPACK_PACKAGE_VENDOR "Paranoid Security Labs")
set(CPACK_PACKAGE_VERSION_MAJOR ${PARANOID_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PARANOID_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PARANOID_VERSION_PATCH})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced host defense and reconnaissance toolkit")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
    set(CPACK_NSIS_DISPLAY_NAME "Paranoid Antivirus Suite")
    set(CPACK_NSIS_PACKAGE_NAME "Paranoid Antivirus Suite")
    set(CPACK_NSIS_CONTACT "support@paranoidlabs.local")
    set(_paranoid_icon "${CMAKE_CURRENT_SOURCE_DIR}/ui/src/assets/ui/shield.ico")
    if(EXISTS ${_paranoid_icon})
        set(CPACK_NSIS_MUI_ICON ${_paranoid_icon})
    endif()
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)
