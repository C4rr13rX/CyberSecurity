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
)

target_include_directories(paranoid_av PRIVATE include)

target_compile_options(paranoid_av PRIVATE -Wall -Wextra -Wpedantic)

find_package(Threads REQUIRED)
target_link_libraries(paranoid_av PRIVATE Threads::Threads)
