#include "AntivirusSuite/QuarantineManager.hpp"

#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace antivirus {

QuarantineManager::QuarantineManager(std::string quarantineRoot) : root(std::move(quarantineRoot)) {
    std::error_code ec;
    fs::create_directories(root, ec);
}

std::string QuarantineManager::quarantineFile(const std::string &path) const {
    fs::path source(path);
    if (!fs::exists(source)) {
        throw std::runtime_error("File not found: " + path);
    }

    const auto destination = fs::path(root) / (source.filename().string() + ".quarantine");
    std::error_code ec;
    fs::rename(source, destination, ec);
    if (ec) {
        throw std::runtime_error("Unable to move file to quarantine: " + ec.message());
    }

#ifndef _WIN32
    ::chmod(destination.c_str(), 0600);
#endif
    return destination.string();
}

bool QuarantineManager::terminateProcess(int pid, bool force) const {
#ifdef _WIN32
    const DWORD exitCode = force ? 1 : 0;
    HANDLE process = OpenProcess(PROCESS_TERMINATE, FALSE, static_cast<DWORD>(pid));
    if (!process) {
        return false;
    }
    const BOOL terminated = TerminateProcess(process, exitCode);
    CloseHandle(process);
    return terminated == TRUE;
#else
    const int signal = force ? SIGKILL : SIGTERM;
    if (::kill(pid, signal) != 0) {
        return false;
    }
    return true;
#endif
}

} // namespace antivirus

