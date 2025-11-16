#include "AntivirusSuite/QuarantineManager.hpp"

#include <csignal>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

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

    ::chmod(destination.c_str(), 0600);
    return destination.string();
}

bool QuarantineManager::terminateProcess(int pid, bool force) const {
    const int signal = force ? SIGKILL : SIGTERM;
    if (::kill(pid, signal) != 0) {
        return false;
    }
    return true;
}

} // namespace antivirus

