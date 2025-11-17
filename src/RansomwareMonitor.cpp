#include "AntivirusSuite/RansomwareMonitor.hpp"

#ifdef _WIN32

namespace antivirus {

RansomwareSummary RansomwareMonitor::watch(const std::string &path, std::chrono::seconds) const {
    RansomwareSummary summary;
    summary.findings.push_back({path, "Ransomware monitoring requires Linux inotify support."});
    return summary;
}

} // namespace antivirus

#else

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <map>
#include <stdexcept>
#include <string>
#include <sys/inotify.h>
#include <sys/select.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;

namespace antivirus {

namespace {

constexpr std::size_t BufferSize = 4096;

void addWatchRecursive(int fd, const fs::path &path, std::map<int, fs::path> &watchMap) {
    std::error_code ec;
    if (!fs::exists(path, ec) || !fs::is_directory(path, ec)) {
        throw std::runtime_error("Path is not a directory: " + path.string());
    }

    const int wd = inotify_add_watch(fd, path.c_str(), IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE);
    if (wd < 0) {
        throw std::runtime_error("Failed to watch " + path.string());
    }
    watchMap.emplace(wd, path);

    for (auto it = fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (!it->is_directory(ec)) {
            continue;
        }
        const int childWd = inotify_add_watch(fd, it->path().c_str(),
                                              IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO | IN_MOVED_FROM | IN_DELETE);
        if (childWd >= 0) {
            watchMap.emplace(childWd, it->path());
        }
    }
}

std::string joinPath(const fs::path &base, const std::string &leaf) {
    return (base / leaf).string();
}

} // namespace

RansomwareSummary RansomwareMonitor::watch(const std::string &path, std::chrono::seconds duration) const {
    const int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {
        throw std::runtime_error("Unable to initialize inotify");
    }

    std::map<int, fs::path> watchMap;
    try {
        addWatchRecursive(fd, path, watchMap);
    } catch (...) {
        close(fd);
        throw;
    }

    const auto end = std::chrono::steady_clock::now() + duration;
    RansomwareSummary summary;

    std::vector<char> buffer(BufferSize);
    while (std::chrono::steady_clock::now() < end) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(fd, &readSet);

        struct timeval timeout {
            0, 500000
        };

        const int ready = select(fd + 1, &readSet, nullptr, nullptr, &timeout);
        if (ready <= 0) {
            continue;
        }

        const ssize_t bytes = read(fd, buffer.data(), buffer.size());
        if (bytes <= 0) {
            continue;
        }

        ssize_t offset = 0;
        while (offset < bytes) {
            const auto *event = reinterpret_cast<const inotify_event *>(buffer.data() + offset);
            offset += sizeof(inotify_event) + event->len;
            summary.totalEvents++;

            const auto watchIt = watchMap.find(event->wd);
            if (watchIt == watchMap.end()) {
                continue;
            }
            const auto absolute = joinPath(watchIt->second, event->len > 0 ? event->name : "");

            if (event->mask & (IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO)) {
                if (isEncryptionExtension(absolute)) {
                    summary.suspectedEncryptions++;
                    summary.findings.push_back({absolute, "File extension resembles ransomware artifact"});
                }
            }
            if (event->mask & IN_DELETE) {
                summary.findings.push_back({absolute, "File deleted during monitoring window"});
            }
        }
    }

    close(fd);
    return summary;
}

bool RansomwareMonitor::isEncryptionExtension(const std::string &path) {
    static const std::vector<std::string> extensions = {
        ".lock", ".locked", ".encrypted", ".enc", ".crypt", ".rnsm", ".pay"};
    return std::any_of(extensions.begin(), extensions.end(), [&](const std::string &ext) {
        if (path.size() < ext.size()) {
            return false;
        }
        return std::equal(ext.rbegin(), ext.rend(), path.rbegin(),
                          [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) ==
                                                       std::tolower(static_cast<unsigned char>(b)); });
    });
}

} // namespace antivirus

#endif // _WIN32

