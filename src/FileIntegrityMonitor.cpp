#include "AntivirusSuite/FileIntegrityMonitor.hpp"

#include "AntivirusSuite/Crypto.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace fs = std::filesystem;

namespace antivirus {

namespace {

struct BaselineEntry {
    std::string path;
    std::uintmax_t size{0};
    std::uintmax_t mtime{0};
    std::string hash;
};

std::string serialize(const BaselineEntry &entry) {
    std::ostringstream oss;
    oss << entry.path << '|' << entry.size << '|' << entry.mtime << '|' << entry.hash;
    return oss.str();
}

BaselineEntry deserialize(const std::string &line) {
    BaselineEntry entry;
    std::istringstream stream(line);
    std::string sizeStr;
    std::string mtimeStr;
    std::getline(stream, entry.path, '|');
    std::getline(stream, sizeStr, '|');
    std::getline(stream, mtimeStr, '|');
    std::getline(stream, entry.hash);
    if (!sizeStr.empty()) {
        entry.size = static_cast<std::uintmax_t>(std::stoull(sizeStr));
    }
    if (!mtimeStr.empty()) {
        entry.mtime = static_cast<std::uintmax_t>(std::stoull(mtimeStr));
    }
    return entry;
}

std::uintmax_t getMtime(const fs::directory_entry &entry) {
    std::error_code ec;
    const auto ftime = entry.last_write_time(ec);
    if (ec) {
        return 0;
    }
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(ftime.time_since_epoch());
    return static_cast<std::uintmax_t>(seconds.count());
}

} // namespace

void FileIntegrityMonitor::createBaseline(const std::string &root, const std::string &baselineFile) const {
    std::ofstream output(baselineFile, std::ios::out | std::ios::trunc);
    if (!output.is_open()) {
        throw std::runtime_error("Unable to write baseline " + baselineFile);
    }

    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied);
         it != fs::recursive_directory_iterator(); ++it) {
        std::error_code statusEc;
        if (!it->is_regular_file(statusEc)) {
            continue;
        }
        BaselineEntry entry;
        entry.path = fs::relative(it->path(), root).string();
        entry.size = it->file_size(statusEc);
        entry.mtime = getMtime(*it);
        entry.hash = hashFile(it->path().string());
        output << serialize(entry) << '\n';
    }
}

FileIntegrityReport FileIntegrityMonitor::verifyBaseline(const std::string &root, const std::string &baselineFile) const {
    std::ifstream input(baselineFile);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to read baseline " + baselineFile);
    }

    std::unordered_map<std::string, BaselineEntry> baseline;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty()) {
            continue;
        }
        const auto entry = deserialize(line);
        baseline.emplace(entry.path, entry);
    }

    FileIntegrityReport report;
    report.baselinePath = baselineFile;

    std::unordered_map<std::string, bool> seen;
    for (const auto &pair : baseline) {
        seen.emplace(pair.first, false);
    }

    for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied);
         it != fs::recursive_directory_iterator(); ++it) {
        std::error_code statusEc;
        if (!it->is_regular_file(statusEc)) {
            continue;
        }
        const auto relative = fs::relative(it->path(), root).string();
        const auto baselineIt = baseline.find(relative);
        if (baselineIt == baseline.end()) {
            report.added.push_back({relative, "New file discovered"});
            continue;
        }

        seen[relative] = true;
        const auto &entry = baselineIt->second;
        const auto currentHash = hashFile(it->path().string());
        if (currentHash != entry.hash) {
            report.modified.push_back({relative, "Hash mismatch"});
        }
    }

    for (const auto &pair : seen) {
        if (!pair.second) {
            report.missing.push_back({pair.first, "File missing from disk"});
        }
    }

    return report;
}

std::string FileIntegrityMonitor::hashFile(const std::string &path) {
    return crypto::sha256File(path);
}

} // namespace antivirus

