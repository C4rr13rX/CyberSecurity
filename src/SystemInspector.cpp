#include "AntivirusSuite/SystemInspector.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <unordered_map>

namespace fs = std::filesystem;

namespace antivirus {

namespace {

bool endsWith(const std::string &value, const std::string &suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string trim(const std::string &input) {
    const auto start = input.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = input.find_last_not_of(" \t\r\n");
    return input.substr(start, end - start + 1);
}

bool isWorldWritable(mode_t mode) {
    return (mode & S_IWOTH) != 0;
}

bool isGroupWritable(mode_t mode) {
    return (mode & S_IWGRP) != 0;
}

void addFinding(std::vector<SystemFinding> &findings, std::string category, std::string description, double severity,
                std::string reference) {
    findings.push_back({std::move(category), std::move(description), severity, std::move(reference)});
}

std::unordered_map<std::string, fs::path> buildModuleIndex() {
    std::unordered_map<std::string, fs::path> index;
    struct utsname info {
    };
    if (uname(&info) != 0) {
        return index;
    }
    fs::path modulesRoot = fs::path("/lib/modules") / info.release;
    std::error_code ec;
    if (!fs::exists(modulesRoot, ec)) {
        return index;
    }

    for (fs::recursive_directory_iterator it(modulesRoot, fs::directory_options::skip_permission_denied, ec);
         it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        std::error_code statusEc;
        if (!it->is_regular_file(statusEc)) {
            continue;
        }
        auto filename = it->path().filename().string();
        if (!endsWith(filename, ".ko") && !endsWith(filename, ".ko.xz")) {
            continue;
        }
        if (endsWith(filename, ".xz")) {
            filename.erase(filename.size() - 3);
        }
        if (endsWith(filename, ".ko")) {
            filename.erase(filename.size() - 3);
        }
        index.emplace(std::move(filename), it->path());
    }
    return index;
}

std::string resolveSymlinkTarget(const fs::path &path) {
    std::error_code ec;
    const auto target = fs::read_symlink(path, ec);
    if (ec) {
        return {};
    }
    return target.string();
}

bool checkFileMetadata(const fs::path &path, struct stat &buffer) {
    if (lstat(path.c_str(), &buffer) != 0) {
        return false;
    }
    return true;
}

} // namespace

bool SystemInspector::isSuspiciousPath(const std::string &path) {
    static const std::vector<std::string> prefixes = {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"};
    return std::any_of(prefixes.begin(), prefixes.end(), [&](const std::string &prefix) {
        return path.rfind(prefix, 0) == 0;
    });
}

std::vector<SystemFinding> SystemInspector::scanAll() const {
    std::vector<SystemFinding> findings;
    scanKernelModules(findings);
    scanPersistenceArtifacts(findings);
    scanSetuidBinaries(findings);
    scanLdPreload(findings);
    scanPrivilegedAccounts(findings);
    return findings;
}

void SystemInspector::scanKernelModules(std::vector<SystemFinding> &findings) const {
    std::ifstream modules("/proc/modules");
    if (!modules.is_open()) {
        return;
    }

    const auto moduleIndex = buildModuleIndex();
    std::string line;
    while (std::getline(modules, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream stream(line);
        std::string name;
        std::string size;
        std::string refCount;
        std::string deps;
        std::string state;
        stream >> name >> size >> refCount >> deps >> state;
        if (name.empty()) {
            continue;
        }

        const auto pathIt = moduleIndex.find(name);
        if (pathIt == moduleIndex.end()) {
            addFinding(findings, "Kernel Module",
                       "Loaded kernel module " + name + " missing from /lib/modules tree (potentially injected).", 8.5,
                       "T1014");
        } else if (isSuspiciousPath(pathIt->second.string())) {
            addFinding(findings, "Kernel Module",
                       "Kernel module " + name + " resolved to writable path " + pathIt->second.string() + '.', 8.5, "T1014");
        }

        if (!state.empty() && state != "Live") {
            addFinding(findings, "Kernel Module",
                       "Module " + name + " state=" + state + " (not Live).", 6.5, "T1014");
        }

        std::ifstream taintFile("/sys/module/" + name + "/taint");
        if (taintFile.is_open()) {
            std::string taint;
            std::getline(taintFile, taint);
            taint = trim(taint);
            if (!taint.empty() && taint != "0") {
                addFinding(findings, "Kernel Module",
                           "Module " + name + " taint flag=" + taint + " (kernel marked tainted).", 7.5, "T1014");
            }
        }
    }
}

void SystemInspector::scanPersistenceArtifacts(std::vector<SystemFinding> &findings) const {
    const std::vector<fs::path> directories = {
        "/etc/cron.d",     "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
        "/etc/systemd/system", "/etc/systemd/user", "/etc/profile.d"
    };

    for (const auto &dir : directories) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) {
            continue;
        }
        for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            struct stat st {
            };
            if (!checkFileMetadata(it->path(), st)) {
                continue;
            }
            if (S_ISDIR(st.st_mode)) {
                continue;
            }

            std::ostringstream reason;
            double severity = 0.0;
            if (S_ISLNK(st.st_mode)) {
                const auto target = resolveSymlinkTarget(it->path());
                reason << "Symlink -> " << target;
                severity = 6.0;
                if (isSuspiciousPath(target)) {
                    severity = std::max(severity, 8.0);
                    reason << " (writable target)";
                }
            }
            if (st.st_uid != 0) {
                if (!reason.str().empty()) {
                    reason << "; ";
                }
                reason << "owned by UID " << st.st_uid;
                severity = std::max(severity, 7.0);
            }
            if (isWorldWritable(st.st_mode) || isGroupWritable(st.st_mode)) {
                if (!reason.str().empty()) {
                    reason << "; ";
                }
                reason << "permissions=" << std::oct << (st.st_mode & 07777);
                severity = std::max(severity, 7.5);
            }

            if (severity > 0.0) {
                addFinding(findings, "Persistence",
                           "Suspicious persistence candidate " + it->path().string() + " -> " + reason.str(), severity,
                           "T1053");
            }
        }
    }

    const std::vector<fs::path> files = {"/etc/rc.local", "/etc/cron.deny"};
    for (const auto &file : files) {
        struct stat st {
        };
        if (!checkFileMetadata(file, st)) {
            continue;
        }
        if (st.st_uid != 0 || isWorldWritable(st.st_mode)) {
            std::ostringstream reason;
            reason << "owner=" << st.st_uid << " mode=" << std::oct << (st.st_mode & 07777);
            addFinding(findings, "Persistence", "/etc/rc.local permissions unexpectedly relaxed -> " + reason.str(), 7.5,
                       "T1037");
        }
    }
}

void SystemInspector::scanSetuidBinaries(std::vector<SystemFinding> &findings) const {
    const std::vector<fs::path> roots = {"/tmp", "/var/tmp", "/dev/shm", "/run", "/home"};
    for (const auto &root : roots) {
        std::error_code ec;
        if (!fs::exists(root, ec)) {
            continue;
        }
        for (fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec);
             it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            struct stat st {
            };
            if (!checkFileMetadata(it->path(), st)) {
                continue;
            }
            if (!S_ISREG(st.st_mode)) {
                continue;
            }
            if ((st.st_mode & S_ISUID) != 0 && st.st_uid == 0) {
                addFinding(findings, "Privilege Escalation",
                           "Setuid root binary " + it->path().string() + " located in untrusted directory.", 9.0, "T1548");
            } else if ((st.st_mode & S_ISGID) != 0 && st.st_gid == 0) {
                addFinding(findings, "Privilege Escalation",
                           "Setgid root binary " + it->path().string() + " located in untrusted directory.", 8.0, "T1548");
            }
        }
    }
}

void SystemInspector::scanLdPreload(std::vector<SystemFinding> &findings) const {
    std::ifstream preload("/etc/ld.so.preload");
    if (!preload.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(preload, line)) {
        const auto trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#') {
            continue;
        }
        const double severity = isSuspiciousPath(trimmed) ? 9.0 : 8.0;
        addFinding(findings, "Boot Integrity", "/etc/ld.so.preload entry: " + trimmed, severity, "T1574");
    }
}

void SystemInspector::scanPrivilegedAccounts(std::vector<SystemFinding> &findings) const {
    std::ifstream passwd("/etc/passwd");
    if (!passwd.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(passwd, line)) {
        if (line.empty()) {
            continue;
        }
        std::vector<std::string> parts;
        std::string token;
        std::istringstream stream(line);
        while (std::getline(stream, token, ':')) {
            parts.push_back(token);
        }
        if (parts.size() < 7) {
            continue;
        }
        const auto &username = parts[0];
        const auto &uidString = parts[2];
        const auto &home = parts[5];
        const auto &shell = parts[6];
        int uid = 0;
        try {
            uid = std::stoi(uidString);
        } catch (...) {
            continue;
        }

        if (uid == 0 && username != "root") {
            addFinding(findings, "Account",
                       "Additional UID 0 account detected: " + username + " home=" + home + " shell=" + shell, 8.0,
                       "T1136");
        }

        if (uid == 0 && isSuspiciousPath(home)) {
            addFinding(findings, "Account",
                       "Root-level account " + username + " home directory in writable path: " + home, 7.0, "T1036");
        }
    }
}

} // namespace antivirus

