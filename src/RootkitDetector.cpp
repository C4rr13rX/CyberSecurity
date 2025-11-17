#include "AntivirusSuite/RootkitDetector.hpp"

#ifndef _WIN32

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_set>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace antivirus {
namespace {

bool readFirstLine(const fs::path &path, std::string &value) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return false;
    }
    std::getline(input, value);
    return true;
}

std::set<std::string> readModuleList() {
    std::ifstream modules("/proc/modules");
    std::set<std::string> names;
    if (!modules.is_open()) {
        return names;
    }
    std::string line;
    while (std::getline(modules, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream stream(line);
        std::string name;
        stream >> name;
        if (!name.empty()) {
            names.insert(name);
        }
    }
    return names;
}

void addFinding(std::vector<RootkitFinding> &findings, std::string indicator, std::string description, double severity,
                std::string evidence, std::string reference, std::string remediation) {
    findings.push_back({std::move(indicator), std::move(description), severity, std::move(evidence), std::move(reference),
                        std::move(remediation)});
}

bool isWritable(const fs::path &path) {
    struct stat st {
    };
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    return (st.st_mode & S_IWOTH) != 0;
}

} // namespace

std::vector<RootkitFinding> RootkitDetector::scan() const {
    std::vector<RootkitFinding> findings;
    scanSuspiciousModules(findings);
    scanHiddenModules(findings);
    scanModuleParameters(findings);
    scanFilesystemArtifacts(findings);
    scanKernelInterfaceProtection(findings);
    return findings;
}

void RootkitDetector::scanSuspiciousModules(std::vector<RootkitFinding> &findings) const {
    static const std::array<const char *, 18> suspiciousModules = {
        "diamorphine", "adore",      "suterusu", "reptile",   "phalanx",   "rootkit",   "knark",     "hide",
        "xkit",        "enmod",      "fisher",   "linrootkit", "linuxku", "hacktool",  "bruteforce", "r0nin",
        "t5ps",        "sinrootkit"};

    const auto loadedModules = readModuleList();
    for (const auto *name : suspiciousModules) {
        if (loadedModules.find(name) != loadedModules.end()) {
            addFinding(findings, "Suspicious module",
                       std::string("Kernel module '") + name + "' is loaded and matches a known rootkit signature.", 9.5,
                       "Module name present in /proc/modules", "T1014",
                       "Investigate module origin and remove if unauthorised. Dump module image for forensic review.");
        }
    }
}

void RootkitDetector::scanHiddenModules(std::vector<RootkitFinding> &findings) const {
    const auto loadedModules = readModuleList();
    std::error_code ec;
    for (const auto &entry : fs::directory_iterator("/sys/module", fs::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        if (!entry.is_directory()) {
            continue;
        }
        const auto name = entry.path().filename().string();
        if (loadedModules.find(name) == loadedModules.end()) {
            addFinding(findings, "Hidden module",
                       "Module '" + name + "' present in /sys/module but missing from /proc/modules (possible hidden LKM).",
                       8.5, entry.path().string(), "T1014",
                       "Cross-check kernel memory for stale module entries and inspect for DKOM-style hiding.");
        }
    }
}

void RootkitDetector::scanModuleParameters(std::vector<RootkitFinding> &findings) const {
    static const std::array<const char *, 6> stealthParameters = {"hide_pid", "hpid", "backdoor", "password", "hideme",
                                                                  "conceal"};

    std::error_code ec;
    for (const auto &moduleDir : fs::directory_iterator("/sys/module", fs::directory_options::skip_permission_denied, ec)) {
        if (ec) {
            ec.clear();
            continue;
        }
        const auto paramsDir = moduleDir.path() / "parameters";
        if (!fs::exists(paramsDir)) {
            continue;
        }
        for (const auto &paramEntry : fs::directory_iterator(paramsDir, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            const auto paramName = paramEntry.path().filename().string();
            if (std::find(stealthParameters.begin(), stealthParameters.end(), paramName) == stealthParameters.end()) {
                continue;
            }
            std::string value;
            if (!readFirstLine(paramEntry.path(), value)) {
                continue;
            }
            if (value.empty() || value == "0" || value == "false") {
                continue;
            }
            addFinding(findings, "Stealth parameter",
                       "Module '" + moduleDir.path().filename().string() + "' exposes parameter '" + paramName +
                           "' with suspicious value '" + value + "'.",
                       8.0, paramEntry.path().string(), "T1014",
                       "Reset module parameter and validate module provenance. Rootkits often use these toggles to hide.");
        }
    }
}

void RootkitDetector::scanFilesystemArtifacts(std::vector<RootkitFinding> &findings) const {
    struct Artifact {
        const char *path;
        const char *description;
        double severity;
        const char *remediation;
    };

    static const std::array<Artifact, 12> artifacts = {{{"/etc/rc.d/init.d/kbd", "Legacy init script favoured by Rkit variants.",
                                                         7.5, "Inspect script contents and disable unauthorised init hooks."},
                                                        {"/dev/.lib", "Hidden /dev/.lib directory often used by adore-ng.", 8.0,
                                                         "Unmount or remove hidden directory after forensic capture."},
                                                        {"/dev/.lib/libkeystroke.so", "Keylogging shared object dropped by adore variants.", 9.0,
                                                         "Capture binary and remove directory. Hunt for LD_PRELOAD abuse."},
                                                        {"/usr/lib/libkeystroke.so", "Keystroke capture library frequently deployed by knark.", 9.0,
                                                         "Quarantine binary and review recent login activity."},
                                                        {"/etc/cron.d/zzz", "Suspicious cron payload placeholder used by multiple rootkits.", 7.5,
                                                         "Disable cron entry and review persistence timeline."},
                                                        {"/etc/.java", "Hidden configuration store leveraged by Suterusu.", 7.0,
                                                         "Inspect directory for rogue binaries or scripts."},
                                                        {"/bin/.ps", "Shadow ps binary used for process cloaking.", 8.5,
                                                         "Compare checksum with vendor baseline and restore trusted binary."},
                                                        {"/usr/sbin/.sshd", "Hidden sshd dropbear backdoor.", 8.5,
                                                         "Assess active listeners and remove unauthorised binaries."},
                                                        {"/etc/ld.so.hash", "Interposer map created by LD_PRELOAD rootkits.", 8.0,
                                                         "Review LD config and purge malicious loaders."},
                                                        {"/etc/init.d/selinux", "Fake SELinux init script used for persistence.", 7.0,
                                                         "Audit SELinux packages and remove rogue scripts."},
                                                        {"/etc/securetty.bak", "Backup securetty placed by t5ps family.", 6.5,
                                                         "Restore canonical securetty and rotate credentials."},
                                                        {"/etc/cron.d/rootkit", "Cron entry naming convention flagging likely compromise.", 9.0,
                                                         "Disable cron artefact and perform credential review."}}};

    for (const auto &artifact : artifacts) {
        std::error_code ec;
        if (!fs::exists(artifact.path, ec)) {
            continue;
        }
        addFinding(findings, "Filesystem artefact", artifact.description, artifact.severity, artifact.path, "T1037",
                   artifact.remediation);
    }

    // Hidden writable directories in /dev or /usr/local
    const std::array<fs::path, 2> roots = {fs::path{"/dev"}, fs::path{"/usr/local"}};
    for (const auto &root : roots) {
        std::error_code iterateError;
        for (const auto &entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied, iterateError)) {
            if (iterateError) {
                iterateError.clear();
                continue;
            }
            if (!entry.is_directory()) {
                continue;
            }
            const auto name = entry.path().filename().string();
            if (name.empty() || name[0] != '.') {
                continue;
            }
            if (isWritable(entry.path())) {
                addFinding(findings, "Hidden writable directory",
                           "Directory '" + entry.path().string() + "' is hidden and world-writable, a common rootkit stash.",
                           7.5, entry.path().string(), "T1098",
                           "Capture contents then remove directory. Harden mount permissions to prevent recreation.");
            }
        }
    }
}

void RootkitDetector::scanKernelInterfaceProtection(std::vector<RootkitFinding> &findings) const {
    std::string value;
    if (readFirstLine("/proc/sys/kernel/modules_disabled", value)) {
        if (value == "0") {
            addFinding(findings, "Module locking disabled",
                       "kernel.modules_disabled is 0 allowing runtime module loading (post-rootkit persistence risk).", 6.5,
                       "/proc/sys/kernel/modules_disabled", "T1547",
                       "Set kernel.modules_disabled=1 after loading trusted modules to block late-stage implants.");
        }
    }

    if (readFirstLine("/proc/sys/kernel/kptr_restrict", value)) {
        if (value == "0") {
            addFinding(findings, "Kernel pointer exposure",
                       "kptr_restrict is disabled, exposing kernel addresses to user space (useful for LKM attackers).", 5.5,
                       "/proc/sys/kernel/kptr_restrict", "T1068",
                       "Set kernel.kptr_restrict=2 to hide addresses and frustrate rootkit exploit chains.");
        }
    }

    if (readFirstLine("/proc/sys/kernel/dmesg_restrict", value)) {
        if (value == "0") {
            addFinding(findings, "dmesg unrestricted",
                       "dmesg_restrict is 0 allowing unprivileged dmesg reads that leak kernel layout info.", 4.5,
                       "/proc/sys/kernel/dmesg_restrict", "T1068",
                       "Set kernel.dmesg_restrict=1 and audit for tampering with syslog configurations.");
        }
    }
}

} // namespace antivirus

#else

namespace antivirus {

std::vector<RootkitFinding> RootkitDetector::scan() const {
    return {};
}

} // namespace antivirus

#endif // _WIN32
