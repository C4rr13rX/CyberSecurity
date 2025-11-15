#include "AntivirusSuite/HeuristicAnalyzer.hpp"

#include "AntivirusSuite/ProcessScanner.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace antivirus {

namespace {

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool hasSuspiciousPrefix(const std::string &value) {
    static const std::vector<std::string> prefixes = {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"
    };
    return std::any_of(prefixes.begin(), prefixes.end(), [&](const std::string &prefix) {
        return value.rfind(prefix, 0) == 0;
    });
}

bool containsAny(const std::string &value, const std::vector<std::string> &patterns) {
    return std::any_of(patterns.begin(), patterns.end(), [&](const std::string &pattern) {
        return value.find(pattern) != std::string::npos;
    });
}

std::vector<std::string> split(const std::string &value, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream stream(value);
    while (std::getline(stream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

bool hasRWX(const std::string &permissions) {
    return permissions.size() >= 3 && permissions[0] == 'r' && permissions[1] == 'w' && permissions[2] == 'x';
}

bool isLikelyAnonymousExecutable(const MemoryRegion &region) {
    return region.permissions.find('x') != std::string::npos && region.anonymous;
}

bool isLoopback(const std::string &address) {
    return address == "127.0.0.1" || address == "::1";
}

bool isPrivateIPv6(const std::string &address) {
    if (address.size() >= 2) {
        const auto prefix = toLower(address.substr(0, 2));
        if (prefix == "fc" || prefix == "fd") {
            return true;
        }
    }
    return address.rfind("fe80", 0) == 0;
}

std::string extractHost(const NetworkEndpoint &endpoint) {
    return endpoint.address;
}

} // namespace

HeuristicAnalyzer::HeuristicAnalyzer() {
    suspiciousBinaries = {
        "nc", "netcat", "socat", "nmap", "masscan", "hydra", "sqlmap",
        "mimikatz", "powershell", "cmd.exe", "certutil", "python", "perl",
        "ruby", "php", "lua", "bash", "sh"
    };

    suspiciousSubstrings = {
        "--connect", "-e /bin/sh", "-EncodedCommand", "powershell -enc",
        "base64", "chmod 777", "curl http", "wget http", "nc -l", "sleep 9999",
        "Invoke-WebRequest", "powershell.exe -nop"
    };

    highRiskCapabilities = {
        "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_SYS_RAWIO", "CAP_SYSLOG"
    };
}

void HeuristicAnalyzer::addFinding(HeuristicReport &report, std::string description, double weight, std::string reference) {
    report.score += weight;
    report.findings.push_back({std::move(description), weight, std::move(reference)});
}

bool HeuristicAnalyzer::isInterpreter(const std::string &cmdline) {
    static const std::vector<std::string> interpreters = {
        "python", "perl", "ruby", "php", "lua", "bash", "sh", "pwsh", "powershell"
    };
    const auto lowered = toLower(cmdline);
    return containsAny(lowered, interpreters);
}

bool HeuristicAnalyzer::isPrivateIPv4(const std::string &address) {
    if (address.rfind("10.", 0) == 0 || address.rfind("127.", 0) == 0) {
        return true;
    }
    if (address.rfind("192.168.", 0) == 0) {
        return true;
    }
    if (address.rfind("172.", 0) == 0 && address.size() > 4) {
        try {
            const auto second = std::stoi(address.substr(4));
            return second >= 16 && second <= 31;
        } catch (...) {
            return false;
        }
    }
    return false;
}

bool HeuristicAnalyzer::isExternalAddress(const std::string &address) {
    if (address.empty()) {
        return false;
    }
    if (isLoopback(address)) {
        return false;
    }
    if (address.find('.') != std::string::npos) {
        return !isPrivateIPv4(address);
    }
    return !isPrivateIPv6(address);
}

HeuristicReport HeuristicAnalyzer::analyze(const ProcessInfo &process) const {
    HeuristicReport report;

    if (process.exePath.empty() && process.cmdline.empty()) {
        addFinding(report, "Process has no executable path and empty command line (possible masquerading).", 8.0, "T1036");
    }

    if (!process.exePath.empty() && hasSuspiciousPrefix(process.exePath)) {
        addFinding(report, "Executable running from temporary location: " + process.exePath, 7.0, "T1055");
    }

    if (!process.exePath.empty() && process.exePath.find("(deleted)") != std::string::npos) {
        addFinding(report, "Process executing binary that has been deleted from disk: " + process.exePath, 8.0, "T1105");
    }

    if (!process.cwd.empty() && hasSuspiciousPrefix(process.cwd)) {
        addFinding(report, "Process working directory located in temporary path: " + process.cwd, 5.0, "T1105");
    }

    if (containsAny(toLower(process.cmdline), suspiciousSubstrings)) {
        addFinding(report, "Command line contains suspicious pattern: " + process.cmdline, 6.0, "T1059");
    }

    if (!process.name.empty()) {
        if (containsAny(toLower(process.name), suspiciousBinaries)) {
            addFinding(report, "Binary name matches suspicious tool list: " + process.name, 5.5, "S0039");
        }
    }

    const auto state = process.metadata.find("State");
    if (state != process.metadata.end() && state->second.find("Z") != std::string::npos) {
        addFinding(report, "Process is in zombie state (possible injection cleanup).", 3.0, "T1055");
    }

    if (process.user == "root") {
        if (!process.exePath.empty() && process.exePath.rfind("/home/", 0) == 0) {
            addFinding(report, "Privileged process executing from user home directory: " + process.exePath, 8.5, "T1078");
        }
        if (!process.cmdline.empty() && isInterpreter(process.cmdline)) {
            addFinding(report, "Privileged interpreter execution detected: " + process.cmdline, 7.0, "T1059");
        }
    }

    if (!process.exePath.empty() && process.exeHash.empty()) {
        addFinding(report, "Executable hash unavailable (binary may be transient or unreadable).", 4.0, "T1105");
    }

    const auto tracerIt = process.metadata.find("TracerPid");
    if (tracerIt != process.metadata.end() && !tracerIt->second.empty() && tracerIt->second != "0") {
        addFinding(report, "Process is being traced by PID " + tracerIt->second, 5.5, "T1055");
    }

    for (const auto &cap : process.effectiveCapabilities) {
        if (std::find(highRiskCapabilities.begin(), highRiskCapabilities.end(), cap) != highRiskCapabilities.end()) {
            addFinding(report, "High-risk capability in effect: " + cap, 6.5, "T1548");
        }
    }

    if (!process.seccompMode.empty() && process.seccompMode == "0" && !process.connections.empty()) {
        addFinding(report, "Networked process without seccomp restrictions.", 3.5, "M1038");
    }

    if (process.connections.size() > 8) {
        addFinding(report, "Process maintains unusually high number of sockets (" + std::to_string(process.connections.size()) + ").", 2.5, "T1095");
    }

    for (const auto &connection : process.connections) {
        if (connection.remote.port == 0) {
            continue;
        }
        const auto remoteHost = extractHost(connection.remote);
        if (isExternalAddress(remoteHost)) {
            addFinding(report, "External network connection to " + remoteHost + ':' + std::to_string(connection.remote.port) +
                                 " via " + connection.protocol, 6.0, "T1041");
            break;
        }
    }

    for (const auto &connection : process.connections) {
        if (!connection.listening) {
            continue;
        }
        if (connection.local.port > 0 && connection.local.port < 1024 && process.user != "root") {
            addFinding(report, 
                       "Process is binding privileged port " + std::to_string(connection.local.port) + " without root privileges.",
                       7.0, "T1040");
            break;
        }
    }

    for (const auto &region : process.memoryRegions) {
        if (hasRWX(region.permissions)) {
            addFinding(report, "Writable and executable memory region present: " + region.addressRange + " " + region.path, 7.5, "T1620");
        }
        if (isLikelyAnonymousExecutable(region)) {
            addFinding(report, "Anonymous executable memory region detected: " + region.addressRange, 8.0, "T1620");
        }
        if (!region.path.empty() && !region.anonymous && hasSuspiciousPrefix(region.path) && region.path.find(".so") != std::string::npos) {
            addFinding(report, "Shared object mapped from writable location: " + region.path, 8.5, "T1055");
        }
    }

    if (!process.namespaces.empty()) {
        const bool hasUserNs = std::any_of(process.namespaces.begin(), process.namespaces.end(), [](const std::string &ns) {
            return ns.rfind("user", 0) == 0;
        });
        if (hasUserNs && process.user == "root") {
            addFinding(report, "Root process executing inside user namespace (potential container breakout).", 4.5, "T1611");
        }
    }

    if (!process.cmdline.empty() && process.cmdline.size() > 4096) {
        addFinding(report, "Extremely long command line (potentially obfuscated payload).", 4.0, "T1027");
    }

    const auto envEnd = process.environment.end();
    const auto preloadIt = process.environment.find("LD_PRELOAD");
    if (preloadIt != envEnd && !preloadIt->second.empty()) {
        const double weight = hasSuspiciousPrefix(preloadIt->second) ? 9.0 : 7.5;
        addFinding(report, "LD_PRELOAD set to " + preloadIt->second, weight, "T1574");
    }

    const auto libraryPathIt = process.environment.find("LD_LIBRARY_PATH");
    if (libraryPathIt != envEnd && !libraryPathIt->second.empty()) {
        const auto segments = split(libraryPathIt->second, ':');
        for (const auto &segment : segments) {
            if (hasSuspiciousPrefix(segment)) {
                addFinding(report, "LD_LIBRARY_PATH contains writable directory: " + segment, 7.5, "T1574");
                break;
            }
        }
    }

    const auto pathIt = process.environment.find("PATH");
    if (pathIt != envEnd && !pathIt->second.empty()) {
        const auto entries = split(pathIt->second, ':');
        if (!entries.empty()) {
            if (entries.front() == ".") {
                addFinding(report, "PATH begins with current directory entry.", 5.5, "T1036");
            } else if (hasSuspiciousPrefix(entries.front())) {
                addFinding(report, "PATH begins with writable directory: " + entries.front(), 6.5, "T1036");
            }
        }
        for (const auto &entry : entries) {
            if (entry.empty()) {
                continue;
            }
            if (entry == "." || hasSuspiciousPrefix(entry)) {
                addFinding(report, "PATH contains writable entry: " + entry, 4.0, "T1036");
                break;
            }
        }
    }

    const auto sshSockIt = process.environment.find("SSH_AUTH_SOCK");
    if (sshSockIt != envEnd && hasSuspiciousPrefix(sshSockIt->second)) {
        addFinding(report, "SSH agent socket located in writable path: " + sshSockIt->second, 5.5, "T1552");
    }

    return report;
}

} // namespace antivirus
