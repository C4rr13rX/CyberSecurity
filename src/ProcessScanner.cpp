#include "AntivirusSuite/ProcessScanner.hpp"

#include "AntivirusSuite/Crypto.hpp"

#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <pwd.h>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>

namespace fs = std::filesystem;

namespace antivirus {

namespace {

std::string trim(const std::string &value) {
    const auto start = value.find_first_not_of(" \n\r\t\f\v");
    if (start == std::string::npos) {
        return "";
    }
    const auto end = value.find_last_not_of(" \n\r\t\f\v");
    return value.substr(start, end - start + 1);
}

std::string toIso8601(std::time_t value) {
    std::tm tm{};
    gmtime_r(&value, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

} // namespace

bool ProcessScanner::isNumericDirectory(const std::string &value) {
    if (value.empty()) {
        return false;
    }
    for (char c : value) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

std::string ProcessScanner::readFile(const std::string &path, bool replaceNull) {
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input.is_open()) {
        return "";
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    std::string value = buffer.str();
    if (replaceNull) {
        for (char &ch : value) {
            if (ch == '\0') {
                ch = ' ';
            }
        }
    }
    return trim(value);
}

std::string ProcessScanner::readLink(const std::string &path) {
    std::error_code ec;
    auto target = fs::read_symlink(path, ec);
    if (ec) {
        return "";
    }
    return target.string();
}

std::string ProcessScanner::readStatusValue(const std::string &statusContent, const std::string &key) {
    std::istringstream stream(statusContent);
    std::string line;
    const auto prefix = key + ':';
    while (std::getline(stream, line)) {
        if (line.rfind(prefix, 0) == 0) {
            return trim(line.substr(prefix.size()));
        }
    }
    return "";
}

std::vector<ProcessInfo> ProcessScanner::snapshotProcesses() const {
    std::vector<ProcessInfo> processes;
    struct sysinfo sysInfo {};
    const bool haveSysInfo = (sysinfo(&sysInfo) == 0);

    for (const auto &entry : fs::directory_iterator("/proc")) {
        if (!entry.is_directory()) {
            continue;
        }
        const auto filename = entry.path().filename().string();
        if (!isNumericDirectory(filename)) {
            continue;
        }

        ProcessInfo info;
        info.pid = std::stoi(filename);

        const auto basePath = entry.path().string();
        const auto statusContent = readFile(basePath + "/status", true);
        info.name = readStatusValue(statusContent, "Name");
        const auto uidString = readStatusValue(statusContent, "Uid");
        if (!uidString.empty()) {
            std::istringstream uidStream(uidString);
            uid_t realUid = 0;
            uidStream >> realUid;
            if (struct passwd *pwd = getpwuid(realUid)) {
                info.user = pwd->pw_name;
            } else {
                info.user = std::to_string(realUid);
            }
        }
        info.cmdline = readFile(basePath + "/cmdline");
        info.exePath = readLink(basePath + "/exe");
        info.cwd = readLink(basePath + "/cwd");
        if (!info.exePath.empty()) {
            info.exeHash = crypto::sha256File(info.exePath);
            info.exeWorldWritable = isWorldWritable(info.exePath);
        }
        if (!info.cwd.empty()) {
            info.cwdWorldWritable = isWorldWritable(info.cwd);
        }
        info.metadata["VmRSS"] = readStatusValue(statusContent, "VmRSS");
        info.metadata["Threads"] = readStatusValue(statusContent, "Threads");
        info.metadata["State"] = readStatusValue(statusContent, "State");
        info.metadata["TracerPid"] = readStatusValue(statusContent, "TracerPid");
        const auto capEff = readStatusValue(statusContent, "CapEff");
        info.effectiveCapabilities = parseCapabilities(capEff);
        info.metadata["CapEffRaw"] = capEff;
        info.seccompMode = readStatusValue(statusContent, "Seccomp");
        const auto cgroup = readFile(basePath + "/cgroup", true);
        if (!cgroup.empty()) {
        info.metadata["Cgroup"] = cgroup;
        }

        const auto nsPath = basePath + "/ns";
        std::error_code ec;
        if (fs::exists(nsPath, ec)) {
            for (const auto &nsEntry : fs::directory_iterator(nsPath, ec)) {
                if (ec) {
                    break;
                }
                info.namespaces.emplace_back(nsEntry.path().filename().string() + " -> " + readLink(nsEntry.path().string()));
            }
        }

        const auto statContent = readFile(basePath + "/stat", false);
        if (!statContent.empty()) {
            const auto closing = statContent.rfind(')');
            if (closing != std::string::npos && closing + 2 < statContent.size()) {
                std::string rest = statContent.substr(closing + 2);
                std::istringstream statStream(rest);
                std::vector<std::string> tokens;
                std::string token;
                while (statStream >> token) {
                    tokens.push_back(token);
                }
                if (tokens.size() > 1) {
                    info.parentPid = std::stoi(tokens[1]);
                }
                if (tokens.size() > 19) {
                    const long ticksPerSecond = sysconf(_SC_CLK_TCK);
                    const long long startTicks = std::stoll(tokens[19]);
                    if (ticksPerSecond > 0 && haveSysInfo) {
                        const double startSeconds = static_cast<double>(startTicks) / static_cast<double>(ticksPerSecond);
                        const auto bootTime = std::chrono::system_clock::from_time_t(std::time(nullptr) - sysInfo.uptime);
                        const auto startPoint = bootTime + std::chrono::milliseconds(static_cast<long long>(startSeconds * 1000.0));
                        const auto startEpoch = std::chrono::system_clock::to_time_t(startPoint);
                        info.startTime = toIso8601(startEpoch);
                    }
                }
            }
        }

        info.connections = parseConnections(basePath);
        info.memoryRegions = parseMemoryRegions(basePath);
        info.environment = parseEnvironment(basePath + "/environ");

        processes.emplace_back(std::move(info));
    }

    return processes;
}

std::string ProcessScanner::decodeIPv4(const std::string &hex) {
    if (hex.size() != 8) {
        return {};
    }
    std::array<unsigned char, 4> bytes{};
    try {
        for (int i = 0; i < 4; ++i) {
            const auto part = hex.substr(i * 2, 2);
            bytes[3 - i] = static_cast<unsigned char>(std::stoi(part, nullptr, 16));
        }
    } catch (...) {
        return {};
    }
    char buffer[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, bytes.data(), buffer, sizeof(buffer))) {
        return {};
    }
    return buffer;
}

std::string ProcessScanner::decodeIPv6(const std::string &hex) {
    if (hex.size() != 32) {
        return {};
    }
    std::array<unsigned char, 16> bytes{};
    try {
        for (int i = 0; i < 16; ++i) {
            const auto part = hex.substr(i * 2, 2);
            bytes[15 - i] = static_cast<unsigned char>(std::stoi(part, nullptr, 16));
        }
    } catch (...) {
        return {};
    }
    char buffer[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, bytes.data(), buffer, sizeof(buffer))) {
        return {};
    }
    return buffer;
}

NetworkEndpoint ProcessScanner::parseEndpoint(const std::string &value, bool ipv6) {
    NetworkEndpoint endpoint;
    const auto separator = value.find(':');
    if (separator == std::string::npos) {
        return endpoint;
    }
    const auto addressPart = value.substr(0, separator);
    const auto portPart = value.substr(separator + 1);
    try {
        endpoint.port = static_cast<std::uint16_t>(std::stoi(portPart, nullptr, 16));
    } catch (...) {
        endpoint.port = 0;
    }
    endpoint.address = ipv6 ? decodeIPv6(addressPart) : decodeIPv4(addressPart);
    return endpoint;
}

std::vector<NetworkConnection> ProcessScanner::parseConnections(const std::string &basePath) {
    std::vector<NetworkConnection> connections;
    const std::vector<std::pair<std::string, bool>> files = {
        {"tcp", false}, {"tcp6", true}, {"udp", false}, {"udp6", true}};

    for (const auto &[name, ipv6] : files) {
        const auto content = readFile(basePath + "/net/" + name, false);
        if (content.empty()) {
            continue;
        }
        std::istringstream stream(content);
        std::string line;
        std::getline(stream, line); // header
        while (std::getline(stream, line)) {
            if (line.empty()) {
                continue;
            }
            std::istringstream lineStream(line);
            std::string sl, localAddress, remoteAddress, state;
            lineStream >> sl >> localAddress >> remoteAddress >> state;
            if (localAddress.empty() || remoteAddress.empty()) {
                continue;
            }
            NetworkConnection connection;
            connection.protocol = name;
            connection.local = parseEndpoint(localAddress, ipv6);
            connection.remote = parseEndpoint(remoteAddress, ipv6);
            connection.state = state;
            connection.listening = connection.remote.port == 0;
            connections.emplace_back(std::move(connection));
        }
    }
    return connections;
}

std::vector<MemoryRegion> ProcessScanner::parseMemoryRegions(const std::string &basePath) {
    std::vector<MemoryRegion> regions;
    const auto content = readFile(basePath + "/maps", false);
    if (content.empty()) {
        return regions;
    }
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream lineStream(line);
        MemoryRegion region;
        lineStream >> region.addressRange >> region.permissions;
        std::string offset, dev, inode;
        lineStream >> offset >> dev >> inode;
        std::string path;
        std::getline(lineStream, path);
        if (!path.empty() && path[0] == ' ') {
            path.erase(0, path.find_first_not_of(' '));
        }
        region.path = path;
        region.anonymous = path.empty() || (!path.empty() && path.front() == '[');
        if (region.permissions.find('x') != std::string::npos) {
            regions.emplace_back(std::move(region));
        }
    }
    return regions;
}

std::vector<std::string> ProcessScanner::parseCapabilities(const std::string &hexMask) {
    if (hexMask.empty()) {
        return {};
    }
    static const std::vector<std::string> capabilityNames = {
        "CAP_CHOWN",         "CAP_DAC_OVERRIDE",  "CAP_DAC_READ_SEARCH", "CAP_FOWNER",       "CAP_FSETID",
        "CAP_KILL",          "CAP_SETGID",        "CAP_SETUID",         "CAP_SETPCAP",      "CAP_LINUX_IMMUTABLE",
        "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN",   "CAP_NET_RAW",      "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",     "CAP_SYS_MODULE",    "CAP_SYS_RAWIO",      "CAP_SYS_CHROOT",   "CAP_SYS_PTRACE",
        "CAP_SYS_PACCT",     "CAP_SYS_ADMIN",     "CAP_SYS_BOOT",       "CAP_SYS_NICE",     "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",      "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",         "CAP_LEASE",        "CAP_AUDIT_WRITE",
        "CAP_AUDIT_CONTROL", "CAP_SETFCAP",       "CAP_MAC_OVERRIDE",   "CAP_MAC_ADMIN",    "CAP_SYSLOG",
        "CAP_WAKE_ALARM",    "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ"};

    unsigned long long mask = 0;
    try {
        mask = std::stoull(hexMask, nullptr, 16);
    } catch (...) {
        return {};
    }

    std::vector<std::string> capabilities;
    for (std::size_t bit = 0; bit < capabilityNames.size(); ++bit) {
        if (mask & (1ULL << bit)) {
            capabilities.push_back(capabilityNames[bit]);
        }
    }
    return capabilities;
}

std::unordered_map<std::string, std::string> ProcessScanner::parseEnvironment(const std::string &path) {
    std::unordered_map<std::string, std::string> environment;
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input.is_open()) {
        return environment;
    }

    const std::string buffer((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    if (buffer.empty()) {
        return environment;
    }

    std::size_t offset = 0;
    while (offset < buffer.size()) {
        const auto terminator = buffer.find('\0', offset);
        const auto length = (terminator == std::string::npos) ? buffer.size() - offset : terminator - offset;
        if (length > 0) {
            const std::string entry = buffer.substr(offset, length);
            const auto equalPos = entry.find('=');
            if (equalPos != std::string::npos && equalPos > 0) {
                std::string key = entry.substr(0, equalPos);
                std::string value = entry.substr(equalPos + 1);
                environment.emplace(std::move(key), std::move(value));
            }
        }
        if (terminator == std::string::npos) {
            break;
        }
        offset = terminator + 1;
    }

    return environment;
}

bool ProcessScanner::isWorldWritable(const std::string &path) {
    if (path.empty()) {
        return false;
    }
    struct stat buffer {
    };
    if (stat(path.c_str(), &buffer) != 0) {
        return false;
    }
    return (buffer.st_mode & S_IWOTH) != 0;
}

} // namespace antivirus
