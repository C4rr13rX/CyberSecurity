#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace antivirus {

struct HeuristicFinding {
    std::string description;
    double weight{1.0};
    std::string reference;
};

struct NetworkEndpoint {
    std::string address;
    std::uint16_t port{0};
};

struct NetworkConnection {
    std::string protocol;
    NetworkEndpoint local;
    NetworkEndpoint remote;
    std::string state;
    bool listening{false};
};

struct MemoryRegion {
    std::string addressRange;
    std::string permissions;
    std::string path;
    bool anonymous{false};
};

struct ProcessInfo {
    int pid{0};
    int parentPid{0};
    std::string name;
    std::string cmdline;
    std::string exePath;
    std::string exeHash;
    std::string cwd;
    std::string user;
    std::string startTime;
    std::vector<std::string> effectiveCapabilities;
    std::string seccompMode;
    std::vector<std::string> namespaces;
    std::vector<NetworkConnection> connections;
    std::vector<MemoryRegion> memoryRegions;
    double riskScore{0.0};
    std::vector<HeuristicFinding> heuristics;
    std::vector<std::string> threatIntelHits;
    std::unordered_map<std::string, std::string> metadata;
    std::unordered_map<std::string, std::string> environment;
    bool exeWorldWritable{false};
    bool cwdWorldWritable{false};
};

class ProcessScanner {
  public:
    std::vector<ProcessInfo> snapshotProcesses() const;

  private:
    static bool isNumericDirectory(const std::string &value);
    static std::string readFile(const std::string &path, bool replaceNull = true);
    static std::string readLink(const std::string &path);
    static std::string readStatusValue(const std::string &statusContent, const std::string &key);
    static std::string decodeIPv4(const std::string &hex);
    static std::string decodeIPv6(const std::string &hex);
    static NetworkEndpoint parseEndpoint(const std::string &value, bool ipv6);
    static std::vector<NetworkConnection> parseConnections(const std::string &basePath);
    static std::vector<MemoryRegion> parseMemoryRegions(const std::string &basePath);
    static std::vector<std::string> parseCapabilities(const std::string &hexMask);
    static std::unordered_map<std::string, std::string> parseEnvironment(const std::string &path);
    static bool isWorldWritable(const std::string &path);
};

} // namespace antivirus
