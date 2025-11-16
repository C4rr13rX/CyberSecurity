#pragma once

#include "ProcessScanner.hpp"
#include "ThreatIntel.hpp"

#include <string>
#include <vector>

namespace antivirus {

struct HeuristicReport {
    std::vector<HeuristicFinding> findings;
    std::vector<std::string> threatIntelHits;
    double score{0.0};
};

class HeuristicAnalyzer {
  public:
    HeuristicAnalyzer();
    void setThreatIntel(const ThreatIntelDatabase *database);
    HeuristicReport analyze(const ProcessInfo &process) const;

  private:
    std::vector<std::string> suspiciousBinaries;
    std::vector<std::string> suspiciousSubstrings;
    std::vector<std::string> highRiskCapabilities;
    const ThreatIntelDatabase *threatIntel{nullptr};
    static void addFinding(HeuristicReport &report, std::string description, double weight,
                           std::string reference = {});
    static bool isInterpreter(const std::string &cmdline);
    static bool isExternalAddress(const std::string &address);
    static bool isPrivateIPv4(const std::string &address);
};

} // namespace antivirus
