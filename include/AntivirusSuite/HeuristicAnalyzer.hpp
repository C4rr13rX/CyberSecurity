#pragma once

#include "ProcessScanner.hpp"

#include <string>
#include <vector>

namespace antivirus {

struct HeuristicReport {
    std::vector<HeuristicFinding> findings;
    double score{0.0};
};

class HeuristicAnalyzer {
  public:
    HeuristicAnalyzer();
    HeuristicReport analyze(const ProcessInfo &process) const;

  private:
    std::vector<std::string> suspiciousBinaries;
    std::vector<std::string> suspiciousSubstrings;
    std::vector<std::string> highRiskCapabilities;
    static void addFinding(HeuristicReport &report, std::string description, double weight,
                           std::string reference = {});
    static bool isInterpreter(const std::string &cmdline);
    static bool isExternalAddress(const std::string &address);
    static bool isPrivateIPv4(const std::string &address);
};

} // namespace antivirus
