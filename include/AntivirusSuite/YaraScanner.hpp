#pragma once

#include <string>
#include <vector>

namespace antivirus {

struct YaraMatch {
    std::string rule;
    std::string target;
    std::string tags;
    std::string meta;
};

struct YaraScanResult {
    bool executed{false};
    std::vector<YaraMatch> matches;
    std::string rawOutput;
    std::string errorMessage;
};

class YaraScanner {
  public:
    YaraScanResult scanPath(const std::string &rulesPath, const std::string &targetPath) const;
    static bool isYaraAvailable();
};

} // namespace antivirus
