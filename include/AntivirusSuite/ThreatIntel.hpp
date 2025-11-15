#pragma once

#include <string>
#include <unordered_set>
#include <vector>

namespace antivirus {

struct ThreatIntelHit {
    std::string indicator;
    std::string type;
};

class ThreatIntelDatabase {
  public:
    void loadFromFile(const std::string &path);
    void saveToFile(const std::string &path) const;

    void addIndicator(const std::string &type, const std::string &value);

    bool hasIp(const std::string &value) const;
    bool hasDomain(const std::string &value) const;
    bool hasHash(const std::string &value) const;

    std::vector<ThreatIntelHit> matchContent(const std::string &content) const;

  private:
    static std::string normalize(const std::string &value);
    static std::string trim(const std::string &value);

    std::unordered_set<std::string> ipIndicators;
    std::unordered_set<std::string> domainIndicators;
    std::unordered_set<std::string> hashIndicators;
};

} // namespace antivirus

