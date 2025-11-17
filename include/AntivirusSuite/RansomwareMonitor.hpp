#pragma once

#include <chrono>
#include <string>
#include <vector>

namespace antivirus {

struct RansomwareFinding {
    std::string path;
    std::string description;
};

struct RansomwareSummary {
    std::size_t totalEvents{0};
    std::size_t suspectedEncryptions{0};
    std::vector<RansomwareFinding> findings;

    bool highRisk(std::size_t encryptionThreshold = 20, std::size_t eventThreshold = 200) const {
        return suspectedEncryptions >= encryptionThreshold || totalEvents >= eventThreshold;
    }
};

class RansomwareMonitor {
  public:
    RansomwareSummary watch(const std::string &path, std::chrono::seconds duration) const;

#ifndef _WIN32
  private:
    static bool isEncryptionExtension(const std::string &path);
#endif
};

} // namespace antivirus

