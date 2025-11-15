#pragma once

#include "TorClient.hpp"

#include <string>
#include <vector>

namespace antivirus {

struct DarkWebFinding {
    std::string keyword;
    std::string context;
};

struct DarkWebScanResult {
    bool success{false};
    std::string errorMessage;
    std::vector<DarkWebFinding> findings;
    std::string responseSnippet;
};

class DarkWebScanner {
  public:
    explicit DarkWebScanner(TorClient client);

    DarkWebScanResult scan(const std::string &host, const std::string &path,
                           const std::vector<std::string> &keywords, std::uint16_t port = 80) const;

  private:
    static std::string toLower(const std::string &value);
    static std::string buildSnippet(const std::string &content, std::size_t position);

    TorClient torClient;
};

} // namespace antivirus

