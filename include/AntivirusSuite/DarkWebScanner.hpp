#pragma once

#include "TorClient.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace antivirus {

struct DarkWebFinding {
    std::string keyword;
    std::string context;
    std::string matchType;
    double confidence{0.0};
    std::size_t lineNumber{0};
};

struct DarkWebScanResult {
    bool success{false};
    std::string errorMessage;
    std::vector<DarkWebFinding> findings;
    std::string responseSnippet;
    int statusCode{0};
    std::size_t bytesTransferred{0};
    double elapsedSeconds{0.0};
};

class DarkWebScanner {
  public:
    explicit DarkWebScanner(TorClient client);

    DarkWebScanResult scan(const std::string &host, const std::string &path,
                           const std::vector<std::string> &keywords, std::uint16_t port = 80) const;

  private:
    static std::string toLower(const std::string &value);
    static std::string buildSnippet(const std::string &content, std::size_t position);
    static std::vector<std::string> splitLines(const std::string &content);
    static void appendStructuredFindings(const std::string &line, std::size_t lineNumber,
                                         std::vector<DarkWebFinding> &findings);
    static void appendBase64Findings(const std::string &content, std::vector<DarkWebFinding> &findings,
                                     const std::vector<std::string> &keywords);
    static bool looksLikeBase64(const std::string &value);
    static std::string decodeBase64(const std::string &value);
    static std::string normaliseKeyword(const std::string &keyword);
    static std::vector<std::string> expandKeywordVariants(const std::string &keyword);

    TorClient torClient;
};

} // namespace antivirus

