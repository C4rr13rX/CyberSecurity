#include "AntivirusSuite/DarkWebScanner.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>

namespace antivirus {

DarkWebScanner::DarkWebScanner(TorClient client) : torClient(std::move(client)) {}

DarkWebScanResult DarkWebScanner::scan(const std::string &host, const std::string &path,
                                       const std::vector<std::string> &keywords, std::uint16_t port) const {
    DarkWebScanResult result;
    try {
        const auto response = torClient.httpGet(host, port, path.empty() ? "/" : path);
        if (response.empty()) {
            result.errorMessage = "Empty response via Tor";
            return result;
        }

        const auto lowered = toLower(response);
        for (const auto &keyword : keywords) {
            const auto loweredKeyword = toLower(keyword);
            auto position = lowered.find(loweredKeyword);
            while (position != std::string::npos) {
                result.findings.push_back({keyword, buildSnippet(response, position)});
                position = lowered.find(loweredKeyword, position + loweredKeyword.size());
            }
        }

        if (!result.findings.empty()) {
            result.success = true;
            result.responseSnippet = buildSnippet(response, response.find(result.findings.front().keyword));
        } else {
            result.success = true;
            result.responseSnippet = response.substr(0, std::min<std::size_t>(response.size(), 200));
        }
    } catch (const std::exception &ex) {
        result.errorMessage = ex.what();
    }

    return result;
}

std::string DarkWebScanner::toLower(const std::string &value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return lowered;
}

std::string DarkWebScanner::buildSnippet(const std::string &content, std::size_t position) {
    const std::size_t radius = 100;
    const auto start = (position > radius) ? position - radius : 0;
    const auto end = std::min(content.size(), position + radius);
    std::ostringstream oss;
    if (start > 0) {
        oss << "...";
    }
    oss << content.substr(start, end - start);
    if (end < content.size()) {
        oss << "...";
    }
    return oss.str();
}

} // namespace antivirus

