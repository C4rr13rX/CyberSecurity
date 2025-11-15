#include "AntivirusSuite/DarkWebScanner.hpp"

#include <algorithm>
#include <cctype>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_set>

namespace antivirus {

namespace {

struct LeakPattern {
    std::string label;
    std::regex expression;
    double confidence;
};

const std::vector<LeakPattern> &structuredPatterns() {
    static const std::vector<LeakPattern> patterns = {
        {"email", std::regex(R"((?:[a-zA-Z0-9_\.-]+)@(?:[a-zA-Z0-9\.-]+)\.[a-zA-Z]{2,})") , 0.6},
        {"credential pair", std::regex(R"(([^\s:]{3,})[:|]([^\s]{3,}))"), 0.7},
        {"credit card", std::regex(R"((?:\b[0-9]{4}[- ]?){3}[0-9]{4}\b)"), 0.8},
        {"ssn", std::regex(R"(\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b)"), 0.9},
        {"phone", std::regex(R"(\b\+?[0-9]{1,3}[- ]?[0-9]{3}[- ]?[0-9]{3,4}[- ]?[0-9]{4}\b)"), 0.55},
        {"street address", std::regex(R"((\b\d{1,6}[\s][\w\s\.]*(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b))",
                                               std::regex_constants::icase),
         0.75},
        {"license plate", std::regex(R"(\b[A-Z0-9]{2,8}\b)") , 0.4}
    };
    return patterns;
}

bool isLikelyCredentialLine(const std::string &line) {
    return line.find(':') != std::string::npos || line.find('|') != std::string::npos || line.find("password") != std::string::npos;
}

bool containsKeywordVariant(const std::string &lineLower, const std::vector<std::string> &variants) {
    for (const auto &variant : variants) {
        if (lineLower.find(variant) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string trim(const std::string &value) {
    const auto first = value.find_first_not_of(" \r\n\t");
    if (first == std::string::npos) {
        return {};
    }
    const auto last = value.find_last_not_of(" \r\n\t");
    return value.substr(first, last - first + 1);
}

} // namespace

DarkWebScanner::DarkWebScanner(TorClient client) : torClient(std::move(client)) {}

DarkWebScanResult DarkWebScanner::scan(const std::string &host, const std::string &path,
                                       const std::vector<std::string> &keywords, std::uint16_t port) const {
    DarkWebScanResult result;
    try {
        std::vector<std::pair<std::string, std::string>> headers = {
            {"Accept-Language", "en-US,en;q=0.9"},
            {"Cache-Control", "no-cache"}
        };
        std::ostringstream safePath;
        safePath << (path.empty() ? "/" : path);
        const auto response = torClient.httpRequest("GET", host, port, safePath.str(), headers, "");
        result.statusCode = response.statusCode;
        result.bytesTransferred = response.bytesTransferred;
        result.elapsedSeconds = response.elapsedSeconds;

        if (response.statusCode >= 400) {
            result.errorMessage = "HTTP status " + std::to_string(response.statusCode);
            return result;
        }

        if (response.body.empty()) {
            result.errorMessage = "Empty response via Tor";
            return result;
        }

        const auto lowered = toLower(response.body);
        const auto lines = splitLines(response.body);
        std::unordered_set<std::string> seenContexts;

        for (const auto &keyword : keywords) {
            const auto variants = expandKeywordVariants(keyword);
            for (const auto &variant : variants) {
                auto position = lowered.find(variant);
                while (position != std::string::npos) {
                    const auto snippet = buildSnippet(response.body, position);
                    if (seenContexts.insert(snippet).second) {
                        result.findings.push_back({keyword, snippet, "keyword", 0.5, 0});
                    }
                    position = lowered.find(variant, position + variant.size());
                }
            }
        }

        for (std::size_t i = 0; i < lines.size(); ++i) {
            const auto &line = lines[i];
            const auto lineLower = toLower(line);
            bool containsKeyword = false;
            for (const auto &keyword : keywords) {
                const auto variants = expandKeywordVariants(keyword);
                if (containsKeywordVariant(lineLower, variants)) {
                    containsKeyword = true;
                    break;
                }
            }

            if (!containsKeyword && !isLikelyCredentialLine(lineLower)) {
                continue;
            }

            appendStructuredFindings(line, i + 1, result.findings);
        }

        appendBase64Findings(response.body, result.findings, keywords);

        if (!result.findings.empty()) {
            result.success = true;
            result.responseSnippet = buildSnippet(response.body, response.body.find(result.findings.front().keyword));
        } else {
            result.success = true;
            result.responseSnippet = response.body.substr(0, std::min<std::size_t>(response.body.size(), 200));
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

std::vector<std::string> DarkWebScanner::splitLines(const std::string &content) {
    std::vector<std::string> lines;
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        lines.push_back(line);
    }
    return lines;
}

void DarkWebScanner::appendStructuredFindings(const std::string &line, std::size_t lineNumber,
                                              std::vector<DarkWebFinding> &findings) {
    for (const auto &pattern : structuredPatterns()) {
        std::smatch match;
        std::string::const_iterator searchStart(line.cbegin());
        while (std::regex_search(searchStart, line.cend(), match, pattern.expression)) {
            const auto snippet = trim(match.str());
            if (!snippet.empty()) {
                findings.push_back({snippet, snippet, pattern.label, pattern.confidence, lineNumber});
            }
            searchStart = match.suffix().first;
        }
    }
}

void DarkWebScanner::appendBase64Findings(const std::string &content, std::vector<DarkWebFinding> &findings,
                                          const std::vector<std::string> &keywords) {
    std::regex base64Regex(R"([A-Za-z0-9+/]{20,}={0,2})");
    std::smatch match;
    std::string::const_iterator searchStart(content.cbegin());
    while (std::regex_search(searchStart, content.cend(), match, base64Regex)) {
        const auto candidate = match.str();
        if (looksLikeBase64(candidate)) {
            const auto decoded = decodeBase64(candidate);
            if (!decoded.empty()) {
                const auto loweredDecoded = toLower(decoded);
                for (const auto &keyword : keywords) {
                    const auto variants = expandKeywordVariants(keyword);
                    for (const auto &variant : variants) {
                        if (loweredDecoded.find(variant) != std::string::npos) {
                            findings.push_back({keyword, buildSnippet(decoded, loweredDecoded.find(variant)), "base64", 0.8, 0});
                            break;
                        }
                    }
                }
            }
        }
        searchStart = match.suffix().first;
    }
}

bool DarkWebScanner::looksLikeBase64(const std::string &value) {
    if (value.size() % 4 != 0) {
        return false;
    }
    for (char ch : value) {
        if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '+' && ch != '/' && ch != '=') {
            return false;
        }
    }
    return true;
}

std::string DarkWebScanner::decodeBase64(const std::string &value) {
    static const std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> decodeTable(256, -1);
    for (std::size_t i = 0; i < base64Chars.size(); ++i) {
        decodeTable[static_cast<unsigned char>(base64Chars[i])] = static_cast<int>(i);
    }

    std::string output;
    int val = 0;
    int valb = -8;
    for (unsigned char c : value) {
        if (decodeTable[c] == -1) {
            if (c == '=') {
                break;
            }
            continue;
        }
        val = (val << 6) + decodeTable[c];
        valb += 6;
        if (valb >= 0) {
            output.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

std::string DarkWebScanner::normaliseKeyword(const std::string &keyword) {
    std::string normalized;
    normalized.reserve(keyword.size());
    for (char ch : keyword) {
        if (std::isalnum(static_cast<unsigned char>(ch))) {
            normalized.push_back(static_cast<char>(std::tolower(ch)));
        }
    }
    return normalized;
}

std::vector<std::string> DarkWebScanner::expandKeywordVariants(const std::string &keyword) {
    std::vector<std::string> variants;
    const auto lower = toLower(keyword);
    variants.push_back(lower);
    const auto normalized = normaliseKeyword(keyword);
    if (!normalized.empty() && normalized != lower) {
        variants.push_back(normalized);
    }
    if (keyword.find('@') != std::string::npos) {
        const auto at = lower.find('@');
        variants.push_back(lower.substr(0, at));
        variants.push_back(lower.substr(at + 1));
    }
    return variants;
}

} // namespace antivirus

