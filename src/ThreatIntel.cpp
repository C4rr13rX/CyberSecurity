#include "AntivirusSuite/ThreatIntel.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace antivirus {

namespace {

std::vector<std::string> split(const std::string &value, char delimiter) {
    std::vector<std::string> parts;
    std::string part;
    std::istringstream stream(value);
    while (std::getline(stream, part, delimiter)) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    return parts;
}

} // namespace

void ThreatIntelDatabase::loadFromFile(const std::string &path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }

        auto parts = split(line, ',');
        if (parts.size() < 2) {
            continue;
        }

        const auto type = trim(parts[0]);
        const auto value = trim(parts[1]);
        if (!type.empty() && !value.empty()) {
            addIndicator(type, value);
        }
    }
}

void ThreatIntelDatabase::saveToFile(const std::string &path) const {
    std::ofstream output(path, std::ios::out | std::ios::trunc);
    if (!output.is_open()) {
        return;
    }

    for (const auto &indicator : ipIndicators) {
        output << "ip," << indicator << '\n';
    }
    for (const auto &indicator : domainIndicators) {
        output << "domain," << indicator << '\n';
    }
    for (const auto &indicator : hashIndicators) {
        output << "hash," << indicator << '\n';
    }
}

void ThreatIntelDatabase::addIndicator(const std::string &type, const std::string &value) {
    const auto lowered = normalize(value);
    if (lowered.empty()) {
        return;
    }

    const auto loweredType = normalize(type);
    if (loweredType == "ip") {
        ipIndicators.insert(lowered);
    } else if (loweredType == "domain") {
        domainIndicators.insert(lowered);
    } else if (loweredType == "hash") {
        hashIndicators.insert(lowered);
    }
}

bool ThreatIntelDatabase::hasIp(const std::string &value) const {
    return ipIndicators.find(normalize(value)) != ipIndicators.end();
}

bool ThreatIntelDatabase::hasDomain(const std::string &value) const {
    return domainIndicators.find(normalize(value)) != domainIndicators.end();
}

bool ThreatIntelDatabase::hasHash(const std::string &value) const {
    return hashIndicators.find(normalize(value)) != hashIndicators.end();
}

std::vector<ThreatIntelHit> ThreatIntelDatabase::matchContent(const std::string &content) const {
    std::vector<ThreatIntelHit> hits;
    const auto loweredContent = normalize(content);

    for (const auto &indicator : domainIndicators) {
        if (loweredContent.find(indicator) != std::string::npos) {
            hits.push_back({indicator, "domain"});
        }
    }

    for (const auto &indicator : hashIndicators) {
        if (loweredContent.find(indicator) != std::string::npos) {
            hits.push_back({indicator, "hash"});
        }
    }

    return hits;
}

std::string ThreatIntelDatabase::normalize(const std::string &value) {
    std::string result;
    result.reserve(value.size());
    for (char ch : value) {
        if (std::isspace(static_cast<unsigned char>(ch))) {
            continue;
        }
        result.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return result;
}

std::string ThreatIntelDatabase::trim(const std::string &value) {
    const auto start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return {};
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

} // namespace antivirus

