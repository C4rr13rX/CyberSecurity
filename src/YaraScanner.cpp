#include "AntivirusSuite/YaraScanner.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace {

std::string readCommandOutput(const std::string &command, int &exitCode) {
    std::array<char, 256> buffer{};
    std::ostringstream output;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return {};
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output << buffer.data();
    }
    exitCode = pclose(pipe);
    return output.str();
}

} // namespace

namespace antivirus {

bool YaraScanner::isYaraAvailable() {
    const int code = std::system("yara --version > /dev/null 2>&1");
    return code == 0;
}

YaraScanResult YaraScanner::scanPath(const std::string &rulesPath, const std::string &targetPath) const {
    YaraScanResult result;
    if (!isYaraAvailable()) {
        result.errorMessage = "yara binary was not found on PATH. Install YARA to enable rule-based scanning.";
        return result;
    }

    int exitCode = 0;
    const auto command = "yara --print-meta --print-tags --print-strings -r \"" + rulesPath + "\" \"" + targetPath + "\"";
    result.rawOutput = readCommandOutput(command, exitCode);
    if (exitCode != 0) {
        result.errorMessage = "yara execution returned non-zero exit code.";
        return result;
    }

    std::istringstream stream(result.rawOutput);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        std::istringstream lineStream(line);
        YaraMatch match;
        lineStream >> match.rule;
        lineStream >> match.target;

        std::string token;
        while (lineStream >> token) {
            if (token.rfind("tags:", 0) == 0) {
                if (!match.tags.empty()) {
                    match.tags += ' ';
                }
                match.tags += token.substr(5);
            } else if (token.rfind("meta:", 0) == 0) {
                if (!match.meta.empty()) {
                    match.meta += ' ';
                }
                match.meta += token.substr(5);
            }
        }

        result.matches.emplace_back(std::move(match));
    }

    result.executed = true;
    return result;
}

} // namespace antivirus
