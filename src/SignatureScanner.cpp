#include "AntivirusSuite/SignatureScanner.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
#ifndef popen
#define popen _popen
#endif
#ifndef pclose
#define pclose _pclose
#endif
#endif

namespace antivirus {

namespace {
std::string readCommandOutput(const std::string &command, int &exitCode) {
    std::array<char, 256> buffer{};
    std::ostringstream output;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return "";
    }
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        output << buffer.data();
    }
    exitCode = pclose(pipe);
    return output.str();
}

bool parseExitCode(int value) {
    if (value == -1) {
        return false;
    }
#ifdef WIFEXITED
    if (WIFEXITED(value)) {
        return WEXITSTATUS(value) == 0 || WEXITSTATUS(value) == 1;
    }
#endif
    return value == 0 || value == 1;
}

SignatureFinding parseFindingLine(const std::string &line) {
    SignatureFinding finding;
    const auto separator = line.find(':');
    if (separator != std::string::npos) {
        finding.target = line.substr(0, separator);
        auto signaturePart = line.substr(separator + 1);
        const auto infectedPos = signaturePart.find("FOUND");
        finding.infected = infectedPos != std::string::npos;
        if (infectedPos != std::string::npos) {
            signaturePart = signaturePart.substr(0, infectedPos);
        }
        finding.signature = signaturePart;
    } else {
        finding.target = line;
    }
    return finding;
}
} // namespace

bool SignatureScanner::isClamAvailable() {
    const int result = std::system("clamscan --version > /dev/null 2>&1");
    return result == 0;
}

SignatureScanResult SignatureScanner::scanPath(const std::string &path) const {
    SignatureScanResult result;
    if (!isClamAvailable()) {
        result.errorMessage = "clamscan was not found on the system PATH. Install ClamAV to enable signature scanning.";
        return result;
    }

    int exitCode = 0;
    const auto output = readCommandOutput("clamscan --no-summary --recursive \"" + path + "\"", exitCode);
    result.rawOutput = output;

    if (!parseExitCode(exitCode)) {
        result.errorMessage = "clamscan execution failed (exit code " + std::to_string(exitCode) + ").";
        return result;
    }

    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        result.findings.emplace_back(parseFindingLine(line));
    }

    result.executed = true;
    return result;
}

} // namespace antivirus
