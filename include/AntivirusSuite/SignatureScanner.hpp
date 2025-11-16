#pragma once

#include <optional>
#include <string>
#include <vector>

namespace antivirus {

struct SignatureFinding {
    std::string target;
    std::string signature;
    bool infected{false};
};

struct SignatureScanResult {
    bool executed{false};
    std::vector<SignatureFinding> findings;
    std::string rawOutput;
    std::string errorMessage;
};

class SignatureScanner {
  public:
    SignatureScanResult scanPath(const std::string &path) const;
    static bool isClamAvailable();
};

} // namespace antivirus
