#pragma once

#include <string>

namespace antivirus {

struct UsbDeploymentResult {
    bool success{false};
    int exitCode{0};
    std::string output;
};

class USBDeployer {
  public:
    UsbDeploymentResult deploy(const std::string &device, const std::string &workdir, bool includeTor,
                               const std::string &binaryPath) const;

  private:
    static std::string resolveScriptPath(const std::string &binaryPath);
};

} // namespace antivirus

