#pragma once

#include <string>
#include <vector>

namespace antivirus {

struct RootkitFinding {
    std::string indicator;
    std::string description;
    double severity{0.0};
    std::string evidence;
    std::string reference;
    std::string remediation;
};

class RootkitDetector {
  public:
    std::vector<RootkitFinding> scan() const;

  private:
    void scanSuspiciousModules(std::vector<RootkitFinding> &findings) const;
    void scanHiddenModules(std::vector<RootkitFinding> &findings) const;
    void scanModuleParameters(std::vector<RootkitFinding> &findings) const;
    void scanFilesystemArtifacts(std::vector<RootkitFinding> &findings) const;
    void scanKernelInterfaceProtection(std::vector<RootkitFinding> &findings) const;
};

} // namespace antivirus

