#pragma once

#include <string>
#include <vector>

namespace antivirus {

struct SystemFinding {
    std::string category;
    std::string description;
    double severity{0.0};
    std::string reference;
};

class SystemInspector {
  public:
    std::vector<SystemFinding> scanAll() const;

  private:
    void scanKernelModules(std::vector<SystemFinding> &findings) const;
    void scanPersistenceArtifacts(std::vector<SystemFinding> &findings) const;
    void scanSetuidBinaries(std::vector<SystemFinding> &findings) const;
    void scanLdPreload(std::vector<SystemFinding> &findings) const;
    void scanPrivilegedAccounts(std::vector<SystemFinding> &findings) const;
    void scanAutostartEntries(std::vector<SystemFinding> &findings) const;
    void scanSudoers(std::vector<SystemFinding> &findings) const;
    void scanSshConfig(std::vector<SystemFinding> &findings) const;

    static bool isSuspiciousPath(const std::string &path);
};

} // namespace antivirus

