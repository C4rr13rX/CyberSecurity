#pragma once

#include <string>

namespace antivirus {

class QuarantineManager {
  public:
    explicit QuarantineManager(std::string quarantineRoot = "/var/lib/paranoid_av/quarantine");

    std::string quarantineFile(const std::string &path) const;
    bool terminateProcess(int pid, bool force = false) const;

  private:
    std::string root;
};

} // namespace antivirus

