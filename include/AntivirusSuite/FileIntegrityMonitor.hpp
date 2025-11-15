#pragma once

#include <string>
#include <vector>

namespace antivirus {

struct FileIntegrityFinding {
    std::string path;
    std::string issue;
};

struct FileIntegrityReport {
    std::vector<FileIntegrityFinding> missing;
    std::vector<FileIntegrityFinding> added;
    std::vector<FileIntegrityFinding> modified;
    std::string baselinePath;
};

class FileIntegrityMonitor {
  public:
    void createBaseline(const std::string &root, const std::string &baselineFile) const;
    FileIntegrityReport verifyBaseline(const std::string &root, const std::string &baselineFile) const;

  private:
    static std::string hashFile(const std::string &path);
};

} // namespace antivirus

