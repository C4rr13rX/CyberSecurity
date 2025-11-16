#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace antivirus {

struct WindowsFileEntry {
    std::string relativePath;
    std::uintmax_t size = 0;
    std::string sha256;
    bool critical = false;
};

enum class WindowsRepairIssueType {
    Missing,
    HashMismatch
};

struct WindowsManifest {
    std::string versionLabel;
    std::string buildNumber;
    std::string manifestKey;
    std::vector<WindowsFileEntry> files;
};

struct WindowsRepairIssue {
    WindowsFileEntry entry;
    WindowsRepairIssueType issue = WindowsRepairIssueType::Missing;
    std::string observedHash;
    std::uintmax_t observedSize = 0;
};

struct WindowsRepairPlan {
    WindowsManifest manifest;
    std::filesystem::path windowsRoot;
    std::vector<WindowsRepairIssue> issues;
    std::vector<std::string> errors;
};

struct WindowsRepairStageResult {
    std::vector<std::string> copied;
    std::vector<std::string> missingSources;
    std::vector<std::string> errors;
};

struct WindowsVersionInfo {
    std::string productName;
    std::string manifestKey;
    std::string buildNumber;
};

class WindowsRepairManager {
  public:
    WindowsRepairManager();

    WindowsManifest captureBaseline(const std::filesystem::path &windowsRoot, const std::string &versionLabel,
                                    const std::string &buildNumber, const std::string &manifestKey,
                                    const std::vector<std::filesystem::path> &relativeRoots = {}) const;

    bool saveManifest(const WindowsManifest &manifest, const std::filesystem::path &outputPath) const;
    WindowsManifest loadManifest(const std::filesystem::path &manifestPath) const;

    WindowsRepairPlan analyze(const std::filesystem::path &windowsRoot, const WindowsManifest &manifest) const;
    bool savePlan(const WindowsRepairPlan &plan, const std::filesystem::path &outputPath) const;

    WindowsRepairStageResult stageRepairs(const std::filesystem::path &repositoryRoot,
                                          const WindowsRepairPlan &plan,
                                          const std::filesystem::path &targetRoot) const;

    std::optional<WindowsVersionInfo> detectHostVersion() const;
    std::optional<std::filesystem::path> defaultWindowsRoot() const;

  private:
    static bool isCriticalExtension(const std::filesystem::path &path);
    static std::string normaliseRelativePath(const std::filesystem::path &root,
                                             const std::filesystem::path &absolute);

    std::string computeHash(const std::filesystem::path &path) const;
};

} // namespace antivirus
