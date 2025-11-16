#include "AntivirusSuite/WindowsRepairManager.hpp"

#include "AntivirusSuite/Crypto.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <unordered_set>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace antivirus {

namespace {

std::string trim(const std::string &value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return {};
    }
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

std::vector<std::string> split(const std::string &value, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream stream(value);
    while (std::getline(stream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

std::string toLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

} // namespace

WindowsRepairManager::WindowsRepairManager() = default;

bool WindowsRepairManager::isCriticalExtension(const fs::path &path) {
    const std::string ext = toLower(path.extension().string());
    static const std::unordered_set<std::string> criticalExt = {".dll", ".sys", ".exe", ".drv", ".ocx"};
    return criticalExt.find(ext) != criticalExt.end();
}

std::string WindowsRepairManager::normaliseRelativePath(const fs::path &root, const fs::path &absolute) {
    std::error_code ec;
    const auto relative = fs::relative(absolute, root, ec);
    if (ec) {
        return absolute.lexically_relative(root).generic_string();
    }
    return relative.generic_string();
}

std::string WindowsRepairManager::computeHash(const fs::path &path) const {
    try {
        return crypto::sha256File(path.string());
    } catch (...) {
        return {};
    }
}

WindowsManifest WindowsRepairManager::captureBaseline(const fs::path &windowsRoot, const std::string &versionLabel,
                                                      const std::string &buildNumber, const std::string &manifestKey,
                                                      const std::vector<fs::path> &relativeRoots) const {
    WindowsManifest manifest;
    manifest.versionLabel = versionLabel;
    manifest.buildNumber = buildNumber;
    manifest.manifestKey = manifestKey;

    std::vector<fs::path> roots = relativeRoots;
    if (roots.empty()) {
        roots = {fs::path("System32"), fs::path("SysWOW64"), fs::path("WinSxS")};
    }

    std::unordered_set<std::string> seen;

    for (const auto &relative : roots) {
        const fs::path absoluteRoot = windowsRoot / relative;
        std::error_code existsEc;
        if (!fs::exists(absoluteRoot, existsEc) || !fs::is_directory(absoluteRoot, existsEc)) {
            continue;
        }

        for (fs::recursive_directory_iterator it(absoluteRoot, fs::directory_options::skip_permission_denied, existsEc);
             it != fs::recursive_directory_iterator(); it.increment(existsEc)) {
            if (existsEc) {
                existsEc.clear();
                continue;
            }
            std::error_code statusEc;
            if (!it->is_regular_file(statusEc)) {
                continue;
            }
            const fs::path &current = it->path();
            const std::string relativePath = normaliseRelativePath(windowsRoot, current);
            if (relativePath.empty()) {
                continue;
            }
            if (!seen.insert(relativePath).second) {
                continue;
            }
            std::uintmax_t size = 0;
            try {
                size = it->file_size();
            } catch (...) {
                size = 0;
            }
            WindowsFileEntry entry;
            entry.relativePath = relativePath;
            entry.size = size;
            entry.sha256 = computeHash(current);
            entry.critical = isCriticalExtension(current);
            manifest.files.push_back(std::move(entry));
        }
    }

    std::sort(manifest.files.begin(), manifest.files.end(), [](const WindowsFileEntry &lhs, const WindowsFileEntry &rhs) {
        return lhs.relativePath < rhs.relativePath;
    });

    return manifest;
}

bool WindowsRepairManager::saveManifest(const WindowsManifest &manifest, const fs::path &outputPath) const {
    std::error_code ec;
    const auto parent = outputPath.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            return false;
        }
    }

    std::ofstream stream(outputPath, std::ios::out | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    stream << "# paranoid_av Windows repair manifest\n";
    stream << "version:" << manifest.versionLabel << "\n";
    stream << "build:" << manifest.buildNumber << "\n";
    stream << "key:" << manifest.manifestKey << "\n";
    for (const auto &entry : manifest.files) {
        stream << "file:" << entry.relativePath << '|' << entry.sha256 << '|' << entry.size << '|' << (entry.critical ? '1' : '0')
               << "\n";
    }
    return true;
}

WindowsManifest WindowsRepairManager::loadManifest(const fs::path &manifestPath) const {
    std::ifstream stream(manifestPath);
    if (!stream.is_open()) {
        throw std::runtime_error("Unable to open manifest: " + manifestPath.string());
    }

    WindowsManifest manifest;
    std::string line;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        if (line.rfind("version:", 0) == 0) {
            manifest.versionLabel = trim(line.substr(8));
            continue;
        }
        if (line.rfind("build:", 0) == 0) {
            manifest.buildNumber = trim(line.substr(6));
            continue;
        }
        if (line.rfind("key:", 0) == 0) {
            manifest.manifestKey = trim(line.substr(4));
            continue;
        }
        if (line.rfind("file:", 0) == 0) {
            const auto payload = split(line.substr(5), '|');
            if (payload.size() < 4) {
                continue;
            }
            WindowsFileEntry entry;
            entry.relativePath = payload[0];
            entry.sha256 = payload[1];
            try {
                entry.size = static_cast<std::uintmax_t>(std::stoull(payload[2]));
            } catch (...) {
                entry.size = 0;
            }
            entry.critical = payload[3] == "1" || toLower(payload[3]) == "true";
            manifest.files.push_back(std::move(entry));
        }
    }

    if (manifest.manifestKey.empty()) {
        throw std::runtime_error("Manifest missing key identifier: " + manifestPath.string());
    }

    std::sort(manifest.files.begin(), manifest.files.end(), [](const WindowsFileEntry &lhs, const WindowsFileEntry &rhs) {
        return lhs.relativePath < rhs.relativePath;
    });

    return manifest;
}

WindowsRepairPlan WindowsRepairManager::analyze(const fs::path &windowsRoot, const WindowsManifest &manifest) const {
    WindowsRepairPlan plan;
    plan.manifest = manifest;
    plan.windowsRoot = windowsRoot;

    for (const auto &entry : manifest.files) {
        fs::path relative(entry.relativePath);
        relative.make_preferred();
        const fs::path absolute = windowsRoot / relative;

        std::error_code ec;
        if (!fs::exists(absolute, ec)) {
            WindowsRepairIssue issue;
            issue.entry = entry;
            issue.issue = WindowsRepairIssueType::Missing;
            plan.issues.push_back(std::move(issue));
            continue;
        }
        if (!fs::is_regular_file(absolute, ec)) {
            plan.errors.push_back("Expected file replaced by non-regular entry: " + absolute.string());
            continue;
        }

        std::uintmax_t observedSize = 0;
        try {
            observedSize = fs::file_size(absolute);
        } catch (...) {
            observedSize = 0;
        }

        const std::string hash = computeHash(absolute);
        if (!entry.sha256.empty() && !hash.empty() && entry.sha256 != hash) {
            WindowsRepairIssue issue;
            issue.entry = entry;
            issue.issue = WindowsRepairIssueType::HashMismatch;
            issue.observedHash = hash;
            issue.observedSize = observedSize;
            plan.issues.push_back(std::move(issue));
        }
    }

    return plan;
}

bool WindowsRepairManager::savePlan(const WindowsRepairPlan &plan, const fs::path &outputPath) const {
    std::error_code ec;
    const auto parent = outputPath.parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            return false;
        }
    }

    std::ofstream stream(outputPath, std::ios::out | std::ios::trunc);
    if (!stream.is_open()) {
        return false;
    }

    stream << "# paranoid_av Windows repair plan\n";
    stream << "version:" << plan.manifest.versionLabel << "\n";
    stream << "build:" << plan.manifest.buildNumber << "\n";
    stream << "key:" << plan.manifest.manifestKey << "\n";
    stream << "root:" << plan.windowsRoot.generic_string() << "\n";

    for (const auto &issue : plan.issues) {
        stream << "issue:" << (issue.issue == WindowsRepairIssueType::Missing ? "missing" : "mismatch") << '|' << issue.entry.relativePath
               << '|' << issue.entry.sha256 << '|' << issue.entry.size << '|' << (issue.entry.critical ? '1' : '0')
               << '|' << issue.observedHash << '|' << issue.observedSize << "\n";
    }

    for (const auto &error : plan.errors) {
        stream << "error:" << error << "\n";
    }

    return true;
}

WindowsRepairStageResult WindowsRepairManager::stageRepairs(const fs::path &repositoryRoot, const WindowsRepairPlan &plan,
                                                            const fs::path &targetRoot) const {
    WindowsRepairStageResult result;
    for (const auto &issue : plan.issues) {
        fs::path relative(issue.entry.relativePath);
        relative.make_preferred();
        const fs::path source = repositoryRoot / plan.manifest.manifestKey / relative;
        std::error_code ec;
        if (!fs::exists(source, ec) || !fs::is_regular_file(source, ec)) {
            result.missingSources.push_back(source.string());
            continue;
        }
        const fs::path destination = targetRoot / relative;
        fs::create_directories(destination.parent_path(), ec);
        if (ec) {
            result.errors.push_back("Unable to create directory for " + destination.string() + ": " + ec.message());
            continue;
        }
        fs::copy_file(source, destination, fs::copy_options::overwrite_existing, ec);
        if (ec) {
            result.errors.push_back("Failed to copy " + source.string() + " -> " + destination.string() + ": " + ec.message());
        } else {
            result.copied.push_back(destination.string());
        }
    }
    return result;
}

std::optional<WindowsVersionInfo> WindowsRepairManager::detectHostVersion() const {
#ifdef _WIN32
    OSVERSIONINFOEXW info{};
    info.dwOSVersionInfoSize = sizeof(info);
#pragma warning(push)
#pragma warning(disable : 4996)
    if (!GetVersionExW(reinterpret_cast<LPOSVERSIONINFOW>(&info))) {
#pragma warning(pop)
        return std::nullopt;
    }
    WindowsVersionInfo version;
    version.buildNumber = std::to_string(info.dwBuildNumber);
    if (info.dwMajorVersion == 10 && info.dwBuildNumber >= 22000) {
        version.productName = "Windows 11";
        version.manifestKey = "win11";
    } else if (info.dwMajorVersion == 10) {
        version.productName = "Windows 10";
        version.manifestKey = "win10";
    } else if (info.dwMajorVersion == 6 && info.dwMinorVersion == 3) {
        version.productName = "Windows 8.1";
        version.manifestKey = "win81";
    } else if (info.dwMajorVersion == 6 && info.dwMinorVersion == 2) {
        version.productName = "Windows 8";
        version.manifestKey = "win8";
    } else if (info.dwMajorVersion == 6 && info.dwMinorVersion == 1) {
        version.productName = "Windows 7";
        version.manifestKey = "win7";
    } else {
        version.productName = "Windows";
        version.manifestKey = "win" + std::to_string(info.dwMajorVersion) + std::to_string(info.dwMinorVersion);
    }
    return version;
#else
    return std::nullopt;
#endif
}

std::optional<fs::path> WindowsRepairManager::defaultWindowsRoot() const {
#ifdef _WIN32
    std::wstring buffer(MAX_PATH, L'\0');
    UINT size = GetWindowsDirectoryW(buffer.data(), static_cast<UINT>(buffer.size()));
    if (size == 0) {
        const wchar_t *env = _wgetenv(L"SystemRoot");
        if (env) {
            return fs::path(env);
        }
        return std::nullopt;
    }
    buffer.resize(size);
    return fs::path(buffer);
#else
    return std::nullopt;
#endif
}

} // namespace antivirus
