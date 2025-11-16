#include "AntivirusSuite/USBDeployer.hpp"

#include <array>
#include <cstdio>
#include <filesystem>
#include <sstream>
#include <stdexcept>
#include <string>
#ifndef _WIN32
#include <sys/wait.h>
#endif

namespace fs = std::filesystem;

namespace antivirus {
namespace {

std::string escape(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.size() * 2);
    const char backslash = static_cast<char>(92);
    const char doubleQuote = static_cast<char>(34);
    const char singleQuote = static_cast<char>(39);
    for (char ch : value) {
        if (ch == backslash || ch == doubleQuote || ch == singleQuote) {
            escaped.push_back(backslash);
        }
        escaped.push_back(ch);
    }
    return escaped;
}





UsbDeploymentResult runScript(const std::string &command) {
    UsbDeploymentResult result;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        result.success = false;
        result.exitCode = -1;
        result.output = "Unable to launch USB deployment helper.";
        return result;
    }

    std::array<char, 4096> buffer{};
    std::ostringstream output;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output << buffer.data();
    }
    const int exitStatus = pclose(pipe);
#ifdef _WIN32
    result.exitCode = exitStatus;
#else
    if (WIFEXITED(exitStatus)) {
        result.exitCode = WEXITSTATUS(exitStatus);
    } else if (WIFSIGNALED(exitStatus)) {
        result.exitCode = 128 + WTERMSIG(exitStatus);
    } else {
        result.exitCode = exitStatus;
    }
#endif
    result.output = output.str();
    result.success = (result.exitCode == 0);
    return result;
}

} // namespace

std::string USBDeployer::resolveScriptPath(const std::string &binaryPath) {
    fs::path exe(binaryPath);
    std::error_code ec;
    if (fs::is_symlink(exe, ec)) {
        std::error_code targetEc;
        const auto resolved = fs::read_symlink(exe, targetEc);
        if (!targetEc) {
            if (resolved.is_relative()) {
                exe = exe.parent_path() / resolved;
            } else {
                exe = resolved;
            }
        }
    }
    exe = fs::absolute(exe, ec);
    if (ec) {
        exe = fs::absolute(fs::path(binaryPath));
    }
    const auto projectRoot = exe.parent_path().parent_path();
    const auto scriptPath = projectRoot / "tools" / "create_usb_scanner.sh";
    return scriptPath.string();
}

UsbDeploymentResult USBDeployer::deploy(const std::string &device, const std::string &workdir, bool includeTor,
                                        const std::string &binaryPath) const {
    const auto script = resolveScriptPath(binaryPath);
    if (!fs::exists(script)) {
        return {false, -1, "USB creation helper script not found at " + script};
    }
    std::ostringstream command;
    command << "PARANOID_AV_BIN=\"" << escape(binaryPath) << "\" \"" << escape(script) << "\" \"" << escape(device)
            << "\"";
    if (!workdir.empty()) {
        command << " \"" << escape(workdir) << "\"";
    }
    if (includeTor) {
        command << " --include-tor";
    }
    return runScript(command.str());
}

} // namespace antivirus

