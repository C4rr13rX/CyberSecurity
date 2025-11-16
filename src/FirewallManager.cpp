#include "AntivirusSuite/FirewallManager.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace antivirus {

namespace {
const char *kDefaultPolicyEnv = "PARANOID_AV_FIREWALL_POLICY";

std::string joinList(const std::vector<std::string> &values, char delimiter) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            oss << delimiter;
        }
        oss << values[i];
    }
    return oss.str();
}

std::string joinPorts(const std::vector<std::uint16_t> &ports) {
    std::ostringstream oss;
    for (std::size_t i = 0; i < ports.size(); ++i) {
        if (i > 0) {
            oss << ',';
        }
        oss << ports[i];
    }
    return oss.str();
}

} // namespace

FirewallManager::FirewallManager() {
    const char *policyPath = std::getenv(kDefaultPolicyEnv);
    if (policyPath != nullptr) {
        loadPolicy(policyPath);
    }
}

FirewallStatus FirewallManager::inspectStatus() const {
    FirewallStatus status;
    status.rules = policy_;
#ifdef _WIN32
    status.nativeSupport = true;
    std::string output;
    const int code = runShell("netsh advfirewall show allprofiles", &output);
    if (code == 0) {
        FirewallProfileStatus current;
        std::istringstream stream(output);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("Profile Settings:") != std::string::npos) {
                if (!current.profile.empty()) {
                    status.profiles.push_back(current);
                }
                current = {};
                current.profile = trim(line.substr(line.find(':') + 1));
            } else if (line.find("State") != std::string::npos) {
                const std::string value = trim(line.substr(line.find(':') + 1));
                current.enabled = (value == "ON" || value == "On" || value == "on");
            } else if (line.find("Default Inbound Action") != std::string::npos) {
                current.inboundAction = trim(line.substr(line.find(':') + 1));
            } else if (line.find("Default Outbound Action") != std::string::npos) {
                current.outboundAction = trim(line.substr(line.find(':') + 1));
            }
        }
        if (!current.profile.empty()) {
            status.profiles.push_back(current);
        }
    } else {
        status.diagnostics.push_back("Failed to query Windows firewall state via netsh.");
    }
#else
    status.nativeSupport = false;
    status.diagnostics.push_back("Windows firewall inspection is available only when running on Windows hosts.");
#endif
    const auto diag = consumeDiagnostics();
    status.diagnostics.insert(status.diagnostics.end(), diag.begin(), diag.end());
    return status;
}

bool FirewallManager::allowApplication(const std::string &path, const std::string &name, const std::string &direction) {
    FirewallRule rule;
    rule.name = name.empty() ? ("Allow " + fs::path(path).filename().string()) : name;
    rule.direction = normaliseDirection(direction);
    rule.action = "allow";
    rule.protocol = "ANY";
    rule.applications = {path};
    const bool result = applyRule(rule);
    policy_.push_back(rule);
    return result;
}

bool FirewallManager::allowPort(std::uint16_t port, const std::string &protocol, const std::string &direction,
                                const std::string &name) {
    FirewallRule rule;
    rule.name = name.empty() ? ("Allow Port " + std::to_string(port)) : name;
    rule.direction = normaliseDirection(direction);
    rule.action = "allow";
    rule.protocol = normaliseProtocol(protocol);
    rule.ports = {port};
    const bool result = applyRule(rule);
    policy_.push_back(rule);
    return result;
}

bool FirewallManager::applyRule(const FirewallRule &rule) {
#ifdef _WIN32
    if (!applyRuleWindows(rule)) {
        recordDiagnostic("Failed to apply firewall rule: " + rule.name);
        return false;
    }
    recordDiagnostic("Applied firewall rule: " + rule.name);
    return true;
#else
    recordDiagnostic("Firewall rule " + rule.name + " recorded for policy, but host firewall control is Windows-only.");
    return true;
#endif
}

bool FirewallManager::removeRule(const std::string &name) {
    if (name.empty()) {
        recordDiagnostic("Cannot remove unnamed firewall rule.");
        return false;
    }
    bool hostSuccess = false;
#ifdef _WIN32
    hostSuccess = removeRuleWindows(name);
    if (hostSuccess) {
        recordDiagnostic("Removed firewall rule from host: " + name);
    }
#else
    recordDiagnostic("Firewall removal for " + name + " recorded for policy, but host control is Windows-only.");
#endif
    const auto before = policy_.size();
    policy_.erase(std::remove_if(policy_.begin(), policy_.end(), [&](const FirewallRule &rule) {
                       return rule.name == name;
                   }),
                   policy_.end());
    const bool policyChanged = policy_.size() != before;
    if (policyChanged) {
        recordDiagnostic("Removed firewall rule from active policy: " + name);
    }
    if (!hostSuccess && !policyChanged) {
        recordDiagnostic("No matching firewall rule named " + name + " was found.");
    }
    return hostSuccess || policyChanged;
}

bool FirewallManager::loadPolicy(const std::string &path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        recordDiagnostic("Unable to open firewall policy: " + path);
        return false;
    }
    std::vector<FirewallRule> parsed;
    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::istringstream stream(line);
        std::string keyword;
        stream >> keyword;
        if (keyword != "rule") {
            continue;
        }
        FirewallRule rule;
        std::string applications;
        std::string ports;
        stream >> std::quoted(rule.name) >> std::quoted(rule.direction) >> std::quoted(rule.action) >> std::quoted(rule.protocol)
               >> std::quoted(applications) >> std::quoted(ports) >> std::quoted(rule.notes);
        rule.direction = normaliseDirection(rule.direction);
        rule.action = trim(rule.action);
        rule.protocol = normaliseProtocol(rule.protocol);
        rule.applications = splitList(applications, ';');
        const auto portTokens = splitList(ports, ',');
        for (const auto &token : portTokens) {
            try {
                const int value = std::stoi(token);
                if (value > 0 && value <= 65535) {
                    rule.ports.push_back(static_cast<std::uint16_t>(value));
                }
            } catch (...) {
            }
        }
        parsed.push_back(rule);
    }
    policy_ = parsed;
    recordDiagnostic("Loaded " + std::to_string(policy_.size()) + " firewall rules from " + path);
    return true;
}

bool FirewallManager::savePolicy(const std::string &path) const {
    std::ofstream output(path);
    if (!output.is_open()) {
        return false;
    }
    output << "# Paranoid AV firewall policy\n";
    for (const auto &rule : policy_) {
        output << "rule " << std::quoted(rule.name) << ' ' << std::quoted(rule.direction) << ' ' << std::quoted(rule.action)
               << ' ' << std::quoted(rule.protocol) << ' ' << std::quoted(joinList(rule.applications, ';')) << ' '
               << std::quoted(joinPorts(rule.ports)) << ' ' << std::quoted(rule.notes) << "\n";
    }
    return true;
}

void FirewallManager::clearPolicy() {
    policy_.clear();
}

std::vector<std::string> FirewallManager::consumeDiagnostics() const {
    auto copy = diagnostics_;
    diagnostics_.clear();
    return copy;
}

std::string FirewallManager::normaliseDirection(const std::string &direction) {
    std::string value = direction;
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return std::tolower(ch); });
    if (value == "in" || value == "inbound") {
        return "inbound";
    }
    if (value == "out" || value == "outbound") {
        return "outbound";
    }
    return "both";
}

std::string FirewallManager::normaliseProtocol(const std::string &protocol) {
    std::string value = protocol;
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return std::toupper(ch); });
    if (value == "UDP") {
        return "UDP";
    }
    if (value == "ANY" || value == "ALL") {
        return "ANY";
    }
    return "TCP";
}

std::vector<std::string> FirewallManager::splitList(const std::string &value, char delimiter) {
    std::vector<std::string> results;
    std::string token;
    std::istringstream stream(value);
    while (std::getline(stream, token, delimiter)) {
        token = trim(token);
        if (!token.empty()) {
            results.push_back(token);
        }
    }
    return results;
}

std::string FirewallManager::trim(const std::string &value) {
    std::size_t start = 0;
    while (start < value.size() && std::isspace(static_cast<unsigned char>(value[start]))) {
        ++start;
    }
    std::size_t end = value.size();
    while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
        --end;
    }
    return value.substr(start, end - start);
}

bool FirewallManager::applyRuleWindows(const FirewallRule &rule) {
    const std::string direction = normaliseDirection(rule.direction);
    std::vector<std::string> directions;
    if (direction == "both") {
        directions = {"inbound", "outbound"};
    } else {
        directions = {direction};
    }
    const std::vector<std::string> applications = rule.applications.empty() ? std::vector<std::string>{""} : rule.applications;
    bool success = true;
    for (const auto &dir : directions) {
        for (const auto &application : applications) {
            std::ostringstream cmd;
            std::string ruleLabel = rule.name.empty() ? "Paranoid AV" : rule.name;
            if (!application.empty()) {
                ruleLabel += " [" + fs::path(application).filename().string() + "]";
            }
            cmd << "netsh advfirewall firewall add rule name=\"" << ruleLabel << " (" << dir << ")\"";
            cmd << " dir=" << (dir == "inbound" ? "in" : "out");
            cmd << " action=" << rule.action;
            cmd << " enable=yes profile=any";
            cmd << " protocol=" << rule.protocol;
            if (!rule.ports.empty()) {
                cmd << " localport=" << joinPorts(rule.ports);
            }
            if (!application.empty()) {
                cmd << " program=\"" << application << "\"";
            }
            if (!writeRuleToShell(cmd.str(), ruleLabel)) {
                success = false;
            }
        }
    }
    return success;
}

bool FirewallManager::removeRuleWindows(const std::string &name) {
    bool success = true;
    for (const auto &dir : {std::string("in"), std::string("out")}) {
        std::ostringstream cmd;
        std::string context = name + " (" + (dir == "in" ? "inbound" : "outbound") + ")";
        cmd << "netsh advfirewall firewall delete rule name=\"" << name << "\" dir=" << dir << " profile=any";
        if (!writeRuleToShell(cmd.str(), context)) {
            success = false;
        }
    }
    return success;
}

bool FirewallManager::writeRuleToShell(const std::string &command, const std::string &context) {
    std::string output;
    const int code = runShell(command, &output);
    if (code != 0) {
        recordDiagnostic("Command failed for rule " + context + ": " + output);
        return false;
    }
    return true;
}

void FirewallManager::recordDiagnostic(const std::string &message) const {
    diagnostics_.push_back(message);
}

int FirewallManager::runShell(const std::string &command, std::string *output) const {
#ifdef _WIN32
    const std::string fullCommand = "cmd /C \"" + command + "\"";
    FILE *pipe = _popen(fullCommand.c_str(), "r");
#else
    FILE *pipe = popen(command.c_str(), "r");
#endif
    if (!pipe) {
        return -1;
    }
    std::array<char, 512> buffer{};
    std::ostringstream stream;
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) {
        stream << buffer.data();
    }
#ifdef _WIN32
    const int code = _pclose(pipe);
#else
    const int code = pclose(pipe);
#endif
    if (output) {
        *output = stream.str();
    }
    return code;
}

} // namespace antivirus
