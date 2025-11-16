#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace antivirus {

struct FirewallRule {
    std::string name;
    std::string direction; // inbound, outbound, or both
    std::string action;    // allow or block
    std::string protocol;  // TCP, UDP, ANY
    std::vector<std::string> applications;
    std::vector<std::string> addresses;
    std::vector<std::uint16_t> ports;
    std::string notes;
};

struct FirewallProfileStatus {
    std::string profile;
    bool enabled{false};
    std::string inboundAction;
    std::string outboundAction;
};

struct FirewallStatus {
    std::vector<FirewallProfileStatus> profiles;
    std::vector<FirewallRule> rules;
    std::vector<std::string> diagnostics;
    bool nativeSupport{false};
};

class FirewallManager {
  public:
    FirewallManager();

    FirewallStatus inspectStatus() const;
    bool allowApplication(const std::string &path, const std::string &name, const std::string &direction);
    bool allowPort(std::uint16_t port, const std::string &protocol, const std::string &direction, const std::string &name);
    bool applyRule(const FirewallRule &rule);
    bool removeRule(const std::string &name);

    bool loadPolicy(const std::string &path);
    bool savePolicy(const std::string &path) const;
    void clearPolicy();

    const std::vector<FirewallRule> &policyRules() const { return policy_; }
    std::vector<std::string> consumeDiagnostics() const;

  private:
    std::vector<FirewallRule> policy_;
    mutable std::vector<std::string> diagnostics_;

    static std::string normaliseDirection(const std::string &direction);
    static std::string normaliseProtocol(const std::string &protocol);
    static std::vector<std::string> splitList(const std::string &value, char delimiter);
    static std::string trim(const std::string &value);

    bool applyRuleWindows(const FirewallRule &rule);
    bool removeRuleWindows(const std::string &name);
    bool writeRuleToShell(const std::string &command, const std::string &context);
    void recordDiagnostic(const std::string &message) const;
    int runShell(const std::string &command, std::string *output) const;
};

} // namespace antivirus
