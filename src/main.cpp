#include "AntivirusSuite/DarkWebScanner.hpp"
#include "AntivirusSuite/FirewallManager.hpp"
#include "AntivirusSuite/FileIntegrityMonitor.hpp"
#include "AntivirusSuite/HeuristicAnalyzer.hpp"
#include "AntivirusSuite/OpenAIAnalyzer.hpp"
#include "AntivirusSuite/ProcessScanner.hpp"
#include "AntivirusSuite/QuarantineManager.hpp"
#include "AntivirusSuite/RansomwareMonitor.hpp"
#include "AntivirusSuite/RootkitDetector.hpp"
#include "AntivirusSuite/SignatureScanner.hpp"
#include "AntivirusSuite/SystemInspector.hpp"
#include "AntivirusSuite/ThreatIntel.hpp"
#include "AntivirusSuite/TorClient.hpp"
#include "AntivirusSuite/USBDeployer.hpp"
#include "AntivirusSuite/WindowsRepairManager.hpp"
#include "AntivirusSuite/WindowsSecurityCenterBridge.hpp"
#include "AntivirusSuite/YaraScanner.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
using namespace std::chrono_literals;

namespace {
std::string formatAddress(const antivirus::NetworkEndpoint &endpoint) {
    if (endpoint.address.empty()) {
        return "*";
    }
    const bool ipv6 = endpoint.address.find(':') != std::string::npos;
    std::ostringstream oss;
    if (ipv6) {
        oss << '[' << endpoint.address << ']';
    } else {
        oss << endpoint.address;
    }
    oss << ':' << endpoint.port;
    return oss.str();
}

std::string joinVector(const std::vector<std::string> &values, const std::string &separator = ", ") {
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i) {
        if (i > 0) {
            oss << separator;
        }
        oss << values[i];
    }
    return oss.str();
}

std::string jsonEscape(const std::string &value) {
    std::ostringstream oss;
    for (char ch : value) {
        switch (ch) {
        case '\\':
            oss << "\\\\";
            break;
        case '\"':
            oss << "\\\"";
            break;
        case '\n':
            oss << "\\n";
            break;
        case '\r':
            oss << "\\r";
            break;
        case '\t':
            oss << "\\t";
            break;
        default:
            oss << ch;
        }
    }
    return oss.str();
}

std::vector<std::string> splitComma(const std::string &value) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream stream(value);
    while (std::getline(stream, token, ',')) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

std::string toLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

bool isDirectionToken(const std::string &value) {
    const std::string lower = toLowerCopy(value);
    return lower == "in" || lower == "inbound" || lower == "out" || lower == "outbound" || lower == "both";
}

std::string canonicalDirection(const std::string &value) {
    const std::string lower = toLowerCopy(value);
    if (lower == "in" || lower == "inbound") {
        return "inbound";
    }
    if (lower == "out" || lower == "outbound") {
        return "outbound";
    }
    return "both";
}

bool isProtocolToken(const std::string &value) {
    const std::string lower = toLowerCopy(value);
    return lower == "tcp" || lower == "udp" || lower == "any" || lower == "all";
}

void printProcessReportTable(const std::vector<antivirus::ProcessInfo> &processes) {
    std::cout << std::left << std::setw(8) << "PID" << std::setw(12) << "USER" << std::setw(8) << "RISK" << std::setw(20)
              << "NAME" << "EXE" << "\n";
    for (const auto &proc : processes) {
        std::cout << std::left << std::setw(8) << proc.pid
                  << std::setw(12) << (proc.user.empty() ? "?" : proc.user.substr(0, 11))
                  << std::setw(8) << std::fixed << std::setprecision(1) << proc.riskScore << std::defaultfloat
                  << std::setw(20) << (proc.name.empty() ? "?" : proc.name.substr(0, 19))
                  << proc.exePath << "\n";
        if (!proc.heuristics.empty()) {
            for (const auto &finding : proc.heuristics) {
                std::cout << "  [" << std::fixed << std::setprecision(1) << finding.weight << std::defaultfloat << "] "
                          << finding.description;
                if (!finding.reference.empty()) {
                    std::cout << " (" << finding.reference << ')';
                }
                std::cout << "\n";
            }
        }
    }
}

void printProcessReportDetailed(const std::vector<antivirus::ProcessInfo> &processes) {
    for (const auto &proc : processes) {
        std::cout << "== PID " << proc.pid << " (" << (proc.name.empty() ? "?" : proc.name) << ")"
                  << " risk=" << std::fixed << std::setprecision(1) << proc.riskScore << std::defaultfloat << "\n";
        std::cout << "   user: " << (proc.user.empty() ? "?" : proc.user)
                  << "  parent: " << proc.parentPid
                  << "  start: " << (proc.startTime.empty() ? "?" : proc.startTime) << "\n";
        std::cout << "   exe: " << (proc.exePath.empty() ? "[missing]" : proc.exePath) << "\n";
        std::cout << "   hash: " << (proc.exeHash.empty() ? "[unavailable]" : proc.exeHash) << "\n";
        std::cout << "   cwd: " << (proc.cwd.empty() ? "[unknown]" : proc.cwd) << "\n";
        std::cout << "   cmd: " << (proc.cmdline.empty() ? "[none]" : proc.cmdline) << "\n";
        if (!proc.effectiveCapabilities.empty()) {
            std::cout << "   capabilities: " << joinVector(proc.effectiveCapabilities) << "\n";
        }
        if (!proc.seccompMode.empty()) {
            std::cout << "   seccomp: mode=" << proc.seccompMode << "\n";
        }
        if (!proc.namespaces.empty()) {
            std::cout << "   namespaces: " << joinVector(proc.namespaces) << "\n";
        }
        for (const auto &[key, value] : proc.metadata) {
            if (value.empty()) {
                continue;
            }
            std::cout << "   meta[" << key << "]=" << value << "\n";
        }
        if (!proc.connections.empty()) {
            std::cout << "   sockets:" << "\n";
            for (const auto &conn : proc.connections) {
                std::cout << "     - " << conn.protocol << ' ' << formatAddress(conn.local) << " -> "
                          << formatAddress(conn.remote) << " state=" << conn.state
                          << (conn.listening ? " (listening)" : "") << "\n";
            }
        }
        if (!proc.memoryRegions.empty()) {
            std::cout << "   exec-mappings:" << "\n";
            for (const auto &region : proc.memoryRegions) {
                std::cout << "     - " << region.addressRange << ' ' << region.permissions
                          << " path=" << (region.path.empty() ? "[anon]" : region.path) << "\n";
            }
        }
        if (!proc.heuristics.empty()) {
            std::cout << "   heuristics:" << "\n";
            for (const auto &finding : proc.heuristics) {
                std::cout << "     - score=" << std::fixed << std::setprecision(1) << finding.weight << std::defaultfloat << " "
                          << finding.description;
                if (!finding.reference.empty()) {
                    std::cout << " (" << finding.reference << ')';
                }
                std::cout << "\n";
            }
        }
        if (!proc.threatIntelHits.empty()) {
            std::cout << "   threat-intel hits: " << joinVector(proc.threatIntelHits) << "\n";
        }
        if (proc.exeWorldWritable) {
            std::cout << "   [!] executable world-writable" << "\n";
        }
        if (proc.cwdWorldWritable) {
            std::cout << "   [!] working directory world-writable" << "\n";
        }
        std::cout << "\n";
    }
}

void printFirewallStatus(const antivirus::FirewallStatus &status, bool jsonOutput) {
    if (jsonOutput) {
        std::cout << "{\n  \"nativeSupport\": " << (status.nativeSupport ? "true" : "false") << ",\n";
        std::cout << "  \"profiles\": [\n";
        for (std::size_t i = 0; i < status.profiles.size(); ++i) {
            const auto &profile = status.profiles[i];
            std::cout << "    {\"profile\": \"" << jsonEscape(profile.profile) << "\", \"enabled\": "
                      << (profile.enabled ? "true" : "false") << ", \"inbound\": \"" << jsonEscape(profile.inboundAction)
                      << "\", \"outbound\": \"" << jsonEscape(profile.outboundAction) << "\"}";
            if (i + 1 < status.profiles.size()) {
                std::cout << ',';
            }
            std::cout << "\n";
        }
        std::cout << "  ],\n  \"rules\": [\n";
        for (std::size_t i = 0; i < status.rules.size(); ++i) {
            const auto &rule = status.rules[i];
            std::cout << "    {\"name\": \"" << jsonEscape(rule.name) << "\", \"direction\": \""
                      << jsonEscape(rule.direction) << "\", \"action\": \"" << jsonEscape(rule.action)
                      << "\", \"protocol\": \"" << jsonEscape(rule.protocol) << "\", \"applications\": [";
            for (std::size_t a = 0; a < rule.applications.size(); ++a) {
                if (a > 0) {
                    std::cout << ',';
                }
                std::cout << "\"" << jsonEscape(rule.applications[a]) << "\"";
            }
            std::cout << "], \"ports\": [";
            for (std::size_t p = 0; p < rule.ports.size(); ++p) {
                if (p > 0) {
                    std::cout << ',';
                }
                std::cout << rule.ports[p];
            }
            std::cout << "]}";
            if (i + 1 < status.rules.size()) {
                std::cout << ',';
            }
            std::cout << "\n";
        }
        std::cout << "  ],\n  \"diagnostics\": [";
        for (std::size_t i = 0; i < status.diagnostics.size(); ++i) {
            if (i > 0) {
                std::cout << ',';
            }
            std::cout << "\"" << jsonEscape(status.diagnostics[i]) << "\"";
        }
        std::cout << "]\n}\n";
        return;
    }

    if (!status.nativeSupport) {
        std::cout << "[i] Native firewall control unavailable on this platform." << std::endl;
    }
    if (!status.profiles.empty()) {
        std::cout << "[Profiles]\n";
        for (const auto &profile : status.profiles) {
            std::cout << "  - " << (profile.profile.empty() ? "Profile" : profile.profile) << " ("
                      << (profile.enabled ? "enabled" : "disabled") << ")"
                      << " inbound=" << (profile.inboundAction.empty() ? "?" : profile.inboundAction)
                      << " outbound=" << (profile.outboundAction.empty() ? "?" : profile.outboundAction) << "\n";
        }
    }
    if (!status.rules.empty()) {
        std::cout << "[Policy Rules]\n";
        for (const auto &rule : status.rules) {
            std::cout << "  - " << (rule.name.empty() ? "unnamed" : rule.name) << " dir=" << rule.direction
                      << " action=" << rule.action << " proto=" << rule.protocol;
            if (!rule.ports.empty()) {
                std::vector<std::string> portStrings;
                portStrings.reserve(rule.ports.size());
                for (auto port : rule.ports) {
                    portStrings.push_back(std::to_string(port));
                }
                std::cout << " ports=" << joinVector(portStrings);
            }
            if (!rule.applications.empty()) {
                std::cout << " apps=" << joinVector(rule.applications);
            }
            std::cout << "\n";
        }
    }
    if (!status.diagnostics.empty()) {
        for (const auto &message : status.diagnostics) {
            std::cout << "[i] " << message << "\n";
        }
    }
}

void printSecurityCenterProducts(const std::vector<antivirus::SecurityCenterProduct> &products, bool jsonOutput) {
    if (jsonOutput) {
        std::cout << "[\n";
        for (std::size_t i = 0; i < products.size(); ++i) {
            const auto &product = products[i];
            std::cout << "  {\"name\": \"" << jsonEscape(product.name) << "\", \"type\": \""
                      << jsonEscape(product.type) << "\", \"state\": \"" << jsonEscape(product.state)
                      << "\", \"path\": \"" << jsonEscape(product.path) << "\", \"default\": "
                      << (product.isDefault ? "true" : "false") << "}";
            if (i + 1 < products.size()) {
                std::cout << ',';
            }
            std::cout << "\n";
        }
        std::cout << "]\n";
        return;
    }
    if (products.empty()) {
        std::cout << "[i] No Windows Security Center products were enumerated." << std::endl;
        return;
    }
    std::cout << "[Windows Security Center]\n";
    for (const auto &product : products) {
        std::cout << "  - " << (product.name.empty() ? "Unnamed" : product.name) << " (" << product.type
                  << ", state=" << product.state << (product.isDefault ? ", default" : "") << ')';
        if (!product.path.empty()) {
            std::cout << " => " << product.path;
        }
        std::cout << "\n";
    }
}

void printFirewallDiagnostics(const antivirus::FirewallManager &manager) {
    const auto diag = manager.consumeDiagnostics();
    for (const auto &message : diag) {
        if (!message.empty()) {
            std::cout << "[i] " << message << "\n";
        }
    }
}


void printProcessReportJson(const std::vector<antivirus::ProcessInfo> &processes) {
    std::cout << "[\n";
    for (std::size_t i = 0; i < processes.size(); ++i) {
        const auto &proc = processes[i];
        std::cout << "  {\n";
        std::cout << "    \"pid\": " << proc.pid << ",\n";
        std::cout << "    \"parentPid\": " << proc.parentPid << ",\n";
        std::cout << "    \"user\": \"" << jsonEscape(proc.user) << "\",\n";
        std::cout << "    \"name\": \"" << jsonEscape(proc.name) << "\",\n";
        std::cout << "    \"exe\": \"" << jsonEscape(proc.exePath) << "\",\n";
        std::cout << "    \"hash\": \"" << jsonEscape(proc.exeHash) << "\",\n";
        std::cout << "    \"risk\": " << std::fixed << std::setprecision(1) << proc.riskScore << ",\n";
        std::cout << "    \"startTime\": \"" << jsonEscape(proc.startTime) << "\",\n";
        std::cout << "    \"cmdline\": \"" << jsonEscape(proc.cmdline) << "\",\n";
        std::cout << "    \"cwd\": \"" << jsonEscape(proc.cwd) << "\",\n";
        std::cout << "    \"capabilities\": [";
        for (std::size_t c = 0; c < proc.effectiveCapabilities.size(); ++c) {
            if (c > 0) {
                std::cout << ",";
            }
            std::cout << "\"" << jsonEscape(proc.effectiveCapabilities[c]) << "\"";
        }
        std::cout << "],\n";
        std::cout << "    \"heuristics\": [\n";
        for (std::size_t h = 0; h < proc.heuristics.size(); ++h) {
            const auto &finding = proc.heuristics[h];
            std::cout << "      {\"score\": " << std::fixed << std::setprecision(1) << finding.weight
                      << ", \"description\": \"" << jsonEscape(finding.description) << "\"";
            if (!finding.reference.empty()) {
                std::cout << ", \"reference\": \"" << jsonEscape(finding.reference) << "\"";
            }
            std::cout << "}";
            if (h + 1 != proc.heuristics.size()) {
                std::cout << ',';
            }
            std::cout << "\n";
        }
        std::cout << "    ],\n";
        std::cout << "    \"threatIntelHits\": [";
        for (std::size_t t = 0; t < proc.threatIntelHits.size(); ++t) {
            if (t > 0) {
                std::cout << ",";
            }
            std::cout << "\"" << jsonEscape(proc.threatIntelHits[t]) << "\"";
        }
        std::cout << "],\n";
        std::cout << "    \"exeWorldWritable\": " << (proc.exeWorldWritable ? "true" : "false") << ",\n";
        std::cout << "    \"cwdWorldWritable\": " << (proc.cwdWorldWritable ? "true" : "false") << ",\n";
        std::cout << "    \"connections\": [\n";
        for (std::size_t c = 0; c < proc.connections.size(); ++c) {
            const auto &conn = proc.connections[c];
            std::cout << "      {\"protocol\": \"" << conn.protocol << "\", \"local\": \""
                      << jsonEscape(formatAddress(conn.local)) << "\", \"remote\": \""
                      << jsonEscape(formatAddress(conn.remote)) << "\", \"state\": \""
                      << jsonEscape(conn.state) << "\", \"listening\": " << (conn.listening ? "true" : "false") << "}";
            if (c + 1 != proc.connections.size()) {
                std::cout << ',';
            }
            std::cout << "\n";
        }
        std::cout << "    ],\n";
        std::cout << "    \"memoryRegions\": [\n";
        for (std::size_t m = 0; m < proc.memoryRegions.size(); ++m) {
            const auto &region = proc.memoryRegions[m];
            std::cout << "      {\"range\": \"" << jsonEscape(region.addressRange) << "\", \"perms\": \""
                      << jsonEscape(region.permissions) << "\", \"path\": \"" << jsonEscape(region.path)
                      << "\", \"anonymous\": " << (region.anonymous ? "true" : "false") << "}";
            if (m + 1 != proc.memoryRegions.size()) {
                std::cout << ',';
            }
            std::cout << "\n";
        }
        std::cout << "    ]\n";
        std::cout << "  }";
        if (i + 1 != processes.size()) {
            std::cout << ',';
        }
        std::cout << "\n";
    }
    std::cout << "]\n";
}

void printProcessReport(const std::vector<antivirus::ProcessInfo> &processes, bool jsonOutput, bool detailed) {
    if (jsonOutput) {
        printProcessReportJson(processes);
    } else if (detailed) {
        printProcessReportDetailed(processes);
    } else {
        printProcessReportTable(processes);
    }
}

void printSignatureReport(const antivirus::SignatureScanResult &result) {
    if (!result.executed) {
        std::cout << "[!] Signature scan not executed: " << result.errorMessage << "\n";
        return;
    }

    if (result.findings.empty()) {
        std::cout << "[+] Signature scan completed. No findings.\n";
        return;
    }

    for (const auto &finding : result.findings) {
        std::cout << (finding.infected ? "[! ]" : "[i ]") << ' ' << finding.target << " -> " << finding.signature << "\n";
    }
}

void printAIReport(const antivirus::OpenAIAnalysisResult &result) {
    if (!result.executed) {
        std::cout << "[!] AI analysis skipped: " << result.errorMessage << "\n";
        return;
    }

    std::cout << "[+] AI analysis executed. Summary placeholder: " << result.summary << "\n";
    std::cout << result.rawResponse << "\n";
}

void printYaraReport(const antivirus::YaraScanResult &result) {
    if (!result.executed) {
        std::cout << "[!] YARA scan not executed: " << result.errorMessage << "\n";
        return;
    }

    if (result.matches.empty()) {
        std::cout << "[+] YARA scan completed. No matches." << std::endl;
        return;
    }

    for (const auto &match : result.matches) {
        std::cout << "[!] YARA match " << match.rule << " -> " << match.target;
        if (!match.tags.empty()) {
            std::cout << " tags=" << match.tags;
        }
        if (!match.meta.empty()) {
            std::cout << " meta=" << match.meta;
        }
        std::cout << "\n";
    }
}

void printSystemFindings(const std::vector<antivirus::SystemFinding> &findings) {
    if (findings.empty()) {
        std::cout << "[+] System audit completed. No critical findings.\n";
        return;
    }

    for (const auto &finding : findings) {
        const char indicator = finding.severity >= 7.5 ? '!' : 'i';
        std::cout << '[' << indicator << " ] " << finding.category << " (severity=" << std::fixed << std::setprecision(1)
                  << finding.severity << std::defaultfloat << ") " << finding.description;
        if (!finding.reference.empty()) {
            std::cout << " ref=" << finding.reference;
        }
        std::cout << "\n";
    }
}

void printFileIntegrityReport(const antivirus::FileIntegrityReport &report) {
    if (report.missing.empty() && report.added.empty() && report.modified.empty()) {
        std::cout << "[+] Integrity verification succeeded. Baseline " << report.baselinePath
                  << " matches current state.\n";
        return;
    }

    for (const auto &finding : report.missing) {
        std::cout << "[!] Missing file: " << finding.path << " -> " << finding.issue << "\n";
    }
    for (const auto &finding : report.modified) {
        std::cout << "[!] Modified file: " << finding.path << " -> " << finding.issue << "\n";
    }
    for (const auto &finding : report.added) {
        std::cout << "[i] New file: " << finding.path << " -> " << finding.issue << "\n";
    }
}

void printRansomwareSummary(const antivirus::RansomwareSummary &summary) {
    std::cout << "[*] Ransomware monitor observed " << summary.totalEvents << " filesystem events";
    if (summary.suspectedEncryptions > 0) {
        std::cout << ", " << summary.suspectedEncryptions << " suspicious encryptions";
    }
    std::cout << ".\n";
    for (const auto &finding : summary.findings) {
        std::cout << "    - " << finding.path << ": " << finding.description << "\n";
    }
    if (summary.highRisk()) {
        std::cout << "[!] High probability of ransomware behavior detected." << std::endl;
    } else {
        std::cout << "[+] No ransomware surge detected." << std::endl;
    }
}

void printDarkWebResult(const antivirus::DarkWebScanResult &result) {
    if (!result.success) {
        std::cout << "[!] Dark web scan did not complete: " << result.errorMessage << "\n";
        return;
    }

    if (result.findings.empty()) {
        std::cout << "[+] No keyword hits detected in retrieved content.\n";
    } else {
        std::cout << "[!] Potential exposure detected for " << result.findings.size() << " artefact(s):\n";
        for (const auto &finding : result.findings) {
            std::cout << "    - " << finding.keyword;
            if (!finding.matchType.empty()) {
                std::cout << " [" << finding.matchType << "]";
            }
            if (finding.confidence > 0.0) {
                std::cout << " (confidence " << std::fixed << std::setprecision(2) << finding.confidence << ")";
                std::cout << std::defaultfloat;
            }
            if (finding.lineNumber > 0) {
                std::cout << " line " << finding.lineNumber;
            }
            std::cout << " -> " << finding.context << "\n";
        }
    }
    if (!result.responseSnippet.empty()) {
        std::cout << "--- snippet ---\n" << result.responseSnippet << "\n--------------\n";
    }
    if (result.statusCode > 0) {
        std::cout << "[*] HTTP status: " << result.statusCode << ", bytes: " << result.bytesTransferred
                  << ", elapsed: " << std::fixed << std::setprecision(2) << result.elapsedSeconds << "s\n";
        std::cout << std::defaultfloat;
    }
}

void printRootkitReportJson(const std::vector<antivirus::RootkitFinding> &findings) {
    std::cout << "[\n";
    for (std::size_t i = 0; i < findings.size(); ++i) {
        const auto &finding = findings[i];
        std::cout << "  {\"indicator\": \"" << jsonEscape(finding.indicator) << "\", \"description\": \""
                  << jsonEscape(finding.description) << "\", \"severity\": " << std::fixed << std::setprecision(2)
                  << finding.severity << std::defaultfloat << ", \"evidence\": \"" << jsonEscape(finding.evidence)
                  << "\"";
        if (!finding.reference.empty()) {
            std::cout << ", \"reference\": \"" << jsonEscape(finding.reference) << "\"";
        }
        if (!finding.remediation.empty()) {
            std::cout << ", \"remediation\": \"" << jsonEscape(finding.remediation) << "\"";
        }
        std::cout << "}";
        if (i + 1 != findings.size()) {
            std::cout << ',';
        }
        std::cout << "\n";
    }
    std::cout << "]\n";
}

void printRootkitReportText(const std::vector<antivirus::RootkitFinding> &findings) {
    if (findings.empty()) {
        std::cout << "[+] Rootkit sweep completed. No anomalies.\n";
        return;
    }

    for (const auto &finding : findings) {
        const char indicator = finding.severity >= 8.0 ? '!' : 'i';
        std::cout << '[' << indicator << " ] Rootkit " << finding.indicator << " (severity=" << std::fixed
                  << std::setprecision(1) << finding.severity << std::defaultfloat << ") " << finding.description;
        if (!finding.reference.empty()) {
            std::cout << " ref=" << finding.reference;
        }
        if (!finding.evidence.empty()) {
            std::cout << " -> " << finding.evidence;
        }
        if (!finding.remediation.empty()) {
            std::cout << " | remediate: " << finding.remediation;
        }
        std::cout << "\n";
    }
}

void printRootkitReport(const std::vector<antivirus::RootkitFinding> &findings, bool jsonOutput) {
    if (jsonOutput) {
        printRootkitReportJson(findings);
    } else {
        printRootkitReportText(findings);
    }
}

std::string windowsIssueType(const antivirus::WindowsRepairIssue &issue) {
    return issue.issue == antivirus::WindowsRepairIssueType::Missing ? "missing" : "mismatch";
}

void writeWindowsPlanJson(std::ostream &out, const antivirus::WindowsRepairPlan &plan, const std::string &indent) {
    out << "{\n";
    out << indent << "  \"version\": \"" << jsonEscape(plan.manifest.versionLabel) << "\",\n";
    out << indent << "  \"build\": \"" << jsonEscape(plan.manifest.buildNumber) << "\",\n";
    out << indent << "  \"manifestKey\": \"" << jsonEscape(plan.manifest.manifestKey) << "\",\n";
    out << indent << "  \"windowsRoot\": \"" << jsonEscape(plan.windowsRoot.generic_string()) << "\",\n";
    out << indent << "  \"issues\": [\n";
    for (std::size_t i = 0; i < plan.issues.size(); ++i) {
        const auto &issue = plan.issues[i];
        out << indent << "    {\"type\": \"" << windowsIssueType(issue) << "\", \"path\": \""
            << jsonEscape(issue.entry.relativePath) << "\", \"critical\": "
            << (issue.entry.critical ? "true" : "false") << ", \"expectedHash\": \""
            << jsonEscape(issue.entry.sha256) << "\", \"expectedSize\": " << issue.entry.size
            << ", \"observedHash\": ";
        if (issue.observedHash.empty()) {
            out << "null";
        } else {
            out << "\"" << jsonEscape(issue.observedHash) << "\"";
        }
        out << ", \"observedSize\": " << issue.observedSize << "}";
        if (i + 1 != plan.issues.size()) {
            out << ',';
        }
        out << "\n";
    }
    out << indent << "  ],\n";
    out << indent << "  \"errors\": [";
    for (std::size_t i = 0; i < plan.errors.size(); ++i) {
        if (i > 0) {
            out << ',';
        }
        out << "\"" << jsonEscape(plan.errors[i]) << "\"";
    }
    out << "]\n";
    out << indent << "}";
}

void writeWindowsStageJson(std::ostream &out, const antivirus::WindowsRepairStageResult &stage, const std::string &indent) {
    out << "{\n";
    out << indent << "  \"success\": "
        << ((stage.errors.empty() && stage.missingSources.empty()) ? "true" : "false") << ",\n";
    out << indent << "  \"copied\": [";
    for (std::size_t i = 0; i < stage.copied.size(); ++i) {
        if (i > 0) {
            out << ',';
        }
        out << "\"" << jsonEscape(stage.copied[i]) << "\"";
    }
    out << "],\n";
    out << indent << "  \"missingSources\": [";
    for (std::size_t i = 0; i < stage.missingSources.size(); ++i) {
        if (i > 0) {
            out << ',';
        }
        out << "\"" << jsonEscape(stage.missingSources[i]) << "\"";
    }
    out << "],\n";
    out << indent << "  \"errors\": [";
    for (std::size_t i = 0; i < stage.errors.size(); ++i) {
        if (i > 0) {
            out << ',';
        }
        out << "\"" << jsonEscape(stage.errors[i]) << "\"";
    }
    out << "]\n";
    out << indent << "}";
}

void printWindowsRepairPlan(const antivirus::WindowsRepairPlan &plan, bool jsonOutput) {
    if (jsonOutput) {
        writeWindowsPlanJson(std::cout, plan, "");
        std::cout << '\n';
        return;
    }

    std::cout << "[*] Windows repair audit for "
              << (plan.manifest.versionLabel.empty() ? "[unknown]" : plan.manifest.versionLabel)
              << " build " << (plan.manifest.buildNumber.empty() ? "[unknown]" : plan.manifest.buildNumber)
              << " (key=" << plan.manifest.manifestKey << ") root=" << plan.windowsRoot.generic_string() << "\n";

    if (plan.issues.empty()) {
        std::cout << "[+] No missing or corrupted baseline files detected." << std::endl;
    } else {
        for (const auto &issue : plan.issues) {
            const std::string type = windowsIssueType(issue);
            std::cout << "[!] " << type << ": " << issue.entry.relativePath
                      << " (critical=" << (issue.entry.critical ? "yes" : "no")
                      << ", expectedHash=" << (issue.entry.sha256.empty() ? "[unknown]" : issue.entry.sha256)
                      << ", expectedSize=" << issue.entry.size;
            if (issue.issue == antivirus::WindowsRepairIssueType::HashMismatch) {
                std::cout << ", observedHash=" << (issue.observedHash.empty() ? "[unknown]" : issue.observedHash)
                          << ", observedSize=" << issue.observedSize;
            } else {
                std::cout << ", observedHash=[missing], observedSize=" << issue.observedSize;
            }
            std::cout << "\n";
        }
    }

    for (const auto &error : plan.errors) {
        std::cout << "[!] Plan error: " << error << "\n";
    }
}

void printWindowsCollection(const antivirus::WindowsRepairPlan &plan, const antivirus::WindowsRepairStageResult &stage,
                            bool jsonOutput, const std::optional<fs::path> &planPath = std::nullopt,
                            bool planSaved = false) {
    if (jsonOutput) {
        std::cout << "{\n  \"plan\": ";
        writeWindowsPlanJson(std::cout, plan, "  ");
        std::cout << ",\n  \"stage\": ";
        writeWindowsStageJson(std::cout, stage, "  ");
        if (planPath) {
            std::cout << ",\n  \"planPath\": {\"path\": \"" << jsonEscape(planPath->generic_string())
                      << "\", \"saved\": " << (planSaved ? "true" : "false") << "}";
        }
        std::cout << "\n}\n";
        return;
    }

    printWindowsRepairPlan(plan, false);
    if (planPath) {
        std::cout << (planSaved ? "[+]" : "[!]") << " Plan output " << planPath->string();
        if (!planSaved) {
            std::cout << " (failed to write)";
        }
        std::cout << "\n";
    }
    std::cout << "[*] Staging results: copied " << stage.copied.size() << " file(s)." << std::endl;
    if (!stage.missingSources.empty()) {
        for (const auto &missing : stage.missingSources) {
            std::cout << "[!] Missing clean source: " << missing << "\n";
        }
    }
    if (!stage.errors.empty()) {
        for (const auto &error : stage.errors) {
            std::cout << "[!] Staging error: " << error << "\n";
        }
    }
}

fs::path resolveSelfPath(const char *argv0) {
    std::error_code ec;
    fs::path path = fs::read_symlink("/proc/self/exe", ec);
    if (!ec && !path.empty()) {
        return path;
    }
    if (argv0 != nullptr) {
        fs::path fallback(argv0);
        path = fs::absolute(fallback, ec);
        if (!ec) {
            return path;
        }
        return fallback;
    }
    return fs::current_path() / "paranoid_av";
}

void usage(const std::string &program) {
    std::cout << "Usage: " << program << " [options]\n"
              << "  --monitor                 Perform process inventory and heuristic analysis\n"
              << "  --monitor-loop <seconds>  Continuously monitor processes\n"
              << "  --json                    Emit monitor output as JSON\n"
              << "  --detailed                Emit verbose monitor report\n"
              << "  --threat-intel-load <file> Load threat intelligence indicators\n"
              << "  --threat-intel-add <type> <value> Append indicator to in-memory set\n"
              << "  --threat-intel-save <file> Persist current indicators\n"
              << "  --system-audit            Run host persistence, module, and privilege hygiene checks\n"
              << "  --rootkit-scan            Inspect kernel modules and artefacts for rootkit indicators\n"
              << "  --integrity-baseline <path> <baseline>  Generate file baseline for path\n"
              << "  --integrity-verify <path> <baseline>   Compare filesystem state to baseline\n"
              << "  --ransomware-watch <path> <seconds>    Observe filesystem activity for encryption\n"
              << "  --quarantine-file <path>  Move a file into quarantine\n"
              << "  --quarantine-pid <pid>    Send SIGTERM to process for containment\n"
              << "  --kill-pid <pid>          Force terminate process with SIGKILL\n"
              << "  --usb-create <device> [workdir]  Flash bootable scanner onto USB device\n"
              << "  --usb-workdir <path>      Override staging directory for USB creation\n"
              << "  --usb-include-tor         Include Tor client packages in the USB image\n"
              << "  --tor-proxy <port>        Override Tor SOCKS proxy port (default 9050)\n"
              << "  --darkweb-port <port>     Override onion service port (default 80)\n"
              << "  --darkweb-scan <host> <path> <keywords>  Query onion service via Tor for leaks\n"
              << "  --firewall-status         Display firewall profiles and policy summary\n"
              << "  --firewall-allow-app <path> [label] [direction]   Allow application through firewall\n"
              << "  --firewall-allow-port <port> [protocol] [direction] [label]  Allow TCP/UDP port\n"
             << "  --firewall-load-policy <file>   Load saved firewall policy and apply rules\n"
             << "  --firewall-save-policy <file>   Persist current firewall policy\n"
             << "  --firewall-remove-rule <name>   Delete a firewall rule by name\n"
             << "  --security-center-status   Enumerate Windows Security Center registrations\n"
              << "  --security-center-register <name> <exe> [guid=G] [reporting=exe] [mode=av|firewall|both]\n"
              << "  --windows-root <path>     Override Windows directory when auditing repair manifests\n"
              << "  --windows-repair-detect   Detect host Windows version and manifest key\n"
              << "  --windows-repair-capture <windows-root> <version> <build> <key> <output>  Capture manifest from clean volume\n"
              << "  --windows-repair-audit <manifest> [plan]  Compare Windows installation to manifest (optional plan output)\n"
              << "  --windows-repair-collect <repository> <output> [manifest]  Detect host version, audit, and stage repairs\n"
              << "  --scan <path>             Run ClamAV signature scan on path\n"
              << "  --yara <rules> <path>     Execute YARA scan against path using rules\n"
              << "  --openai <path>           Submit file to OpenAI-assisted analysis\n"
              << "  --help                    Show this help message\n";
}

std::string readFile(const fs::path &path) {
    std::ifstream input(path, std::ios::in | std::ios::binary);
    if (!input.is_open()) {
        throw std::runtime_error("Unable to open file: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

} // namespace

int main(int argc, char *argv[]) {
    if (argc == 1) {
        usage(argv[0]);
        return 0;
    }

    antivirus::ProcessScanner processScanner;
    antivirus::HeuristicAnalyzer heuristics;
    antivirus::SignatureScanner signatureScanner;
    antivirus::OpenAIAnalyzer aiAnalyzer;
    antivirus::YaraScanner yaraScanner;
    antivirus::SystemInspector systemInspector;
    antivirus::RootkitDetector rootkitDetector;
    antivirus::ThreatIntelDatabase threatIntel;
    antivirus::FileIntegrityMonitor integrityMonitor;
    antivirus::RansomwareMonitor ransomwareMonitor;
    antivirus::QuarantineManager quarantineManager;
    antivirus::USBDeployer usbDeployer;
    antivirus::WindowsRepairManager windowsRepairManager;
    antivirus::FirewallManager firewallManager;
    antivirus::WindowsSecurityCenterBridge securityCenterBridge;

    heuristics.setThreatIntel(&threatIntel);

    bool jsonOutput = false;
    bool detailedOutput = false;
    std::optional<std::string> threatIntelPath;
    int torProxyPort = 9050;
    std::uint16_t darkWebPort = 80;
    std::string usbWorkdir;
    bool usbIncludeTor = false;
    std::optional<fs::path> binaryPath;
    std::optional<fs::path> windowsRootOverride;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help") {
            usage(argv[0]);
            return 0;
        }

        if (arg == "--json") {
            jsonOutput = true;
            continue;
        }

        if (arg == "--detailed") {
            detailedOutput = true;
            continue;
        }

        if (arg == "--threat-intel-load") {
            if (i + 1 >= argc) {
                std::cerr << "--threat-intel-load requires a file path" << std::endl;
                return 1;
            }
            const std::string path = argv[++i];
            threatIntel.loadFromFile(path);
            threatIntelPath = path;
            std::cout << "[*] Loaded threat intelligence indicators from " << path << "\n";
            continue;
        }

        if (arg == "--threat-intel-add") {
            if (i + 2 >= argc) {
                std::cerr << "--threat-intel-add requires a type and value" << std::endl;
                return 1;
            }
            const std::string type = argv[++i];
            const std::string value = argv[++i];
            threatIntel.addIndicator(type, value);
            std::cout << "[*] Added indicator " << type << ':' << value << "\n";
            continue;
        }

        if (arg == "--threat-intel-save") {
            if (i + 1 >= argc) {
                if (!threatIntelPath) {
                    std::cerr << "--threat-intel-save requires a file path when no prior load" << std::endl;
                    return 1;
                }
                threatIntel.saveToFile(*threatIntelPath);
                std::cout << "[*] Saved threat intelligence to " << *threatIntelPath << "\n";
            } else {
                const std::string path = argv[++i];
                threatIntel.saveToFile(path);
                threatIntelPath = path;
                std::cout << "[*] Saved threat intelligence to " << path << "\n";
            }
            continue;
        }

        if (arg == "--monitor") {
            auto processes = processScanner.snapshotProcesses();
            for (auto &process : processes) {
                const auto report = heuristics.analyze(process);
                process.heuristics = report.findings;
                process.threatIntelHits = report.threatIntelHits;
                process.riskScore = report.score;
            }
            printProcessReport(processes, jsonOutput, detailedOutput);
            continue;
        }

        if (arg == "--system-audit") {
            const auto findings = systemInspector.scanAll();
            printSystemFindings(findings);
            continue;
        }

        if (arg == "--rootkit-scan") {
            const auto findings = rootkitDetector.scan();
            printRootkitReport(findings, jsonOutput);
            continue;
        }

        if (arg == "--integrity-baseline") {
            if (i + 2 >= argc) {
                std::cerr << "--integrity-baseline requires a root path and baseline file" << std::endl;
                return 1;
            }
            const std::string rootPath = argv[++i];
            const std::string baseline = argv[++i];
            try {
                integrityMonitor.createBaseline(rootPath, baseline);
                std::cout << "[+] Baseline created at " << baseline << " for " << rootPath << "\n";
            } catch (const std::exception &ex) {
                std::cerr << "Failed to create baseline: " << ex.what() << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--integrity-verify") {
            if (i + 2 >= argc) {
                std::cerr << "--integrity-verify requires a root path and baseline file" << std::endl;
                return 1;
            }
            const std::string rootPath = argv[++i];
            const std::string baseline = argv[++i];
            try {
                const auto report = integrityMonitor.verifyBaseline(rootPath, baseline);
                printFileIntegrityReport(report);
            } catch (const std::exception &ex) {
                std::cerr << "Failed to verify baseline: " << ex.what() << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--ransomware-watch") {
            if (i + 2 >= argc) {
                std::cerr << "--ransomware-watch requires a path and duration" << std::endl;
                return 1;
            }
            const std::string watchPath = argv[++i];
            const int seconds = std::stoi(argv[++i]);
            try {
                const auto summary = ransomwareMonitor.watch(watchPath, std::chrono::seconds(seconds));
                printRansomwareSummary(summary);
            } catch (const std::exception &ex) {
                std::cerr << "Ransomware monitor failed: " << ex.what() << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--quarantine-file") {
            if (i + 1 >= argc) {
                std::cerr << "--quarantine-file requires a path" << std::endl;
                return 1;
            }
            const std::string target = argv[++i];
            try {
                const auto quarantined = quarantineManager.quarantineFile(target);
                std::cout << "[!] Moved to quarantine: " << quarantined << "\n";
            } catch (const std::exception &ex) {
                std::cerr << "Failed to quarantine file: " << ex.what() << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--quarantine-pid" || arg == "--kill-pid") {
            if (i + 1 >= argc) {
                std::cerr << arg << " requires a PID" << std::endl;
                return 1;
            }
            const int pid = std::stoi(argv[++i]);
            const bool force = (arg == "--kill-pid");
            if (quarantineManager.terminateProcess(pid, force)) {
                std::cout << "[!] Sent " << (force ? "SIGKILL" : "SIGTERM") << " to PID " << pid << "\n";
            } else {
                std::cerr << "Failed to signal PID " << pid << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--usb-workdir") {
            if (i + 1 >= argc) {
                std::cerr << "--usb-workdir requires a directory" << std::endl;
                return 1;
            }
            usbWorkdir = argv[++i];
            continue;
        }

        if (arg == "--usb-include-tor") {
            usbIncludeTor = true;
            continue;
        }

        if (arg == "--usb-create") {
            if (i + 1 >= argc) {
                std::cerr << "--usb-create requires a block device" << std::endl;
                return 1;
            }
            const std::string device = argv[++i];
            std::string workdir = usbWorkdir;
            if (i + 1 < argc) {
                const std::string next = argv[i + 1];
                if (!next.empty() && next[0] != '-') {
                    workdir = next;
                    ++i;
                }
            }
            if (!binaryPath) {
                binaryPath = resolveSelfPath(argv[0]);
            }
            const auto result = usbDeployer.deploy(device, workdir, usbIncludeTor, binaryPath->string());
            if (!result.output.empty()) {
                std::cout << result.output;
                if (result.output.back() != '\n') {
                    std::cout << '\n';
                }
            }
            if (result.success) {
                std::cout << "[+] USB deployment completed successfully.\n";
            } else {
                std::cerr << "[!] USB deployment failed (exit code " << result.exitCode << ").\n";
                return result.exitCode == 0 ? 1 : result.exitCode;
            }
            continue;
        }

        if (arg == "--windows-root") {
            if (i + 1 >= argc) {
                std::cerr << "--windows-root requires a directory" << std::endl;
                return 1;
            }
            windowsRootOverride = fs::path(argv[++i]);
            continue;
        }

        if (arg == "--windows-repair-detect") {
            const auto info = windowsRepairManager.detectHostVersion();
            if (!info) {
                std::cerr << "Windows version detection unavailable on this platform. Supply --windows-root for offline analysis." << std::endl;
                return 1;
            }
            if (jsonOutput) {
                std::cout << "{\"success\":true,\"productName\":\"" << jsonEscape(info->productName)
                          << "\",\"manifestKey\":\"" << jsonEscape(info->manifestKey)
                          << "\",\"build\":\"" << jsonEscape(info->buildNumber) << "\"}\n";
            } else {
                std::cout << "[*] Detected " << info->productName << " build " << info->buildNumber
                          << " (manifest key " << info->manifestKey << ")" << std::endl;
            }
            continue;
        }

        if (arg == "--windows-repair-capture") {
            if (i + 5 >= argc) {
                std::cerr << "--windows-repair-capture requires windows root, version, build, key, and output path" << std::endl;
                return 1;
            }
            const fs::path windowsRoot = argv[++i];
            const std::string versionLabel = argv[++i];
            const std::string buildNumber = argv[++i];
            const std::string manifestKey = argv[++i];
            const fs::path outputPath = argv[++i];
            const auto manifest = windowsRepairManager.captureBaseline(windowsRoot, versionLabel, buildNumber, manifestKey);
            const bool saved = windowsRepairManager.saveManifest(manifest, outputPath);
            if (jsonOutput) {
                std::cout << "{\"saved\":" << (saved ? "true" : "false") << ",\"entries\":" << manifest.files.size()
                          << ",\"output\":\"" << jsonEscape(outputPath.generic_string()) << "\"}\n";
            } else {
                if (saved) {
                    std::cout << "[+] Captured " << manifest.files.size() << " baseline entries -> " << outputPath << "\n";
                } else {
                    std::cerr << "[!] Failed to write manifest to " << outputPath << std::endl;
                    return 1;
                }
            }
            if (!saved) {
                return 1;
            }
            continue;
        }

        if (arg == "--windows-repair-audit") {
            if (i + 1 >= argc) {
                std::cerr << "--windows-repair-audit requires a manifest path" << std::endl;
                return 1;
            }
            const fs::path manifestPath = argv[++i];
            std::optional<fs::path> planPath;
            if (i + 1 < argc) {
                const std::string next = argv[i + 1];
                if (!next.empty() && next[0] != '-') {
                    planPath = fs::path(next);
                    ++i;
                }
            }
            fs::path windowsRoot;
            if (windowsRootOverride) {
                windowsRoot = *windowsRootOverride;
            } else {
                auto defaultRoot = windowsRepairManager.defaultWindowsRoot();
                if (!defaultRoot) {
                    std::cerr << "Provide --windows-root when auditing from non-Windows environments." << std::endl;
                    return 1;
                }
                windowsRoot = *defaultRoot;
            }
            antivirus::WindowsManifest manifest;
            try {
                manifest = windowsRepairManager.loadManifest(manifestPath);
            } catch (const std::exception &ex) {
                std::cerr << "Failed to load manifest: " << ex.what() << std::endl;
                return 1;
            }
            const auto plan = windowsRepairManager.analyze(windowsRoot, manifest);
            bool planSaved = false;
            if (planPath) {
                planSaved = windowsRepairManager.savePlan(plan, *planPath);
            }
            if (jsonOutput) {
                std::cout << "{\n  \"plan\": ";
                writeWindowsPlanJson(std::cout, plan, "  ");
                if (planPath) {
                    std::cout << ",\n  \"planPath\": {\"path\": \"" << jsonEscape(planPath->generic_string())
                              << "\", \"saved\": " << (planSaved ? "true" : "false") << "}";
                }
                std::cout << "\n}\n";
            } else {
                printWindowsRepairPlan(plan, false);
                if (planPath) {
                    std::cout << (planSaved ? "[+]" : "[!]") << " Plan output " << planPath->string();
                    if (!planSaved) {
                        std::cout << " (failed to write)";
                    }
                    std::cout << "\n";
                }
            }
            if (!plan.errors.empty()) {
                return 1;
            }
            continue;
        }

        if (arg == "--windows-repair-collect") {
            if (i + 2 >= argc) {
                std::cerr << "--windows-repair-collect requires repository and output directories" << std::endl;
                return 1;
            }
            const fs::path repositoryRoot = argv[++i];
            const fs::path outputDir = argv[++i];
            std::optional<fs::path> manifestOverride;
            if (i + 1 < argc) {
                const std::string next = argv[i + 1];
                if (!next.empty() && next[0] != '-') {
                    manifestOverride = fs::path(next);
                    ++i;
                }
            }
            auto versionInfo = windowsRepairManager.detectHostVersion();
            if (!versionInfo && !manifestOverride) {
                std::cerr << "Unable to detect Windows version. Provide an explicit manifest path." << std::endl;
                return 1;
            }
            fs::path manifestPath;
            if (manifestOverride) {
                manifestPath = *manifestOverride;
            } else {
                manifestPath = repositoryRoot / (versionInfo->manifestKey + ".manifest");
            }
            antivirus::WindowsManifest manifest;
            try {
                manifest = windowsRepairManager.loadManifest(manifestPath);
            } catch (const std::exception &ex) {
                std::cerr << "Failed to load manifest: " << ex.what() << std::endl;
                return 1;
            }
            fs::path windowsRoot;
            if (windowsRootOverride) {
                windowsRoot = *windowsRootOverride;
            } else {
                auto defaultRoot = windowsRepairManager.defaultWindowsRoot();
                if (!defaultRoot) {
                    std::cerr << "Provide --windows-root when staging repairs from non-Windows environments." << std::endl;
                    return 1;
                }
                windowsRoot = *defaultRoot;
            }
            const auto plan = windowsRepairManager.analyze(windowsRoot, manifest);
            const auto stage = windowsRepairManager.stageRepairs(repositoryRoot, plan, outputDir);
            const fs::path planPath = outputDir / (manifest.manifestKey + "_plan.txt");
            const bool planSaved = windowsRepairManager.savePlan(plan, planPath);
            printWindowsCollection(plan, stage, jsonOutput, planPath, planSaved);
            if (!stage.errors.empty() || !stage.missingSources.empty()) {
                return 1;
            }
            continue;
        }

        if (arg == "--tor-proxy") {
            if (i + 1 >= argc) {
                std::cerr << "--tor-proxy requires a port" << std::endl;
                return 1;
            }
            torProxyPort = std::stoi(argv[++i]);
            continue;
        }

        if (arg == "--darkweb-port") {
            if (i + 1 >= argc) {
                std::cerr << "--darkweb-port requires a port" << std::endl;
                return 1;
            }
            darkWebPort = static_cast<std::uint16_t>(std::stoi(argv[++i]));
            continue;
        }

        if (arg == "--darkweb-scan") {
            if (i + 3 >= argc) {
                std::cerr << "--darkweb-scan requires host, path, and comma-separated keywords" << std::endl;
                return 1;
            }
            const std::string host = argv[++i];
            const std::string path = argv[++i];
            const std::string keywordsArg = argv[++i];
            const auto keywords = splitComma(keywordsArg);
            if (keywords.empty()) {
                std::cerr << "Provide at least one keyword for --darkweb-scan" << std::endl;
                return 1;
            }
            try {
                antivirus::TorClient torClient("127.0.0.1", static_cast<std::uint16_t>(torProxyPort));
                antivirus::DarkWebScanner scanner(std::move(torClient));
                const auto result = scanner.scan(host, path, keywords, darkWebPort);
                printDarkWebResult(result);
            } catch (const std::exception &ex) {
                std::cerr << "Dark web scan failed: " << ex.what() << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--firewall-status") {
            const auto status = firewallManager.inspectStatus();
            printFirewallStatus(status, jsonOutput);
            continue;
        }

        if (arg == "--firewall-allow-app") {
            if (i + 1 >= argc) {
                std::cerr << "--firewall-allow-app requires an executable path" << std::endl;
                return 1;
            }
            const std::string application = argv[++i];
            std::string label;
            std::string direction = "both";
            while (i + 1 < argc) {
                const std::string peek = argv[i + 1];
                if (peek.rfind("--", 0) == 0) {
                    break;
                }
                if (isDirectionToken(peek)) {
                    direction = canonicalDirection(peek);
                    ++i;
                    continue;
                }
                if (label.empty()) {
                    label = peek;
                    ++i;
                    continue;
                }
                break;
            }
            const bool allowed = firewallManager.allowApplication(application, label, direction);
            std::cout << (allowed ? "[+]" : "[!]") << " Registered firewall application rule for " << application << "\n";
            printFirewallDiagnostics(firewallManager);
            continue;
        }

        if (arg == "--firewall-allow-port") {
            if (i + 1 >= argc) {
                std::cerr << "--firewall-allow-port requires a port" << std::endl;
                return 1;
            }
            const int portValue = std::stoi(argv[++i]);
            if (portValue <= 0 || portValue > 65535) {
                std::cerr << "Port must be between 1 and 65535" << std::endl;
                return 1;
            }
            std::string protocol = "TCP";
            std::string direction = "both";
            std::string label;
            while (i + 1 < argc) {
                const std::string peek = argv[i + 1];
                if (peek.rfind("--", 0) == 0) {
                    break;
                }
                if (isProtocolToken(peek)) {
                    protocol = peek;
                    ++i;
                    continue;
                }
                if (isDirectionToken(peek)) {
                    direction = canonicalDirection(peek);
                    ++i;
                    continue;
                }
                if (label.empty()) {
                    label = peek;
                    ++i;
                    continue;
                }
                break;
            }
            const bool allowed = firewallManager.allowPort(static_cast<std::uint16_t>(portValue), protocol, direction, label);
            std::cout << (allowed ? "[+]" : "[!]") << " Registered firewall port rule for " << portValue << "\n";
            printFirewallDiagnostics(firewallManager);
            continue;
        }

        if (arg == "--firewall-load-policy") {
            if (i + 1 >= argc) {
                std::cerr << "--firewall-load-policy requires a file path" << std::endl;
                return 1;
            }
            const std::string policyPath = argv[++i];
            if (!firewallManager.loadPolicy(policyPath)) {
                printFirewallDiagnostics(firewallManager);
                return 1;
            }
            for (const auto &rule : firewallManager.policyRules()) {
                firewallManager.applyRule(rule);
            }
            std::cout << "[+] Loaded firewall policy from " << policyPath << "\n";
            printFirewallDiagnostics(firewallManager);
            continue;
        }

        if (arg == "--firewall-save-policy") {
            if (i + 1 >= argc) {
                std::cerr << "--firewall-save-policy requires a file path" << std::endl;
                return 1;
            }
            const std::string policyPath = argv[++i];
            if (firewallManager.savePolicy(policyPath)) {
                std::cout << "[+] Firewall policy saved to " << policyPath << "\n";
            } else {
                std::cerr << "Failed to save firewall policy to " << policyPath << std::endl;
                return 1;
            }
            continue;
        }

        if (arg == "--firewall-remove-rule") {
            if (i + 1 >= argc) {
                std::cerr << "--firewall-remove-rule requires a rule name" << std::endl;
                return 1;
            }
            const std::string ruleName = argv[++i];
            const bool removed = firewallManager.removeRule(ruleName);
            std::cout << (removed ? "[+]" : "[!]") << " Removal attempted for firewall rule " << ruleName << "\n";
            printFirewallDiagnostics(firewallManager);
            continue;
        }

        if (arg == "--security-center-status") {
            const auto products = securityCenterBridge.enumerateProducts();
            printSecurityCenterProducts(products, jsonOutput);
            continue;
        }

        if (arg == "--security-center-register") {
            if (i + 2 >= argc) {
                std::cerr << "--security-center-register requires a product name and executable path" << std::endl;
                return 1;
            }
            antivirus::SecurityCenterRegistration registration;
            registration.productName = argv[++i];
            registration.productPath = argv[++i];
            registration.reportingPath = registration.productPath;
            while (i + 1 < argc) {
                const std::string peek = argv[i + 1];
                if (peek.rfind("--", 0) == 0) {
                    break;
                }
                const auto delimiter = peek.find('=');
                if (delimiter == std::string::npos) {
                    break;
                }
                ++i;
                const std::string key = peek.substr(0, delimiter);
                const std::string value = peek.substr(delimiter + 1);
                if (key == "guid") {
                    registration.guid = value;
                } else if (key == "reporting") {
                    registration.reportingPath = value;
                } else if (key == "mode") {
                    const std::string lower = toLowerCopy(value);
                    if (lower == "firewall") {
                        registration.includeAntivirus = false;
                        registration.includeFirewall = true;
                    } else if (lower == "antivirus" || lower == "av") {
                        registration.includeAntivirus = true;
                        registration.includeFirewall = false;
                    } else {
                        registration.includeAntivirus = true;
                        registration.includeFirewall = true;
                    }
                }
            }
            std::vector<std::string> errors;
            const bool success = securityCenterBridge.registerSuite(registration, &errors);
            if (!errors.empty()) {
                for (const auto &message : errors) {
                    std::cerr << "[!] " << message << "\n";
                }
            }
            if (!success) {
                return 1;
            }
            std::cout << "[+] Submitted suite registration to Windows Security Center." << std::endl;
            continue;
        }

        if (arg == "--monitor-loop") {
            if (i + 1 >= argc) {
                std::cerr << "--monitor-loop requires an interval in seconds" << std::endl;
                return 1;
            }
            const int interval = std::stoi(argv[++i]);
            std::cout << "[*] Continuous monitoring every " << interval << " seconds. Press Ctrl+C to stop.\n";
            while (true) {
                auto processes = processScanner.snapshotProcesses();
                for (auto &process : processes) {
                    const auto report = heuristics.analyze(process);
                    process.heuristics = report.findings;
                    process.threatIntelHits = report.threatIntelHits;
                    process.riskScore = report.score;
                }
                printProcessReport(processes, jsonOutput, detailedOutput);
                std::this_thread::sleep_for(std::chrono::seconds(interval));
            }
        }

        if (arg == "--scan") {
            if (i + 1 >= argc) {
                std::cerr << "--scan requires a path" << std::endl;
                return 1;
            }
            const std::string path = argv[++i];
            if (!fs::exists(path)) {
                std::cerr << "Path not found: " << path << std::endl;
                return 1;
            }
            const auto result = signatureScanner.scanPath(path);
            printSignatureReport(result);
            continue;
        }

        if (arg == "--yara") {
            if (i + 2 >= argc) {
                std::cerr << "--yara requires a rules path and a target path" << std::endl;
                return 1;
            }
            const std::string rules = argv[++i];
            const std::string target = argv[++i];
            if (!fs::exists(rules)) {
                std::cerr << "Rules not found: " << rules << std::endl;
                return 1;
            }
            if (!fs::exists(target)) {
                std::cerr << "Target not found: " << target << std::endl;
                return 1;
            }
            const auto result = yaraScanner.scanPath(rules, target);
            printYaraReport(result);
            continue;
        }

        if (arg == "--openai") {
            if (i + 1 >= argc) {
                std::cerr << "--openai requires a path" << std::endl;
                return 1;
            }
            const std::string path = argv[++i];
            if (!fs::exists(path)) {
                std::cerr << "File not found: " << path << std::endl;
                return 1;
            }
            try {
                const auto sample = readFile(path);
                const auto result = aiAnalyzer.analyzeSample(sample, "Process or file supplied via CLI");
                printAIReport(result);
            } catch (const std::exception &ex) {
                std::cerr << "Failed to read sample: " << ex.what() << std::endl;
                return 1;
            }
            continue;
        }

        std::cerr << "Unknown argument: " << arg << "\n";
        usage(argv[0]);
        return 1;
    }

    return 0;
}
