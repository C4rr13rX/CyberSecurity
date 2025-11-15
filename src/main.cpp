#include "AntivirusSuite/DarkWebScanner.hpp"
#include "AntivirusSuite/FileIntegrityMonitor.hpp"
#include "AntivirusSuite/HeuristicAnalyzer.hpp"
#include "AntivirusSuite/OpenAIAnalyzer.hpp"
#include "AntivirusSuite/ProcessScanner.hpp"
#include "AntivirusSuite/QuarantineManager.hpp"
#include "AntivirusSuite/RansomwareMonitor.hpp"
#include "AntivirusSuite/SignatureScanner.hpp"
#include "AntivirusSuite/SystemInspector.hpp"
#include "AntivirusSuite/ThreatIntel.hpp"
#include "AntivirusSuite/TorClient.hpp"
#include "AntivirusSuite/YaraScanner.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>

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
              << "  --integrity-baseline <path> <baseline>  Generate file baseline for path\n"
              << "  --integrity-verify <path> <baseline>   Compare filesystem state to baseline\n"
              << "  --ransomware-watch <path> <seconds>    Observe filesystem activity for encryption\n"
              << "  --quarantine-file <path>  Move a file into quarantine\n"
              << "  --quarantine-pid <pid>    Send SIGTERM to process for containment\n"
              << "  --kill-pid <pid>          Force terminate process with SIGKILL\n"
              << "  --tor-proxy <port>        Override Tor SOCKS proxy port (default 9050)\n"
              << "  --darkweb-port <port>     Override onion service port (default 80)\n"
              << "  --darkweb-scan <host> <path> <keywords>  Query onion service via Tor for leaks\n"
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
    antivirus::ThreatIntelDatabase threatIntel;
    antivirus::FileIntegrityMonitor integrityMonitor;
    antivirus::RansomwareMonitor ransomwareMonitor;
    antivirus::QuarantineManager quarantineManager;

    heuristics.setThreatIntel(&threatIntel);

    bool jsonOutput = false;
    bool detailedOutput = false;
    std::optional<std::string> threatIntelPath;
    int torProxyPort = 9050;
    std::uint16_t darkWebPort = 80;

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
