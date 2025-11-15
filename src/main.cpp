#include "AntivirusSuite/HeuristicAnalyzer.hpp"
#include "AntivirusSuite/OpenAIAnalyzer.hpp"
#include "AntivirusSuite/ProcessScanner.hpp"
#include "AntivirusSuite/SignatureScanner.hpp"
#include "AntivirusSuite/SystemInspector.hpp"
#include "AntivirusSuite/YaraScanner.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

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

void usage(const std::string &program) {
    std::cout << "Usage: " << program << " [options]\n"
              << "  --monitor                 Perform process inventory and heuristic analysis\n"
              << "  --monitor-loop <seconds>  Continuously monitor processes\n"
              << "  --json                    Emit monitor output as JSON\n"
              << "  --detailed                Emit verbose monitor report\n"
              << "  --system-audit            Run host persistence, module, and privilege hygiene checks\n"
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

    bool jsonOutput = false;
    bool detailedOutput = false;

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

        if (arg == "--monitor") {
            auto processes = processScanner.snapshotProcesses();
            for (auto &process : processes) {
                const auto report = heuristics.analyze(process);
                process.heuristics = report.findings;
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
