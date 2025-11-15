#include "AntivirusSuite/OpenAIAnalyzer.hpp"

#include <array>
#include <cstdlib>
#include <sstream>

namespace antivirus {

OpenAIAnalyzer::OpenAIAnalyzer(std::string model) : modelName(std::move(model)) {
    const char *key = std::getenv("OPENAI_API_KEY");
    if (key != nullptr) {
        apiKey = key;
    }
}

bool OpenAIAnalyzer::isConfigured() const {
    return !apiKey.empty();
}

OpenAIAnalysisResult OpenAIAnalyzer::analyzeSample(const std::string &sample, const std::string &context) const {
    OpenAIAnalysisResult result;
    if (apiKey.empty()) {
        result.errorMessage = "OPENAI_API_KEY environment variable is not set. Skipping AI analysis.";
        return result;
    }

    std::ostringstream prompt;
    prompt << "You are an antivirus assistant. Analyze the following artefact and report potential malicious "
           << "behaviour, MITRE ATT&CK techniques, and recommended remediation steps. Context: " << context
           << "\n\nArtefact:\n" << sample;

    // Use curl for simplicity; curl must be available on the host system.
    std::ostringstream command;
    command << "curl -sS -X POST https://api.openai.com/v1/chat/completions "
            << "-H 'Authorization: Bearer " << apiKey << "' "
            << "-H 'Content-Type: application/json' "
            << "-d '{";

    // Build JSON payload in a curl-friendly way (escape quotes)
    std::string escapedPrompt;
    escapedPrompt.reserve(prompt.str().size());
    for (const char ch : prompt.str()) {
        if (ch == '\\') {
            escapedPrompt += "\\\\";
        } else if (ch == '\"') {
            escapedPrompt += "\\\"";
        } else if (ch == '\n') {
            escapedPrompt += "\\n";
        } else {
            escapedPrompt += ch;
        }
    }

    command << "\"model\":\"" << modelName << "\","
            << "\"messages\":[{\"role\":\"system\",\"content\":\"You are a defensive cybersecurity analyst.\"},"
            << "{\"role\":\"user\",\"content\":\"" << escapedPrompt << "\"}]";
    command << "}'";

    FILE *pipe = popen(command.str().c_str(), "r");
    if (!pipe) {
        result.errorMessage = "Failed to execute curl command for OpenAI analysis.";
        return result;
    }

    std::array<char, 512> buffer{};
    std::ostringstream response;
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        response << buffer.data();
    }
    const int exitCode = pclose(pipe);
    if (exitCode != 0) {
        result.errorMessage = "curl command returned non-zero exit code.";
        result.rawResponse = response.str();
        return result;
    }

    result.executed = true;
    result.rawResponse = response.str();
    result.summary = "OpenAI response captured. Parse JSON for actionable findings.";
    return result;
}

} // namespace antivirus
