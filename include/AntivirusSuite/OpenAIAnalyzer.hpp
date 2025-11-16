#pragma once

#include <optional>
#include <string>
#include <vector>

namespace antivirus {

struct OpenAIAnalysisResult {
    bool executed{false};
    std::string summary;
    std::string rawResponse;
    std::string errorMessage;
};

class OpenAIAnalyzer {
  public:
    explicit OpenAIAnalyzer(std::string model = "gpt-4o-mini");

    OpenAIAnalysisResult analyzeSample(const std::string &sample, const std::string &context) const;
    bool isConfigured() const;

  private:
    std::string modelName;
    std::string apiKey;
};

} // namespace antivirus
