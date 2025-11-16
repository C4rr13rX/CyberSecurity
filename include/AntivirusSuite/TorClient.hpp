#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace antivirus {

struct TorHttpResponse {
    int statusCode{0};
    std::map<std::string, std::string> headers;
    std::string body;
    std::size_t bytesTransferred{0};
    double elapsedSeconds{0.0};
};

class TorClient {
  public:
    TorClient(std::string proxyHost = "127.0.0.1", std::uint16_t proxyPort = 9050);

    TorHttpResponse httpRequest(const std::string &method, const std::string &host, std::uint16_t port,
                                const std::string &path, const std::vector<std::pair<std::string, std::string>> &headers,
                                const std::string &body, int timeoutSeconds = 20, int maxRedirects = 2) const;

    TorHttpResponse httpGet(const std::string &host, std::uint16_t port, const std::string &path,
                            int timeoutSeconds = 20) const;

  private:
    std::string proxyHost;
    std::uint16_t proxyPort;
};

} // namespace antivirus

