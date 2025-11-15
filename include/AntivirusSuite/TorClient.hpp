#pragma once

#include <cstdint>
#include <string>

namespace antivirus {

class TorClient {
  public:
    TorClient(std::string proxyHost = "127.0.0.1", std::uint16_t proxyPort = 9050);

    std::string httpGet(const std::string &host, std::uint16_t port, const std::string &path,
                        int timeoutSeconds = 20) const;

  private:
    std::string proxyHost;
    std::uint16_t proxyPort;
};

} // namespace antivirus

