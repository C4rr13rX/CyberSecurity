#include "AntivirusSuite/TorClient.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdexcept>
#include <string>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace antivirus {

namespace {

void setTimeout(int sock, int timeoutSeconds) {
    struct timeval tv {
        timeoutSeconds, 0
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

std::string readAll(int sock) {
    std::vector<char> buffer(4096);
    std::string result;
    ssize_t bytes = 0;
    while ((bytes = recv(sock, buffer.data(), buffer.size(), 0)) > 0) {
        result.append(buffer.data(), bytes);
    }
    return result;
}

} // namespace

TorClient::TorClient(std::string host, std::uint16_t port) : proxyHost(std::move(host)), proxyPort(port) {}

std::string TorClient::httpGet(const std::string &host, std::uint16_t port, const std::string &path,
                               int timeoutSeconds) const {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *resolved = nullptr;
    if (getaddrinfo(proxyHost.c_str(), std::to_string(proxyPort).c_str(), &hints, &resolved) != 0) {
        throw std::runtime_error("Unable to resolve Tor proxy host");
    }

    int sock = -1;
    for (auto *ptr = resolved; ptr != nullptr; ptr = ptr->ai_next) {
        sock = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (connect(sock, ptr->ai_addr, ptr->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    freeaddrinfo(resolved);

    if (sock < 0) {
        throw std::runtime_error("Unable to connect to Tor proxy");
    }

    setTimeout(sock, timeoutSeconds);

    const unsigned char greeting[3] = {0x05, 0x01, 0x00};
    if (send(sock, greeting, sizeof(greeting), 0) != static_cast<ssize_t>(sizeof(greeting))) {
        close(sock);
        throw std::runtime_error("Failed to negotiate with Tor proxy");
    }

    unsigned char response[2];
    if (recv(sock, response, sizeof(response), 0) != static_cast<ssize_t>(sizeof(response))) {
        close(sock);
        throw std::runtime_error("Tor proxy did not respond to greeting");
    }

    if (response[0] != 0x05 || response[1] != 0x00) {
        close(sock);
        throw std::runtime_error("Tor proxy requires unsupported authentication");
    }

    std::vector<unsigned char> connectRequest;
    connectRequest.push_back(0x05); // version
    connectRequest.push_back(0x01); // connect
    connectRequest.push_back(0x00); // reserved
    connectRequest.push_back(0x03); // domain name
    connectRequest.push_back(static_cast<unsigned char>(host.size()));
    connectRequest.insert(connectRequest.end(), host.begin(), host.end());
    connectRequest.push_back(static_cast<unsigned char>((port >> 8) & 0xFF));
    connectRequest.push_back(static_cast<unsigned char>(port & 0xFF));

    if (send(sock, connectRequest.data(), connectRequest.size(), 0) !=
        static_cast<ssize_t>(connectRequest.size())) {
        close(sock);
        throw std::runtime_error("Failed to send connect request to Tor proxy");
    }

    unsigned char connectResponse[10];
    const ssize_t connectBytes = recv(sock, connectResponse, sizeof(connectResponse), 0);
    if (connectBytes < 4 || connectResponse[1] != 0x00) {
        close(sock);
        throw std::runtime_error("Tor proxy connect request rejected");
    }

    std::ostringstream request;
    request << "GET " << path << " HTTP/1.1\r\n";
    request << "Host: " << host << "\r\n";
    request << "User-Agent: paranoid-av/1.0\r\n";
    request << "Connection: close\r\n\r\n";

    const auto requestStr = request.str();
    if (send(sock, requestStr.c_str(), requestStr.size(), 0) != static_cast<ssize_t>(requestStr.size())) {
        close(sock);
        throw std::runtime_error("Failed to send HTTP request through Tor");
    }

    const auto responseBody = readAll(sock);
    close(sock);
    return responseBody;
}

} // namespace antivirus

