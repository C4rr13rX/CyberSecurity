#include "AntivirusSuite/TorClient.hpp"

#ifndef _WIN32

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <map>
#include <netdb.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
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

std::string toLower(const std::string &value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return lowered;
}

std::map<std::string, std::string> parseHeaders(const std::string &rawHeaders) {
    std::map<std::string, std::string> headers;
    std::istringstream iss(rawHeaders);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line == "\r") {
            continue;
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string key = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        if (!value.empty() && value.front() == ' ') {
            value.erase(value.begin());
        }
        if (!value.empty() && value.back() == '\r') {
            value.pop_back();
        }
        headers[toLower(key)] = value;
    }
    return headers;
}

std::string decodeChunked(const std::string &body) {
    std::size_t position = 0;
    std::string decoded;
    while (position < body.size()) {
        const auto lineEnd = body.find("\r\n", position);
        if (lineEnd == std::string::npos) {
            break;
        }
        const auto chunkSizeStr = body.substr(position, lineEnd - position);
        position = lineEnd + 2;
        std::size_t chunkSize = 0;
        std::stringstream ss;
        ss << std::hex << chunkSizeStr;
        ss >> chunkSize;
        if (chunkSize == 0) {
            break;
        }
        if (position + chunkSize > body.size()) {
            break;
        }
        decoded.append(body.substr(position, chunkSize));
        position += chunkSize + 2; // skip data and CRLF
    }
    return decoded;
}

std::string extractBody(const std::string &raw, std::size_t headerEnd,
                        const std::map<std::string, std::string> &headers) {
    auto body = raw.substr(headerEnd + 4);
    const auto transferEncoding = headers.find("transfer-encoding");
    if (transferEncoding != headers.end() && transferEncoding->second.find("chunked") != std::string::npos) {
        body = decodeChunked(body);
    }
    return body;
}

bool parseLocation(const std::string &location, std::string &hostOut, std::uint16_t &portOut, std::string &pathOut) {
    if (location.empty()) {
        return false;
    }
    std::string url = location;
    if (url.find("http://") == 0) {
        url = url.substr(7);
    } else if (url.find("https://") == 0) {
        url = url.substr(8);
    }
    const auto slash = url.find('/');
    std::string hostPort = url.substr(0, slash);
    pathOut = (slash == std::string::npos) ? "/" : url.substr(slash);
    const auto colon = hostPort.find(':');
    if (colon != std::string::npos) {
        hostOut = hostPort.substr(0, colon);
        portOut = static_cast<std::uint16_t>(std::stoi(hostPort.substr(colon + 1)));
    } else {
        hostOut = hostPort;
        portOut = 80;
    }
    return true;
}

} // namespace

TorClient::TorClient(std::string host, std::uint16_t port) : proxyHost(std::move(host)), proxyPort(port) {}

TorHttpResponse TorClient::httpRequest(const std::string &method, const std::string &host, std::uint16_t port,
                                       const std::string &path,
                                       const std::vector<std::pair<std::string, std::string>> &headers,
                                       const std::string &body, int timeoutSeconds, int maxRedirects) const {
    std::string currentHost = host;
    std::string currentPath = path;
    std::uint16_t currentPort = port;

    for (int redirect = 0; redirect <= maxRedirects; ++redirect) {
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
        connectRequest.push_back(0x05);
        connectRequest.push_back(0x01);
        connectRequest.push_back(0x00);
        connectRequest.push_back(0x03);
        connectRequest.push_back(static_cast<unsigned char>(currentHost.size()));
        connectRequest.insert(connectRequest.end(), currentHost.begin(), currentHost.end());
        connectRequest.push_back(static_cast<unsigned char>((currentPort >> 8) & 0xFF));
        connectRequest.push_back(static_cast<unsigned char>(currentPort & 0xFF));

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
        request << method << ' ' << currentPath << " HTTP/1.1\r\n";
        request << "Host: " << currentHost << "\r\n";
        request << "User-Agent: paranoid-av/1.1\r\n";
        request << "Accept: */*\r\n";
        for (const auto &[headerKey, headerValue] : headers) {
            request << headerKey << ": " << headerValue << "\r\n";
        }
        if (!body.empty()) {
            request << "Content-Length: " << body.size() << "\r\n";
        }
        request << "Connection: close\r\n\r\n";
        if (!body.empty()) {
            request << body;
        }

        const auto requestStr = request.str();
        if (send(sock, requestStr.c_str(), requestStr.size(), 0) != static_cast<ssize_t>(requestStr.size())) {
            close(sock);
            throw std::runtime_error("Failed to send HTTP request through Tor");
        }

        const auto start = std::chrono::steady_clock::now();
        const auto responseBody = readAll(sock);
        const auto end = std::chrono::steady_clock::now();
        close(sock);

        if (responseBody.empty()) {
            throw std::runtime_error("Empty response via Tor");
        }

        const auto headerEnd = responseBody.find("\r\n\r\n");
        if (headerEnd == std::string::npos) {
            throw std::runtime_error("Invalid HTTP response received via Tor");
        }

        std::istringstream headerStream(responseBody.substr(0, headerEnd));
        std::string statusLine;
        std::getline(headerStream, statusLine);
        if (statusLine.empty()) {
            throw std::runtime_error("Malformed status line in Tor response");
        }

        std::istringstream statusStream(statusLine);
        std::string httpVersion;
        statusStream >> httpVersion;
        int statusCode = 0;
        statusStream >> statusCode;

        const auto headersMap = parseHeaders(responseBody.substr(statusLine.size() + 2, headerEnd - (statusLine.size() + 2)));
        auto bodyContent = extractBody(responseBody, headerEnd, headersMap);

        TorHttpResponse httpResponse{};
        httpResponse.statusCode = statusCode;
        httpResponse.headers = headersMap;
        httpResponse.body = bodyContent;
        httpResponse.bytesTransferred = responseBody.size();
        httpResponse.elapsedSeconds =
            std::chrono::duration_cast<std::chrono::duration<double>>(end - start).count();

        if (statusCode >= 300 && statusCode < 400) {
            const auto locationIt = headersMap.find("location");
            if (locationIt != headersMap.end()) {
                if (parseLocation(locationIt->second, currentHost, currentPort, currentPath)) {
                    continue;
                }
            }
        }

        return httpResponse;
    }

    throw std::runtime_error("Tor redirect limit exceeded");
}

TorHttpResponse TorClient::httpGet(const std::string &host, std::uint16_t port, const std::string &path,
                                   int timeoutSeconds) const {
    return httpRequest("GET", host, port, path, {}, "", timeoutSeconds);
}

} // namespace antivirus

#else

namespace antivirus {

TorClient::TorClient(std::string host, std::uint16_t port) : proxyHost(std::move(host)), proxyPort(port) {}

TorHttpResponse TorClient::httpRequest(const std::string &, const std::string &, std::uint16_t,
                                       const std::string &, const std::vector<std::pair<std::string, std::string>> &,
                                       const std::string &, int, int) const {
    TorHttpResponse response;
    response.statusCode = 0;
    response.body = "Tor client is not supported on Windows builds.";
    return response;
}

TorHttpResponse TorClient::httpGet(const std::string &host, std::uint16_t port, const std::string &path,
                                   int timeoutSeconds) const {
    return httpRequest("GET", host, port, path, {}, std::string(), timeoutSeconds, 0);
}

} // namespace antivirus

#endif // _WIN32

