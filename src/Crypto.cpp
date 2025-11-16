#include "AntivirusSuite/Crypto.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace {

class Sha256Context {
  public:
    void update(const std::uint8_t *data, std::size_t len) {
        for (std::size_t i = 0; i < len; ++i) {
            buffer[index++] = data[i];
            if (index == 64) {
                transform();
                bitLength += 512;
                index = 0;
            }
        }
    }

    void final(std::array<std::uint8_t, 32> &hash) {
        std::size_t i = index;

        if (index < 56) {
            buffer[i++] = 0x80;
            while (i < 56) {
                buffer[i++] = 0x00;
            }
        } else {
            buffer[i++] = 0x80;
            while (i < 64) {
                buffer[i++] = 0x00;
            }
            transform();
            std::fill(buffer.begin(), buffer.begin() + 56, 0);
        }

        bitLength += index * 8ULL;
        buffer[63] = static_cast<std::uint8_t>(bitLength);
        buffer[62] = static_cast<std::uint8_t>(bitLength >> 8);
        buffer[61] = static_cast<std::uint8_t>(bitLength >> 16);
        buffer[60] = static_cast<std::uint8_t>(bitLength >> 24);
        buffer[59] = static_cast<std::uint8_t>(bitLength >> 32);
        buffer[58] = static_cast<std::uint8_t>(bitLength >> 40);
        buffer[57] = static_cast<std::uint8_t>(bitLength >> 48);
        buffer[56] = static_cast<std::uint8_t>(bitLength >> 56);
        transform();

        for (std::size_t j = 0; j < 4; ++j) {
            for (std::size_t k = 0; k < 8; ++k) {
                hash[j + (k * 4)] = static_cast<std::uint8_t>((state[k] >> (24 - j * 8)) & 0x000000ffu);
            }
        }
    }

    static Sha256Context create() {
        Sha256Context ctx;
        ctx.state = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                     0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        ctx.index = 0;
        ctx.bitLength = 0;
        return ctx;
    }

  private:
    std::array<std::uint32_t, 8> state{};
    std::array<std::uint8_t, 64> buffer{};
    std::size_t index{0};
    unsigned long long bitLength{0};

    static std::uint32_t rotr(std::uint32_t value, std::uint32_t bits) {
        return (value >> bits) | (value << (32 - bits));
    }

    void transform() {
        static constexpr std::array<std::uint32_t, 64> k = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
            0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
            0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
            0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
            0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
            0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
            0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
            0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

        std::array<std::uint32_t, 64> m{};
        for (std::size_t i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (static_cast<std::uint32_t>(buffer[j]) << 24) | (static_cast<std::uint32_t>(buffer[j + 1]) << 16) |
                   (static_cast<std::uint32_t>(buffer[j + 2]) << 8) | (static_cast<std::uint32_t>(buffer[j + 3]));
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const auto s0 = rotr(m[i - 15], 7) ^ rotr(m[i - 15], 18) ^ (m[i - 15] >> 3);
            const auto s1 = rotr(m[i - 2], 17) ^ rotr(m[i - 2], 19) ^ (m[i - 2] >> 10);
            m[i] = m[i - 16] + s0 + m[i - 7] + s1;
        }

        auto a = state[0];
        auto b = state[1];
        auto c = state[2];
        auto d = state[3];
        auto e = state[4];
        auto f = state[5];
        auto g = state[6];
        auto h = state[7];

        for (std::size_t i = 0; i < 64; ++i) {
            const auto s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const auto ch = (e & f) ^ ((~e) & g);
            const auto temp1 = h + s1 + ch + k[i] + m[i];
            const auto s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
};

} // namespace

namespace antivirus::crypto {

std::string sha256(const std::string &data) {
    auto ctx = Sha256Context::create();
    ctx.update(reinterpret_cast<const std::uint8_t *>(data.data()), data.size());
    std::array<std::uint8_t, 32> digest{};
    ctx.final(digest);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : digest) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::string sha256File(const std::string &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        return {};
    }

    auto ctx = Sha256Context::create();
    std::array<char, 4096> buffer{};
    while (input.good()) {
        input.read(buffer.data(), buffer.size());
        const auto bytesRead = input.gcount();
        if (bytesRead > 0) {
            ctx.update(reinterpret_cast<const std::uint8_t *>(buffer.data()), static_cast<std::size_t>(bytesRead));
        }
    }

    if (input.bad()) {
        return {};
    }

    std::array<std::uint8_t, 32> digest{};
    ctx.final(digest);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : digest) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

} // namespace antivirus::crypto
