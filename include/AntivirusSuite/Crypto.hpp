#pragma once

#include <string>

namespace antivirus::crypto {

std::string sha256(const std::string &data);
std::string sha256File(const std::string &path);

}
