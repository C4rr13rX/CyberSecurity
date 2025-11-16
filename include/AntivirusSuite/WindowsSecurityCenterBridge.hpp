#pragma once

#include <string>
#include <vector>

namespace antivirus {

struct SecurityCenterProduct {
    std::string name;
    std::string type;
    std::string state;
    std::string path;
    bool isDefault{false};
    bool registered{false};
};

struct SecurityCenterRegistration {
    std::string productName;
    std::string productPath;
    std::string reportingPath;
    std::string guid;
    bool includeAntivirus{true};
    bool includeFirewall{true};
};

class WindowsSecurityCenterBridge {
  public:
    bool registerSuite(const SecurityCenterRegistration &registration, std::vector<std::string> *errors = nullptr) const;
    std::vector<SecurityCenterProduct> enumerateProducts() const;

  private:
    bool registerProvider(const SecurityCenterRegistration &registration, const std::string &provider,
                          std::vector<std::string> *errors) const;
};

} // namespace antivirus
