#include "AntivirusSuite/WindowsSecurityCenterBridge.hpp"

#include <vector>

namespace antivirus {
namespace {
void appendUnsupported(std::vector<std::string> *errors, const std::string &message) {
    if (errors) {
        errors->push_back(message);
    }
}
} // namespace

bool WindowsSecurityCenterBridge::registerSuite(const SecurityCenterRegistration &registration,
                                                std::vector<std::string> *errors) const {
#ifdef _WIN32
    appendUnsupported(errors, "Windows Security Center integration is disabled in this build.");
    (void)registration;
    return false;
#else
    appendUnsupported(errors, "Windows Security Center registration is supported only on Windows hosts.");
    (void)registration;
    return false;
#endif
}

std::vector<SecurityCenterProduct> WindowsSecurityCenterBridge::enumerateProducts() const {
#ifdef _WIN32
    return {};
#else
    return {};
#endif
}

bool WindowsSecurityCenterBridge::registerProvider(const SecurityCenterRegistration &registration,
                                                   const std::string &provider, std::vector<std::string> *errors) const {
#ifdef _WIN32
    (void)registration;
    (void)provider;
    appendUnsupported(errors, "Windows Security Center integration is disabled in this build.");
    return false;
#else
    (void)registration;
    (void)provider;
    appendUnsupported(errors, "Windows Security Center registration is supported only on Windows hosts.");
    return false;
#endif
}

} // namespace antivirus
