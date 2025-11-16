#include "AntivirusSuite/WindowsSecurityCenterBridge.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#define _WIN32_DCOM
#include <windows.h>
#include <combaseapi.h>
#include <wscapi.h>
#include <stringapiset.h>
#endif

namespace antivirus {

namespace {
#ifdef _WIN32
std::wstring widen(const std::string &value) {
    if (value.empty()) {
        return std::wstring();
    }
    const int length = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    std::wstring buffer(static_cast<std::size_t>(length > 0 ? length - 1 : 0), L'\0');
    if (length > 0) {
        MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, buffer.data(), length);
    }
    return buffer;
}

std::string narrow(const wchar_t *value) {
    if (value == nullptr || *value == L'\0') {
        return std::string();
    }
    const int length = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    std::string buffer(static_cast<std::size_t>(length > 0 ? length - 1 : 0), '\0');
    if (length > 0) {
        WideCharToMultiByte(CP_UTF8, 0, value, -1, buffer.data(), length, nullptr, nullptr);
    }
    return buffer;
}

std::string stateToString(WSC_SECURITY_PRODUCT_STATE state) {
    switch (state) {
    case WSC_SECURITY_PRODUCT_STATE_ON:
        return "on";
    case WSC_SECURITY_PRODUCT_STATE_OFF:
        return "off";
    case WSC_SECURITY_PRODUCT_STATE_SNOOZED:
        return "snoozed";
    default:
        return "unknown";
    }
}

std::string typeToString(WSC_SECURITY_PRODUCT_TYPE type) {
    switch (type) {
    case WSC_SECURITY_PRODUCT_TYPE_ANTIVIRUS:
        return "antivirus";
    case WSC_SECURITY_PRODUCT_TYPE_FIREWALL:
        return "firewall";
    case WSC_SECURITY_PRODUCT_TYPE_ANTISPYWARE:
        return "antispyware";
    default:
        return "other";
    }
}

std::string generateGuid(const std::string &seed) {
    if (!seed.empty()) {
        return seed;
    }
    const auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::ostringstream oss;
    oss << '{' << std::hex << std::uppercase << std::setfill('0');
    oss << std::setw(8) << static_cast<std::uint32_t>((now >> 32) & 0xffffffff);
    oss << '-' << std::setw(4) << static_cast<std::uint32_t>((now >> 16) & 0xffff);
    oss << '-' << std::setw(4) << static_cast<std::uint32_t>(now & 0xffff);
    oss << '-' << std::setw(4) << static_cast<std::uint32_t>((now >> 48) & 0xffff);
    oss << '-' << std::setw(12) << static_cast<std::uint64_t>(now & 0xffffffffffffULL);
    oss << '}';
    return oss.str();
}
#endif

} // namespace

bool WindowsSecurityCenterBridge::registerSuite(const SecurityCenterRegistration &registration,
                                                 std::vector<std::string> *errors) const {
#ifdef _WIN32
    SecurityCenterRegistration reg = registration;
    if (reg.reportingPath.empty()) {
        reg.reportingPath = reg.productPath;
    }
    reg.guid = generateGuid(reg.guid);
    bool success = true;
    if (reg.includeAntivirus) {
        success &= registerProvider(reg, "Av", errors);
    }
    if (reg.includeFirewall) {
        success &= registerProvider(reg, "Firewall", errors);
    }
    return success;
#else
    if (errors) {
        errors->push_back("Windows Security Center registration is supported only on Windows hosts.");
    }
    (void)registration;
    return false;
#endif
}

std::vector<SecurityCenterProduct> WindowsSecurityCenterBridge::enumerateProducts() const {
    std::vector<SecurityCenterProduct> products;
#ifdef _WIN32
    HRESULT initHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool needUninit = SUCCEEDED(initHr);
    if (initHr == RPC_E_CHANGED_MODE) {
        needUninit = false;
    }
    IWscProductList *productList = nullptr;
    HRESULT hr = CoCreateInstance(__uuidof(WscProductList), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&productList));
    if (FAILED(hr)) {
        if (needUninit) {
            CoUninitialize();
        }
        return products;
    }
    hr = productList->Initialize(WSC_SECURITY_PROVIDER_FIREWALL | WSC_SECURITY_PROVIDER_ANTIVIRUS);
    if (FAILED(hr)) {
        productList->Release();
        if (needUninit) {
            CoUninitialize();
        }
        return products;
    }
    LONG count = 0;
    productList->get_Count(&count);
    for (LONG i = 0; i < count; ++i) {
        IWscProduct *product = nullptr;
        if (FAILED(productList->get_Item(i, &product))) {
            continue;
        }
        SecurityCenterProduct entry;
        BSTR name = nullptr;
        if (SUCCEEDED(product->get_ProductName(&name))) {
            entry.name = narrow(name);
            SysFreeString(name);
        }
        WSC_SECURITY_PRODUCT_TYPE type;
        if (SUCCEEDED(product->get_ProductType(&type))) {
            entry.type = typeToString(type);
        }
        WSC_SECURITY_PRODUCT_STATE state;
        if (SUCCEEDED(product->get_ProductState(&state))) {
            entry.state = stateToString(state);
        }
        VARIANT_BOOL isDefault = VARIANT_FALSE;
        if (SUCCEEDED(product->get_ProductIsDefault(&isDefault))) {
            entry.isDefault = (isDefault == VARIANT_TRUE);
        }
        BSTR remediation = nullptr;
        if (SUCCEEDED(product->get_RemediationPath(&remediation))) {
            entry.path = narrow(remediation);
            SysFreeString(remediation);
        }
        entry.registered = true;
        products.push_back(entry);
        product->Release();
    }
    productList->Release();
    if (needUninit) {
        CoUninitialize();
    }
#endif
    return products;
}

bool WindowsSecurityCenterBridge::registerProvider(const SecurityCenterRegistration &registration,
                                                   const std::string &provider, std::vector<std::string> *errors) const {
#ifdef _WIN32
    std::string guid = (provider == "Firewall") ? generateGuid(std::string()) : registration.guid;
    const std::wstring keyPath = widen("SOFTWARE\\Microsoft\\Security Center\\Provider\\" + provider + "\\" + guid);
    HKEY key = nullptr;
    LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                                  &key, nullptr);
    if (result != ERROR_SUCCESS) {
        if (errors) {
            errors->push_back("Failed to open Security Center registry path for provider " + provider);
        }
        return false;
    }
    const std::wstring productName = widen(registration.productName);
    const std::wstring productPath = widen(registration.productPath);
    const std::wstring reportingPath = widen(registration.reportingPath);
    const DWORD state = 0x00001010;
    const DWORD timestamp = static_cast<DWORD>(std::time(nullptr));
    RegSetValueExW(key, L"DisplayName", 0, REG_SZ, reinterpret_cast<const BYTE *>(productName.c_str()),
                   static_cast<DWORD>((productName.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(key, L"PathToSignedProductExe", 0, REG_SZ, reinterpret_cast<const BYTE *>(productPath.c_str()),
                   static_cast<DWORD>((productPath.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(key, L"PathToSignedReportingExe", 0, REG_SZ, reinterpret_cast<const BYTE *>(reportingPath.c_str()),
                   static_cast<DWORD>((reportingPath.size() + 1) * sizeof(wchar_t)));
    RegSetValueExW(key, L"ProductState", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&state), sizeof(state));
    RegSetValueExW(key, L"Timestamp", 0, REG_DWORD, reinterpret_cast<const BYTE *>(&timestamp), sizeof(timestamp));
    RegCloseKey(key);
    return true;
#else
    (void)registration;
    (void)provider;
    (void)errors;
    return false;
#endif
}

} // namespace antivirus
