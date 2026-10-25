#include "WindowsSupport.h"

#include <setupapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <map>

namespace hyperv_guard::setup {
namespace {

class Inf {
public:
    explicit Inf(const std::filesystem::path& path) {
        UINT line = 0;
        handle_ = SetupOpenInfFileW(path.c_str(), nullptr, INF_STYLE_WIN4, &line);
        if (handle_ == INVALID_HANDLE_VALUE) {
            throw Error{L"Open package INF (line " + std::to_wstring(line) + L"): " + ErrorCode(GetLastError())};
        }
    }
    ~Inf() { SetupCloseInfFile(handle_); }

    std::wstring Field(const wchar_t* section, const wchar_t* key, DWORD field) {
        INFCONTEXT context{};
        if (!SetupFindFirstLineW(handle_, section, key, &context)) {
            throw Error{std::wstring(L"Missing INF entry: ") + section + L"/" + key};
        }
        return Get(context, field);
    }

    void Require(const wchar_t* section, const wchar_t* key, DWORD field, const wchar_t* expected) {
        if (_wcsicmp(Field(section, key, field).c_str(), expected) != 0) {
            throw Error{std::wstring(L"Not the target-restricted HyperVGuard LWF package: ") + section + L"/" + key};
        }
    }

    void RequireModel() {
        INFCONTEXT context{};
        if (!SetupFindFirstLineW(handle_, L"Models.NTamd64.10.0...25341", nullptr, &context) ||
            _wcsicmp(Get(context, 1).c_str(), L"Install") != 0 ||
            _wcsicmp(Get(context, 2).c_str(), L"hyperv_guard") != 0 ||
            SetupFindNextLine(&context, &context)) {
            throw Error{L"Expected exactly the target-restricted HyperVGuard LWF model."};
        }
    }

    void RequireDriverStoreFiles() {
        Require(L"DestinationDirs", L"DriverFiles", 1, L"13");
        Require(L"DestinationDirs", L"NotifyFiles", 1, L"13");
        DWORD size = 0;
        SetupGetTargetPathW(handle_, nullptr, L"NotifyFiles", nullptr, 0, &size);
        if (!size || size > 32768) throw Error{L"Invalid notify DLL destination."};
        std::vector<wchar_t> directory(size);
        if (!SetupGetTargetPathW(handle_, nullptr, L"NotifyFiles", directory.data(), size, nullptr)) {
            throw Error{L"Read notify DLL destination: " + ErrorCode(GetLastError())};
        }
        // SetupAPI expands DIRID 13 to a temporary destination (normally '.')
        // until the INF is staged. Compare both fields in the same parse context.
        const auto dll = std::filesystem::path(directory.data()) / L"HyperVGuardNotify.dll";
        RequireNdi(L"Ndi", L"ComponentDll", dll.c_str());
    }

    void RequireNdi(const wchar_t* subkey, const wchar_t* name, const wchar_t* expected) {
        INFCONTEXT context{};
        if (!SetupFindFirstLineW(handle_, L"Ndi", nullptr, &context)) throw Error{L"Missing INF Ndi section."};
        unsigned matches = 0;
        do {
            if (_wcsicmp(Get(context, 1).c_str(), L"HKR") != 0 ||
                _wcsicmp(Get(context, 2).c_str(), subkey) != 0 ||
                _wcsicmp(Get(context, 3).c_str(), name) != 0) continue;
            ++matches;
            const auto actual = Get(context, 5);
            if (_wcsicmp(actual.c_str(), expected) != 0) {
                throw Error{std::wstring(L"Unexpected INF binding policy: ") + name + L" = " + actual};
            }
        } while (SetupFindNextLine(&context, &context));
        if (matches != 1) throw Error{std::wstring(L"Missing or ambiguous INF binding policy: ") + name};
    }
private:
    static std::wstring Get(INFCONTEXT& context, DWORD field) {
        DWORD size = 0;
        SetupGetStringFieldW(&context, field, nullptr, 0, &size);
        if (!size || size > 32768) throw Error{L"Invalid INF field length."};
        std::vector<wchar_t> text(size);
        if (!SetupGetStringFieldW(&context, field, text.data(), size, nullptr)) {
            throw Error{L"Read INF field: " + ErrorCode(GetLastError())};
        }
        return text.data();
    }
    HINF handle_ = INVALID_HANDLE_VALUE;
};

void VerifyTrust(WINTRUST_DATA& data, const std::wstring& subject) {
    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE | WTD_DISABLE_MD2_MD4;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    const LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &data);
    if (status != ERROR_SUCCESS) {
        throw Error{subject + L" signature/catalog is not trusted: " + ErrorCode(static_cast<DWORD>(status)) +
                    L". Configure certificate trust yourself; this program never imports certificates or changes security policy."};
    }
}

void VerifyFileSignature(const std::filesystem::path& path, HANDLE handle) {
    WINTRUST_FILE_INFO file{};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    file.hFile = handle;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    VerifyTrust(data, path.filename().wstring());
}

class CatalogAdmin {
public:
    CatalogAdmin() {
        if (!CryptCATAdminAcquireContext2(&value, nullptr, L"SHA256", nullptr, 0)) {
            throw Error{L"Acquire SHA-256 catalog context: " + ErrorCode(GetLastError())};
        }
    }
    ~CatalogAdmin() { CryptCATAdminReleaseContext(value, 0); }
    HCATADMIN value = nullptr;
};

void VerifyCatalogMember(CatalogAdmin& admin, const std::filesystem::path& catalog,
                         const std::filesystem::path& member, HANDLE handle) {
    DWORD size = 0;
    if (!CryptCATAdminCalcHashFromFileHandle2(admin.value, handle, &size, nullptr, 0) || size != 32) {
        throw Error{L"Get catalog member hash size: " + ErrorCode(GetLastError())};
    }
    std::vector<BYTE> hash(size);
    if (!CryptCATAdminCalcHashFromFileHandle2(admin.value, handle, &size, hash.data(), 0)) {
        throw Error{L"Hash catalog member: " + ErrorCode(GetLastError())};
    }
    constexpr wchar_t digits[] = L"0123456789ABCDEF";
    std::wstring tag;
    for (const BYTE byte : hash) {
        tag += digits[byte >> 4];
        tag += digits[byte & 15];
    }
    WINTRUST_CATALOG_INFO info{};
    info.cbStruct = sizeof(info);
    info.pcwszCatalogFilePath = catalog.c_str();
    info.pcwszMemberTag = tag.c_str();
    info.pcwszMemberFilePath = member.c_str();
    info.hMemberFile = handle;
    info.pbCalculatedFileHash = hash.data();
    info.cbCalculatedFileHash = size;
    info.hCatAdmin = admin.value;
    WINTRUST_DATA data{};
    data.dwUnionChoice = WTD_CHOICE_CATALOG;
    data.pCatalog = &info;
    VerifyTrust(data, member.filename().wstring());
}

} // namespace

void ValidateInfFile(const std::filesystem::path& path) {
    Inf inf(path);
    inf.Require(L"Version", L"Class", 1, L"NetService");
    inf.Require(L"Version", L"ClassGUID", 1, L"{4D36E974-E325-11CE-BFC1-08002BE10318}");
    inf.Require(L"Version", L"CatalogFile", 1, L"HyperVGuard.cat");
    inf.Require(L"Version", L"DriverVer", 2, kPackageVersion);
    inf.RequireModel();
    inf.Require(L"Install", L"NetCfgInstanceId", 1, L"{6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}");
    inf.RequireNdi(L"Ndi", L"FilterClass", L"custom");
    inf.RequireNdi(L"Ndi", L"FilterType", L"2");
    inf.RequireNdi(L"Ndi", L"FilterRunType", L"2");
    inf.RequireNdi(L"Ndi", L"ClsID", L"{1CFED41E-4579-42CF-962C-2A7E04C6DBC8}");
    inf.RequireDriverStoreFiles();
    inf.RequireNdi(L"Ndi\\Interfaces", L"FilterMediaTypes", L"ethernet");
    inf.RequireNdi(L"Ndi\\Interfaces", L"UpperRange", L"noupper");
    inf.RequireNdi(L"Ndi\\Interfaces", L"LowerRange", L"nolower");
}

std::vector<Handle> LockAndVerifyPackage(const std::filesystem::path& package) {
    constexpr std::array<const wchar_t*, 4> names = {
        L"HyperVGuard.inf", L"HyperVGuard.sys", L"HyperVGuardNotify.dll", L"HyperVGuard.cat"
    };
    std::vector<Handle> files;
    for (const auto name : names) {
        const auto path = package / name;
        // Keep read-only, non-delete-sharing handles alive through installation,
        // so the files checked here cannot be replaced before SetupCopyOEMInf.
        Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr));
        if (file.get() == INVALID_HANDLE_VALUE) throw Error{L"Open package file " + path.wstring() + L": " + ErrorCode(GetLastError())};
        BY_HANDLE_FILE_INFORMATION information{};
        if (!GetFileInformationByHandle(file.get(), &information) ||
            (information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) throw Error{L"A package input is not a regular file."};
        files.push_back(std::move(file));
    }
    ValidateInfFile(package / names[0]);
    for (size_t i = 1; i < names.size(); ++i) VerifyFileSignature(package / names[i], files[i].get());
    CatalogAdmin admin;
    for (size_t i = 0; i < names.size() - 1; ++i) {
        VerifyCatalogMember(admin, package / names[3], package / names[i], files[i].get());
    }
    return files;
}

} // namespace hyperv_guard::setup
