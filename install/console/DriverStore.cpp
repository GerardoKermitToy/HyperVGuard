#include "WindowsSupport.h"

#include <setupapi.h>
#include <newdev.h>
#include <algorithm>
#include <cwchar>
#include <iterator>

namespace hyperv_xndis_filter::setup {
namespace {

constexpr wchar_t kOriginalInf[] = L"HyperVXNdisFilter.inf";

std::filesystem::path InfDirectory() {
    std::vector<wchar_t> windows(32768);
    const UINT size = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    if (!size || size >= windows.size()) throw Error{L"Find Windows INF directory: " + ErrorCode(GetLastError())};
    return std::filesystem::path(std::wstring(windows.data(), size)) / L"INF";
}

bool HasProductName(const std::filesystem::path& published) {
    DWORD size = 0;
    SetupGetInfInformationW(published.c_str(), INFINFO_INF_NAME_IS_ABSOLUTE, nullptr, 0, &size);
    if (size < sizeof(SP_INF_INFORMATION) || size > 1024 * 1024) {
        throw Error{L"Read published INF information " + published.wstring() + L": " + ErrorCode(GetLastError())};
    }
    std::vector<BYTE> buffer(size);
    auto* information = reinterpret_cast<SP_INF_INFORMATION*>(buffer.data());
    if (!SetupGetInfInformationW(published.c_str(), INFINFO_INF_NAME_IS_ABSOLUTE,
                                information, size, nullptr) || information->InfCount != 1) {
        throw Error{L"Read published INF identity " + published.wstring() + L": " + ErrorCode(GetLastError())};
    }
    SP_ORIGINAL_FILE_INFO_W original{};
    original.cbSize = sizeof(original);
    if (!SetupQueryInfOriginalFileInformationW(information, 0, nullptr, &original)) {
        throw Error{L"Read original INF name " + published.wstring() + L": " + ErrorCode(GetLastError())};
    }
    if (std::find(std::begin(original.OriginalInfName), std::end(original.OriginalInfName), L'\0') ==
        std::end(original.OriginalInfName)) throw Error{L"Unterminated original INF name."};
    return _wcsicmp(original.OriginalInfName, kOriginalInf) == 0;
}

std::filesystem::path ProductStoreInf(const std::filesystem::path& published) {
    if (!HasProductName(published)) throw Error{L"Refusing to remove an unrelated OEM INF: " + published.wstring()};
    std::vector<wchar_t> store(32768);
    if (!SetupGetInfDriverStoreLocationW(published.c_str(), nullptr, nullptr, store.data(),
                                        static_cast<DWORD>(store.size()), nullptr)) {
        throw Error{L"Find Driver Store package for " + published.wstring() + L": " + ErrorCode(GetLastError())};
    }
    const std::filesystem::path path(store.data());
    if (_wcsicmp(path.filename().c_str(), kOriginalInf) != 0) {
        throw Error{L"Unexpected original INF in Driver Store: " + path.wstring()};
    }
    // Имя исходного INF — только предварительный отбор. Версия не ограничена,
    // но класс, все модели, GUID фильтра и служба обязаны принадлежать нам.
    ValidateRemovalInfFile(path);
    return path;
}

bool Missing(DWORD error) {
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

} // namespace

bool IsPublishedInfName(const std::wstring& name) {
    if (name.size() < 8 || _wcsnicmp(name.c_str(), L"oem", 3) != 0 ||
        _wcsicmp(name.c_str() + name.size() - 4, L".inf") != 0) return false;
    return std::all_of(name.begin() + 3, name.end() - 4, [](wchar_t c) { return c >= L'0' && c <= L'9'; });
}

std::vector<std::wstring> ReadWindowsDriverPackages() {
    const auto directory = InfDirectory();
    DWORD size = 0;
    SetupGetInfFileListW(directory.c_str(), INF_STYLE_WIN4, nullptr, 0, &size);
    if (!size || size > 16 * 1024 * 1024) throw Error{L"Enumerate published OEM INFs: " + ErrorCode(GetLastError())};
    std::vector<wchar_t> names(size);
    if (!SetupGetInfFileListW(directory.c_str(), INF_STYLE_WIN4, names.data(), size, &size)) {
        throw Error{L"Enumerate published OEM INFs: " + ErrorCode(GetLastError())};
    }
    if (!size || size > names.size() || names[size - 1] != L'\0') throw Error{L"Invalid published INF list."};
    names.resize(size);
    std::vector<std::wstring> packages;
    auto current = names.begin();
    while (current != names.end() && *current) {
        const auto end = std::find(current, names.end(), L'\0');
        if (end == names.end()) throw Error{L"Unterminated published INF name."};
        const std::wstring name(current, end);
        current = end + 1;
        if (!IsPublishedInfName(name)) continue;
        const auto published = directory / name;
        // Не считаем ошибку чтения чужого INF доказательством его принадлежности.
        // При неполной инвентаризации завершаемся ошибкой, а не ложным успехом.
        if (!HasProductName(published)) continue;
        ProductStoreInf(published);
        packages.push_back(name);
    }
    std::sort(packages.begin(), packages.end());
    return packages;
}

Change RemoveWindowsDriverPackage(const std::wstring& published_inf) {
    if (!IsPublishedInfName(published_inf)) throw Error{L"Expected a published OEM INF basename, not a path."};
    const auto published = InfDirectory() / published_inf;
    if (GetFileAttributesW(published.c_str()) == INVALID_FILE_ATTRIBUTES) {
        const DWORD error = GetLastError();
        if (Missing(error)) return Change::Complete;
        throw Error{L"Check published INF " + published_inf + L": " + ErrorCode(error)};
    }
    // Повторяем проверку непосредственно перед удалением; не доверяем старому
    // списку и не сканируем/удаляем FileRepository по маске имени каталога.
    const auto store = ProductStoreInf(published);
    BOOL reboot = FALSE;
    const BOOL previous = SetupSetNonInteractiveMode(TRUE);
    const BOOL removed = DiUninstallDriverW(nullptr, store.c_str(), 0, &reboot);
    const DWORD error = removed ? ERROR_SUCCESS : GetLastError();
    SetupSetNonInteractiveMode(previous);
    if (!removed) {
        if (reboot) WriteText(L"Windows requires a reboot even though package deletion failed. After reboot, rerun Uninstall.exe.\n");
        if (Missing(error)) return reboot ? Change::RebootRequired : Change::Complete;
        if (error == ERROR_INF_IN_USE_BY_DEVICES || error == ERROR_SHARING_VIOLATION ||
            error == ERROR_LOCK_VIOLATION || error == ERROR_SUCCESS_REBOOT_REQUIRED) {
            WriteText(L"Package " + published_inf + L" is still in use; reboot and rerun Uninstall.exe: " + ErrorCode(error) + L"\n");
            return Change::RebootRequired;
        }
        throw Error{L"Remove Driver Store package " + published_inf + L": " + ErrorCode(error)};
    }
    WriteText(L"Removed Driver Store package: " + published_inf + L"\n");
    return reboot ? Change::RebootRequired : Change::Complete;
}

} // namespace hyperv_xndis_filter::setup
