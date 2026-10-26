#include "Management.h"

#include <exception>

int wmain(int argc, wchar_t** argv) {
    using namespace hyperv_xndis_filter::setup;
#ifdef HYPERVXNDISFILTER_UNINSTALL
    constexpr Action executable = Action::Uninstall;
#else
    constexpr Action executable = Action::Install;
#endif
    Options options;
    std::wstring error;
    if (!ParseOptions(executable, argc, argv, options, error)) {
        WriteText(L"ERROR: " + error + L"\n", true);
        return 2;
    }
    if (options.help) {
        WriteText(Usage(executable));
        return 0;
    }
    try {
        if (options.action == Action::Install && options.package.empty()) options.package = ExecutableDirectory();
        auto system = CreateWindowsSystem();
        return Execute(options, *system);
    } catch (const Error& failure) {
        WriteText(L"ERROR: " + failure.message + L"\n", true);
    } catch (const std::exception& failure) {
        const std::string text(failure.what());
        WriteText(L"ERROR: " + std::wstring(text.begin(), text.end()) + L"\n", true);
    }
    return 1;
}
