#include "WindowsSupport.h"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>

using namespace hyperv_guard::setup;

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 && argc != 4) return 2;
    try {
        const std::filesystem::path source(argv[1]);
        const std::filesystem::path fixture = std::filesystem::path(argv[2]) / L"setup-inf-fixture.inf";
        ValidateInfFile(source);
        std::ifstream stream(source, std::ios::binary);
        const std::string original((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        if (original.empty()) throw std::runtime_error("empty source INF");
        const std::vector<std::pair<std::string, std::string>> mutations = {
            {"Class=NetService", "Class=Net"},
            {"CatalogFile=HyperVGuard.cat", "CatalogFile=Unrelated.cat"},
            {"0.3.1.0", "0.3.0.0"},
            {"6E76EAD1-7BCB-49C4-9547-D3E6B3488F71", "00000001-0002-0003-0405-060708090A0B"},
            {"Install, hyperv_guard", "Install, another_component"},
            {"FilterClass,,\"custom\"", "FilterClass,,\"ms_switch_filter\""},
            {"FilterType,0x00010001,2", "FilterType,0x00010001,1"},
            {"FilterRunType,0x00010001,2", "FilterRunType,0x00010001,1"},
            {"1CFED41E-4579-42CF-962C-2A7E04C6DBC8", "00000001-0002-0003-0405-060708090A0B"},
            {"ComponentDll,,\"%13%\\HyperVGuardNotify.dll\"", "ComponentDll,,\"other.dll\""},
            {"LowerRange,,\"nolower\"", "LowerRange,,\"vmnetextension\""},
            {"FilterMediaTypes,,\"ethernet\"", "FilterMediaTypes,,\"wan\""},
            {"HKR,Ndi,FilterClass,,\"custom\"", "HKR,Ndi,FilterClass,,\"custom\"\nHKR,Ndi,FilterClass,,\"custom\""}
        };
        for (const auto& [from, to] : mutations) {
            std::string text = original;
            const auto position = text.find(from);
            if (position == std::string::npos) throw std::runtime_error("mutation fixture not found");
            text.replace(position, from.size(), to);
            {
                std::ofstream output(fixture, std::ios::binary | std::ios::trunc);
                output << text;
                if (!output) throw std::runtime_error("fixture write failed");
            }
            bool rejected = false;
            try { ValidateInfFile(fixture); }
            catch (const Error&) { rejected = true; }
            if (!rejected) throw std::runtime_error("unsafe INF accepted");
        }
        std::filesystem::remove(fixture);
        std::printf("PASS: real INF and %zu rejected package-policy mutations (SetupAPI parsing only).\n", mutations.size());
        if (argc == 4) {
            // Optional offline signature/membership validation of an existing
            // signed package; no WMI, NetCfg, COM registration or driver access.
            auto files = LockAndVerifyPackage(std::filesystem::path(argv[3]));
            if (files.size() != 4) return 1;
            std::puts("PASS: existing signed package trust and SHA-256 catalog membership; read-only handles only.");
        }
        return 0;
    } catch (const Error& error) {
        WriteText(L"FAIL: " + error.message + L"\n", true);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
    }
    return 1;
}
