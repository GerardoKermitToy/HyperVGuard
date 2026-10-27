#include "WindowsSupport.h"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>

using namespace hyperv_xndis_filter::setup;

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
            {"CatalogFile=HyperVXNdisFilter.cat", "CatalogFile=Unrelated.cat"},
            {"ServiceBinary=%13%\\HyperVXNdisFilter.sys", "ServiceBinary=%13%\\OtherFilter.sys"},
            {"ServiceBinary=%13%\\HyperVXNdisFilter.sys", "ServiceBinary=%13%\\Unrelated.sys"},
            {"HyperVXNdisFilter.sys,,,2", "OtherFilter.sys,,,2"},
            {"HyperVXNdisFilter.sys,,,2", "HyperVXNdisFilter.sys,,,2\nUnrelated.sys,,,2"},
            {"HyperVXNdisFilter.sys=1", "OtherFilter.sys=1"},
            {"DriverFiles=13", "DriverFiles=12"},
            {"0.3.3.0", "0.3.2.0"},
            {"0.3.3.0", "0.3.0.0"},
            {"6E76EAD1-7BCB-49C4-9547-D3E6B3488F71", "00000001-0002-0003-0405-060708090A0B"},
            {"Install, hyperv_xndis_filter", "Install, another_component"},
            {"AddService=HyperVXNdisFilter,,Service", "AddService=OtherFilter,,Service"},
            {"AddService=HyperVXNdisFilter,,Service", "AddService=HyperVXNdisFilter,,OtherService"},
            {"DelService=HyperVXNdisFilter,0x200", "DelService=OtherFilter,0x200"},
            {"HKR,Ndi,Service,,\"HyperVXNdisFilter\"", "HKR,Ndi,Service,,\"OtherFilter\""},
            {"HKR,Ndi,CoServices,0x00010000,\"HyperVXNdisFilter\"", "HKR,Ndi,CoServices,0x00010000,\"OtherFilter\""},
            {"FilterClass,,\"custom\"", "FilterClass,,\"ms_switch_filter\""},
            {"FilterType,0x00010001,2", "FilterType,0x00010001,1"},
            {"FilterRunType,0x00010001,2", "FilterRunType,0x00010001,1"},
            {"1CFED41E-4579-42CF-962C-2A7E04C6DBC8", "00000001-0002-0003-0405-060708090A0B"},
            {"ComponentDll,,\"%13%\\HyperVXNdisFilterNotify.dll\"", "ComponentDll,,\"other.dll\""},
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
