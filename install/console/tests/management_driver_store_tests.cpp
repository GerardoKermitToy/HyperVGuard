#include "WindowsSupport.h"

#include <cstdio>
#include <fstream>
#include <iterator>
#include <stdexcept>

using namespace hyperv_xndis_filter::setup;
namespace {

void Require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::string Replace(std::string text, const std::string& from, const std::string& to) {
    size_t position = 0, count = 0;
    while ((position = text.find(from, position)) != std::string::npos) {
        text.replace(position, from.size(), to);
        position += to.size();
        ++count;
    }
    Require(count != 0, "fixture marker not found");
    return text;
}

void Write(const std::filesystem::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
    Require(static_cast<bool>(output), "fixture write failed");
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return 2;
    try {
        std::ifstream input(argv[1], std::ios::binary);
        const std::string original((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        Require(!original.empty(), "empty source INF");
        const auto fixture = std::filesystem::path(argv[2]) / L"removal-identity-fixture.inf";
        std::vector<std::string> accepted{
            original,
            Replace(original, "0.3.2.0", "0.3.0.0"),
            Replace(original, "0.3.2.0", "0.2.1.0"),
            Replace(original, "DriverVer=10/27/2026,0.3.2.0", ""),
            Replace(original, "%13%", "%12%"),
            Replace(original, "NTamd64.10.0...25341", "NTamd64"),
            Replace(Replace(original, "%Provider%=Models,NTamd64.10.0...25341", "%Provider%=Models"),
                    "[Models.NTamd64.10.0...25341]", "[Models]"),
            Replace(original, "%Provider%=Models,NTamd64.10.0...25341", "%Provider%=Models,NTamd64.10.0...25341,NTamd64") +
                "\n[Models.NTamd64]\n%Description%=Install, hyperv_xndis_filter\n",
            Replace(original, "Install", "OwnInstall"),
        };
        for (const auto* suffix : {".NT", ".NTamd64", ".NTx86", ".NTia64", ".NTarm", ".NTarm64"}) {
            const auto install = std::string("Install") + suffix;
            const auto owned = Replace(Replace(original, "[Install]", "[" + install + "]"),
                                       "[Install.Services]", "[" + install + ".Services]");
            accepted.push_back(owned);
            accepted.push_back(original + "\n[" + install + "]\nNetCfgInstanceId={6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}\n[" +
                               install + ".Services]\nAddService=HyperVXNdisFilter,,Service\n");
        }
        for (const auto& text : accepted) {
            Write(fixture, text);
            ValidateRemovalInfFile(fixture);
        }
        std::vector<std::string> rejected{
            Replace(original, "Class=NetService", "Class=Net"),
            Replace(original, "4D36E974-E325-11CE-BFC1-08002BE10318", "4D36E972-E325-11CE-BFC1-08002BE10318"),
            Replace(original, "CatalogFile=HyperVXNdisFilter.cat", "CatalogFile=Unrelated.cat"),
            Replace(original, "hyperv_xndis_filter", "another_component"),
            Replace(original, "6E76EAD1-7BCB-49C4-9547-D3E6B3488F71", "00000001-0002-0003-0405-060708090A0B"),
            Replace(original, "AddService=HyperVXNdisFilter,,Service", "AddService=OtherFilter,,Service"),
            Replace(original, "AddService=HyperVXNdisFilter,,Service", "AddService=HyperVXNdisFilter,,OtherService"),
            Replace(original, "ServiceType=1", "ServiceType=2"),
            Replace(original, "ServiceBinary=%13%\\HyperVXNdisFilter.sys", "ServiceBinary=%13%\\OtherFilter.sys"),
            Replace(original, "ServiceBinary=%13%\\HyperVXNdisFilter.sys", "ServiceBinary=%13%\\OtherHyperVXNdisFilter.sys"),
            Replace(original, "%Description%=Install, hyperv_xndis_filter", "%Description%=Install, hyperv_xndis_filter, another_component"),
            Replace(original, "%Description%=Install, hyperv_xndis_filter", "%Description%=Install, hyperv_xndis_filter\n%Description%=Install, another_component"),
            Replace(original, "%Provider%=Models,NTamd64.10.0...25341", "%Provider%=Models,NTamd64.10.0...25341\nOther=OtherModels,NTamd64") +
                "\n[OtherModels.NTamd64]\nOther=Install, another_component\n",
            Replace(original, "%Provider%=Models,NTamd64.10.0...25341", "%Provider%=Models,NTamd64.10.0...25341,NTamd64") +
                "\n[Models.NTamd64]\nOther=Install, another_component\n",
            Replace(original, "AddService=HyperVXNdisFilter,,Service", "AddService=HyperVXNdisFilter,,Service\nAddService=OtherFilter,,Service"),
            Replace(original, "AddService=HyperVXNdisFilter,,Service", "AddService=HyperVXNdisFilter,,Service\nInclude=other.inf\nNeeds=Other.Services"),
            Replace(original, "Class=NetService", "Class=NetService\nClass=Net"),
            Replace(original, "ServiceBinary=%13%\\HyperVXNdisFilter.sys", "ServiceBinary=%13%\\HyperVXNdisFilter.sys\nServiceBinary=%13%\\OtherFilter.sys"),
            Replace(original, "NetCfgInstanceId=", "NetCfgInstanceId=\"{6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}\"\nNetCfgInstanceId="),
            Replace(original, "[Install.Services]", "[Wrong.Services]"),
            Replace(original, "[Models.NTamd64.10.0...25341]", "[MissingModel]"),
            original + "\n[Install.NTamd64]\nNetCfgInstanceId={00000001-0002-0003-0405-060708090A0B}\n"
                "[Install.NTamd64.Services]\nAddService=OtherFilter,,OtherService\n"
                "[OtherService]\nServiceType=1\nServiceBinary=%13%\\OtherFilter.sys\n",
        };
        for (const auto* suffix : {".NT", ".NTamd64", ".NTx86", ".NTia64", ".NTarm", ".NTarm64"}) {
            const auto install = std::string("Install") + suffix;
            rejected.push_back(original + "\n[" + install + "]\nNetCfgInstanceId={6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}\n[" +
                               install + ".Services]\nAddService=OtherFilter,,Service\n");
            rejected.push_back(original + "\n[" + install + ".Services]\nAddService=OtherFilter,,Service\n");
        }
        for (const auto& text : rejected) {
            Write(fixture, text);
            bool refused = false;
            try { ValidateRemovalInfFile(fixture); }
            catch (const Error&) { refused = true; }
            Require(refused, "unrelated or ambiguous package accepted for removal");
        }
        std::filesystem::remove(fixture);
        for (const auto* name : {L"oem0.inf", L"oem123.inf", L"OEM12.INF"}) {
            Require(IsPublishedInfName(name), "valid OEM basename rejected");
        }
        for (const std::wstring name : {std::wstring{}, std::wstring(L"oem.inf"), std::wstring(L"HyperVXNdisFilter.inf"),
                std::wstring(L"oem-1.inf"), std::wstring(L"oem1.inf.bak"), std::wstring(L"../oem1.inf"),
                std::wstring(L"C:\\Windows\\INF\\oem1.inf"), std::wstring(L"oem1.inf\\x"), std::wstring(L"oem1\0.inf", 9)}) {
            Require(!IsPublishedInfName(name), "path or malformed OEM basename accepted");
        }
        std::printf("PASS: %zu owned/old-version INF fixtures, %zu rejected mixed/ambiguous fixtures, strict OEM names; no system inventory or driver deletion.\n",
                    accepted.size(), rejected.size());
        return 0;
    } catch (const Error& error) {
        WriteText(L"FAIL: " + error.message + L"\n", true);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL: %s\n", error.what());
    }
    return 1;
}
