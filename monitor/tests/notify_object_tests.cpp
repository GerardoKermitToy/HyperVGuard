#include "../../install/notify/BindingPolicy.h"
#include <cstdio>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)
int wmain(int argc, wchar_t** argv) {
    CHECK(argc == 2);
    // Load as a normal user-mode DLL only. Never register COM or call NetCfg.
    const HMODULE module = LoadLibraryW(argv[1]);
    CHECK(module != nullptr);
    using GetClass = HRESULT (__stdcall*)(REFCLSID, REFIID, void**);
    using CanUnload = HRESULT (__stdcall*)();
    const auto getClass = reinterpret_cast<GetClass>(GetProcAddress(module, "DllGetClassObject"));
    const auto canUnload = reinterpret_cast<CanUnload>(GetProcAddress(module, "DllCanUnloadNow"));
    CHECK(getClass != nullptr && canUnload != nullptr);
    CHECK(GetProcAddress(module, "DllRegisterServer") != nullptr);
    CHECK(GetProcAddress(module, "DllUnregisterServer") != nullptr);
    CHECK(canUnload() == S_OK);
    IClassFactory* factory = nullptr;
    CHECK(getClass(GUID_NULL, IID_IClassFactory, reinterpret_cast<void**>(&factory)) == CLASS_E_CLASSNOTAVAILABLE);
    CHECK(factory == nullptr);
    CHECK(getClass(hyperv_xndis_filter::kNotifyClsid, IID_IClassFactory, nullptr) == E_POINTER);
    CHECK(getClass(hyperv_xndis_filter::kNotifyClsid, IID_IClassFactory, reinterpret_cast<void**>(&factory)) == S_OK);
    CHECK(canUnload() == S_FALSE);
    INetCfgComponentControl* control = nullptr;
    CHECK(factory->CreateInstance(nullptr, IID_INetCfgComponentControl, reinterpret_cast<void**>(&control)) == S_OK);
    CHECK(control->Initialize(nullptr, nullptr, TRUE) == E_POINTER);
    CHECK(control->ApplyRegistryChanges() == S_OK);
    CHECK(control->ApplyPnpChanges(nullptr) == S_OK);
    CHECK(control->CancelChanges() == S_OK);
    INetCfgComponentNotifyBinding* notify = nullptr;
    CHECK(control->QueryInterface(IID_INetCfgComponentNotifyBinding, reinterpret_cast<void**>(&notify)) == S_OK);
    CHECK(notify->QueryBindingPath(NCN_ENABLE, nullptr) == E_POINTER);
    CHECK(notify->NotifyBindingPath(NCN_REMOVE, nullptr) == S_OK);
    notify->Release(); control->Release(); factory->Release();
    CHECK(canUnload() == S_OK);
    CHECK(FreeLibrary(module));
    std::puts("PASS notify DLL exports, COM interfaces and lifetime (no registration or network access)");
    return 0;
}
