#pragma once
#include <windows.h>
#include <objbase.h>
#include <cguid.h>
#include <netcfgx.h>
#include <devguid.h>
#include <wrl/client.h>
#include <algorithm>
#include <vector>
#include <utility>

namespace hyperv_xndis_filter {

struct BindingPathIdentity {
    bool owns_path = false;
    unsigned adapters = 0;
    GUID adapter{};
};

struct BindingPathDiagnostic {
    const wchar_t* operation = L"Validate binding path arguments";
    unsigned interface_index = 0;
};

// The class-scoped enumerator is authoritative. NetCfg can return E_POINTER
// from GetClassGuid even for a valid Net adapter returned by this enumerator.
inline HRESULT ReadBindingAdapters(INetCfg* config, std::vector<GUID>& adapters) {
    using Microsoft::WRL::ComPtr;
    adapters.clear();
    if (!config) return E_POINTER;
    ComPtr<IEnumNetCfgComponent> enumerator;
    HRESULT hr = config->EnumComponents(&GUID_DEVCLASS_NET, &enumerator);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    if (!enumerator) return E_UNEXPECTED;
    std::vector<GUID> inspected;
    for (;;) {
        ComPtr<INetCfgComponent> component;
        ULONG fetched = 0;
        hr = enumerator->Next(1, &component, &fetched);
        if (hr == S_FALSE) {
            if (fetched != 0 || component) return E_UNEXPECTED;
            adapters = std::move(inspected);
            return S_OK;
        }
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        if (fetched != 1 || !component || inspected.size() == 4096) return E_UNEXPECTED;
        GUID instance{};
        hr = component->GetInstanceGuid(&instance);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        if (instance == GUID_NULL || std::find(inspected.begin(), inspected.end(), instance) != inspected.end()) return E_UNEXPECTED;
        inspected.push_back(instance);
    }
}

inline HRESULT InspectBindingComponent(INetCfgComponent* component, const GUID& filter,
                                       bool lower, const std::vector<GUID>& adapters,
                                       BindingPathIdentity& identity, BindingPathDiagnostic& diagnostic) {
    diagnostic.operation = lower ? L"lower.GetInstanceGuid" : L"upper.GetClassGuid";
    if (component == nullptr) return E_UNEXPECTED;
    GUID instance{};
    HRESULT hr = S_OK;
    if (lower) {
        hr = component->GetInstanceGuid(&instance);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        if (instance == GUID_NULL) return E_UNEXPECTED;
        if (std::find(adapters.begin(), adapters.end(), instance) != adapters.end()) {
            ++identity.adapters;
            identity.adapter = instance;
            return S_OK;
        }
    }
    diagnostic.operation = lower ? L"lower.GetClassGuid" : L"upper.GetClassGuid";
    GUID component_class{};
    hr = component->GetClassGuid(&component_class);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    // Non-PnP vEthernet interfaces can be absent from EnumComponents(Net).
    // A successful direct class query independently proves their adapter class.
    if (lower && component_class == GUID_DEVCLASS_NET) {
        ++identity.adapters;
        identity.adapter = instance;
        return S_OK;
    }
    if (component_class == GUID_DEVCLASS_NETSERVICE) {
        if (!lower) {
            diagnostic.operation = L"upper.GetInstanceGuid";
            hr = component->GetInstanceGuid(&instance);
            if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
            if (instance == GUID_NULL) return E_UNEXPECTED;
        }
        if (instance == filter) identity.owns_path = true;
    }
    return S_OK;
}

// Shared by installer and notify DLL. The adapter inventory must come from
// ReadBindingAdapters in the same NetCfg session. No binding mutation occurs.
inline HRESULT InspectBindingPath(INetCfgBindingPath* path, const GUID& filter,
                                  const std::vector<GUID>& adapters, BindingPathIdentity& identity,
                                  BindingPathDiagnostic* failure = nullptr) {
    using Microsoft::WRL::ComPtr;
    identity = {};
    BindingPathDiagnostic local;
    auto& diagnostic = failure ? *failure : local;
    diagnostic = {};
    if (path == nullptr) return E_POINTER;
    if (filter == GUID_NULL || std::find(adapters.begin(), adapters.end(), filter) != adapters.end()) return E_INVALIDARG;
    ComPtr<IEnumNetCfgBindingInterface> interfaces;
    diagnostic.operation = L"EnumBindingInterfaces";
    HRESULT hr = path->EnumBindingInterfaces(&interfaces);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    if (!interfaces) return E_UNEXPECTED;
    BindingPathIdentity inspected;
    for (unsigned steps = 0; ; ++steps) {
        diagnostic.interface_index = steps;
        diagnostic.operation = L"IEnumNetCfgBindingInterface.Next";
        ComPtr<INetCfgBindingInterface> binding;
        ULONG fetched = 0;
        hr = interfaces->Next(1, &binding, &fetched);
        if (hr == S_FALSE) {
            if (fetched != 0 || binding) return E_UNEXPECTED;
            identity = inspected;
            diagnostic.operation = L"";
            return S_OK;
        }
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        if (fetched != 1 || !binding || steps == 64) return E_UNEXPECTED;
        ComPtr<INetCfgComponent> upper, lower;
        diagnostic.operation = L"GetUpperComponent";
        hr = binding->GetUpperComponent(&upper);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        diagnostic.operation = L"GetLowerComponent";
        hr = binding->GetLowerComponent(&lower);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        hr = InspectBindingComponent(upper.Get(), filter, false, adapters, inspected, diagnostic);
        if (FAILED(hr)) return hr;
        // Count adapters only on lower endpoints, not twice per interface chain.
        hr = InspectBindingComponent(lower.Get(), filter, true, adapters, inspected, diagnostic);
        if (FAILED(hr)) return hr;
    }
}

} // namespace hyperv_xndis_filter
