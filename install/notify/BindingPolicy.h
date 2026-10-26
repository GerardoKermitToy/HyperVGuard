#pragma once
#include <windows.h>
#include <netcfgx.h>
#include <netcfgn.h>
#include "BindingPath.h"

namespace hyperv_xndis_filter {
inline constexpr wchar_t kConfigKey[] = L"SOFTWARE\\HyperVXNdisFilter\\Lwf";
inline constexpr wchar_t kComponentId[] = L"hyperv_xndis_filter";
// Package identity from INF NetCfgInstanceId, never a machine adapter GUID.
inline constexpr GUID kFilterInstanceId = {0x6e76ead1, 0x7bcb, 0x49c4, {0x95, 0x47, 0xd3, 0xe6, 0xb3, 0x48, 0x8f, 0x71}};
// Independent of the filter's NetCfgInstanceId.
inline constexpr GUID kNotifyClsid = {0x1cfed41e, 0x4579, 0x42cf, {0x96, 0x2c, 0x2a, 0x7e, 0x04, 0xc6, 0xdb, 0xc8}};

// A renamed package must not coexist with the same filter instance under a
// different component ID. Inspection is read-only and never depends on names.
inline HRESULT CheckFilterIdentityAvailable(INetCfg* config) {
    using Microsoft::WRL::ComPtr;
    if (!config) return E_POINTER;
    ComPtr<IEnumNetCfgComponent> enumerator;
    HRESULT hr = config->EnumComponents(&GUID_DEVCLASS_NETSERVICE, &enumerator);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    if (!enumerator) return E_UNEXPECTED;
    for (unsigned count = 0;; ++count) {
        ComPtr<INetCfgComponent> component;
        ULONG fetched = 0;
        hr = enumerator->Next(1, &component, &fetched);
        if (hr == S_FALSE) return fetched == 0 && !component ? S_OK : E_UNEXPECTED;
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        if (fetched != 1 || !component || count == 4096) return E_UNEXPECTED;
        GUID instance{};
        hr = component->GetInstanceGuid(&instance);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        if (instance == GUID_NULL) return E_UNEXPECTED;
        if (instance == kFilterInstanceId) return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    }
}

inline HRESULT BindingDecision(DWORD flags, bool owns_path, bool configured,
                               unsigned adapters, bool target_matches) {
    if (!owns_path || (flags & (NCN_REMOVE | NCN_DISABLE)) != 0 ||
        (flags & (NCN_ADD | NCN_ENABLE)) == 0) return S_OK;
    return configured && adapters == 1 && target_matches ? S_OK : NETCFG_S_DISABLE_QUERY;
}
HRESULT EvaluateBindingPath(DWORD flags, INetCfgBindingPath* path, const std::vector<GUID>& adapters);
}
