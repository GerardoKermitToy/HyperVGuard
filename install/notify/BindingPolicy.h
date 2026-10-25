#pragma once
#include <windows.h>
#include <netcfgx.h>
#include <netcfgn.h>
#include "BindingPath.h"

namespace hyperv_guard {
inline constexpr wchar_t kConfigKey[] = L"SOFTWARE\\HyperVGuard\\Lwf";
inline constexpr wchar_t kComponentId[] = L"hyperv_guard";
// Package identity from INF NetCfgInstanceId, never a machine adapter GUID.
inline constexpr GUID kFilterInstanceId = {0x6e76ead1, 0x7bcb, 0x49c4, {0x95, 0x47, 0xd3, 0xe6, 0xb3, 0x48, 0x8f, 0x71}};
// Independent of the filter's NetCfgInstanceId.
inline constexpr GUID kNotifyClsid = {0x1cfed41e, 0x4579, 0x42cf, {0x96, 0x2c, 0x2a, 0x7e, 0x04, 0xc6, 0xdb, 0xc8}};

inline HRESULT BindingDecision(DWORD flags, bool owns_path, bool configured,
                               unsigned adapters, bool target_matches) {
    if (!owns_path || (flags & (NCN_REMOVE | NCN_DISABLE)) != 0 ||
        (flags & (NCN_ADD | NCN_ENABLE)) == 0) return S_OK;
    return configured && adapters == 1 && target_matches ? S_OK : NETCFG_S_DISABLE_QUERY;
}
HRESULT EvaluateBindingPath(DWORD flags, INetCfgBindingPath* path, const std::vector<GUID>& adapters);
}
