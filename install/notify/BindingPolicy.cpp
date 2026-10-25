#include "BindingPolicy.h"
#include "NetCfgTrace.h"

namespace hyperv_guard {

static bool ReadTarget(GUID& guid) {
    DWORD version = 0, size = sizeof(version);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, L"ConfigVersion", RRF_RT_REG_DWORD,
                     nullptr, &version, &size) != ERROR_SUCCESS || version != 2) return false;
    DWORD allowed = 0;
    size = sizeof(allowed);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, L"AllowBindings", RRF_RT_REG_DWORD,
                     nullptr, &allowed, &size) != ERROR_SUCCESS || allowed != 1) return false;
    ULONGLONG luid = 0;
    size = sizeof(luid);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, L"TargetNetLuid", RRF_RT_REG_QWORD,
                     nullptr, &luid, &size) != ERROR_SUCCESS || luid == 0) return false;
    wchar_t text[39]{};
    size = sizeof(text);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, kConfigKey, L"TargetInterfaceGuid", RRF_RT_REG_SZ,
                     nullptr, text, &size) != ERROR_SUCCESS || size != sizeof(text) ||
        text[38] != L'\0') return false;
    return SUCCEEDED(CLSIDFromString(text, &guid)) && guid != GUID_NULL;
}

HRESULT EvaluateBindingPath(DWORD flags, INetCfgBindingPath* path, const std::vector<GUID>& adapters) {
    TraceNetCfg("QueryBindingPath", S_OK, flags);
    if (path == nullptr) return E_POINTER;
    if ((flags & (NCN_DISABLE | NCN_REMOVE)) != 0 || (flags & (NCN_ENABLE | NCN_ADD)) == 0) return S_OK;
    GUID target{};
    const bool configured = ReadTarget(target);
    BindingPathIdentity identity;
    const HRESULT hr = InspectBindingPath(path, kFilterInstanceId, adapters, identity);
    TraceNetCfg("InspectBindingPath", hr, flags);
    if (FAILED(hr)) return hr;
    const HRESULT decision = BindingDecision(flags, identity.owns_path, configured, identity.adapters, identity.adapter == target);
    TraceNetCfg("BindingDecision", decision, flags);
    return decision;
}
}
