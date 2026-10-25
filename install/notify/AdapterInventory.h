#pragma once
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <memory>
#include "BindingPath.h"

namespace hyperv_guard {

// NetCfg omits dynamic NonPnpNetworkInterface adapters from EnumComponents(Net).
// NETIO supplies their independent GUID/NET_LUID identity, without friendly names.
inline HRESULT ReadBindingAdapterInventory(INetCfg* config, std::vector<GUID>& adapters) {
    adapters.clear();
    std::vector<GUID> inspected;
    HRESULT hr = ReadBindingAdapters(config, inspected);
    if (FAILED(hr)) return hr;
    MIB_IF_TABLE2* raw = nullptr;
    const DWORD result = GetIfTable2(&raw);
    const auto release = [](MIB_IF_TABLE2* table) { if (table) FreeMibTable(table); };
    std::unique_ptr<MIB_IF_TABLE2, decltype(release)> table(raw, release);
    if (result != NO_ERROR) return HRESULT_FROM_WIN32(result);
    if (!table || table->NumEntries > 4096) return E_UNEXPECTED;
    for (ULONG index = 0; index != table->NumEntries; ++index) {
        const auto& entry = table->Table[index];
        if (entry.InterfaceGuid == GUID_NULL || !entry.InterfaceLuid.Value) return E_UNEXPECTED;
        if (std::find(inspected.begin(), inspected.end(), entry.InterfaceGuid) != inspected.end()) continue;
        if (inspected.size() == 4096) return E_UNEXPECTED;
        inspected.push_back(entry.InterfaceGuid);
    }
    adapters = std::move(inspected);
    return S_OK;
}

} // namespace hyperv_guard
