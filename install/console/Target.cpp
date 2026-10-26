#include "WindowsSupport.h"

#include <wbemidl.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <limits>

namespace hyperv_xndis_filter::setup {
namespace {

struct Variant {
    VARIANT value{};
    ~Variant() { VariantClear(&value); }
};

class Bstr {
public:
    explicit Bstr(const std::wstring& text) : value_(SysAllocString(text.c_str())) {
        if (!value_) throw std::bad_alloc();
    }
    ~Bstr() { SysFreeString(value_); }
    BSTR get() const { return value_; }
private:
    BSTR value_;
};

std::wstring Text(IWbemClassObject* object, const wchar_t* property) {
    Variant variant;
    Check(object->Get(property, 0, &variant.value, nullptr, nullptr), property);
    if (variant.value.vt != VT_BSTR || !variant.value.bstrVal) {
        throw Error{std::wstring(L"Missing WMI string: ") + property};
    }
    return {variant.value.bstrVal, SysStringLen(variant.value.bstrVal)};
}

uint64_t Number(IWbemClassObject* object, const wchar_t* property) {
    Variant variant;
    Check(object->Get(property, 0, &variant.value, nullptr, nullptr), property);
    const VARIANT& value = variant.value;
    if (value.vt == VT_UI4) return value.ulVal;
    if (value.vt == VT_I4 && value.lVal >= 0) return static_cast<uint64_t>(value.lVal);
    if (value.vt == VT_UI8) return value.ullVal;
    if (value.vt == VT_BSTR && value.bstrVal && SysStringLen(value.bstrVal)) {
        uint64_t result = 0;
        const std::wstring_view text(value.bstrVal, SysStringLen(value.bstrVal));
        for (const wchar_t c : text) {
            if (c < L'0' || c > L'9') throw Error{L"Invalid numeric WMI property."};
            const uint64_t digit = static_cast<uint64_t>(c - L'0');
            if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10) throw Error{L"Numeric WMI property overflow."};
            result = result * 10 + digit;
        }
        return result;
    }
    throw Error{std::wstring(L"Invalid numeric WMI property: ") + property};
}

bool Boolean(IWbemClassObject* object, const wchar_t* property) {
    Variant variant;
    Check(object->Get(property, 0, &variant.value, nullptr, nullptr), property);
    if (variant.value.vt != VT_BOOL) throw Error{std::wstring(L"Missing WMI Boolean: ") + property};
    return variant.value.boolVal != VARIANT_FALSE;
}

class Wmi {
public:
    explicit Wmi(const wchar_t* name_space) {
        ComPtr<IWbemLocator> locator;
        Check(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&locator)), L"Create WMI locator");
        Bstr resource(name_space);
        Check(locator->ConnectServer(resource.get(), nullptr, nullptr, nullptr,
                                     WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &services_), L"Connect to local WMI");
        Check(CoSetProxyBlanket(services_.Get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                               RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                               nullptr, EOAC_NONE), L"Set local WMI proxy security");
    }

    std::vector<ComPtr<IWbemClassObject>> Query(const std::wstring& query) {
        Bstr language(L"WQL"), statement(query);
        ComPtr<IEnumWbemClassObject> enumerator;
        Check(services_->ExecQuery(language.get(), statement.get(),
                                  WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                  nullptr, &enumerator), L"Read local WMI topology");
        std::vector<ComPtr<IWbemClassObject>> objects;
        for (;;) {
            ComPtr<IWbemClassObject> object;
            ULONG returned = 0;
            const HRESULT hr = enumerator->Next(15000, 1, &object, &returned);
            Check(hr, L"Enumerate local WMI topology");
            if (hr == WBEM_S_TIMEDOUT) throw Error{L"WMI enumeration timed out; no fallback is allowed."};
            if (returned == 0 && hr == WBEM_S_FALSE) break;
            if (returned != 1 || !object) throw Error{L"Unexpected WMI enumeration result."};
            if (objects.size() == 4096) throw Error{L"WMI topology exceeded the bounded enumeration limit."};
            objects.push_back(std::move(object));
        }
        return objects;
    }

    std::vector<ComPtr<IWbemClassObject>> Associated(IWbemClassObject* object, const wchar_t* restriction) {
        return Query(L"ASSOCIATORS OF {" + Text(object, L"__RELPATH") + L"} WHERE " + restriction);
    }
private:
    ComPtr<IWbemServices> services_;
};

} // namespace

Adapter ResolveWindowsTarget() {
    Wmi hyperv(L"ROOT\\virtualization\\v2");
    const auto switches = hyperv.Query(L"SELECT Name FROM Msvm_VirtualEthernetSwitch WHERE Name='C08CB7B8-9B3C-408E-8E30-5E16A3AEB444'");
    std::vector<GUID> identities;
    for (const auto& object : switches) {
        GUID guid{};
        if (!ParseGuid(Text(object.Get(), L"Name"), guid)) throw Error{L"Invalid Hyper-V switch identity."};
        identities.push_back(guid);
    }
    if (identities.size() != 1 || identities.front() != kDefaultSwitchId) {
        throw Error{L"The automatic Default Switch is missing or ambiguous."};
    }
    std::vector<HostPort> ports;
    // This class represents management-OS ports, never guest synthetic ports.
    for (const auto& object : hyperv.Query(L"SELECT * FROM Msvm_InternalEthernetPort")) {
        HostPort port;
        port.device_id = Text(object.Get(), L"DeviceID");
        for (const auto& endpoint : hyperv.Associated(object.Get(), L"ResultClass=Msvm_LANEndpoint")) {
            for (const auto& peer : hyperv.Associated(endpoint.Get(), L"AssocClass=Msvm_ActiveConnection ResultClass=Msvm_LANEndpoint")) {
                if (_wcsicmp(Text(peer.Get(), L"SystemCreationClassName").c_str(), L"Msvm_VirtualEthernetSwitch") != 0) continue;
                GUID switch_id{};
                if (!ParseGuid(Text(peer.Get(), L"SystemName"), switch_id)) throw Error{L"Invalid connected switch identity."};
                port.switches.push_back(switch_id);
            }
        }
        ports.push_back(std::move(port));
    }
    Wmi networking(L"ROOT\\StandardCimv2");
    std::vector<Adapter> adapters;
    for (const auto& object : networking.Query(L"SELECT Name,InterfaceGuid,NetLuid,Virtual,HardwareInterface,InterfaceType FROM MSFT_NetAdapter")) {
        Adapter adapter;
        if (!ParseGuid(Text(object.Get(), L"InterfaceGuid"), adapter.guid)) continue;
        adapter.luid = Number(object.Get(), L"NetLuid");
        adapter.name = Text(object.Get(), L"Name");
        adapter.is_virtual = Boolean(object.Get(), L"Virtual");
        adapter.hardware = Boolean(object.Get(), L"HardwareInterface");
        const uint64_t type = Number(object.Get(), L"InterfaceType");
        if (type > std::numeric_limits<uint32_t>::max()) throw Error{L"Invalid adapter interface type."};
        adapter.interface_type = static_cast<uint32_t>(type);
        adapters.push_back(std::move(adapter));
    }
    const Adapter target = SelectTarget(identities, ports, adapters);
    NET_LUID luid{};
    CheckWin32(ConvertInterfaceGuidToLuid(&target.guid, &luid), L"Convert target GUID to NET_LUID");
    GUID round_trip{};
    CheckWin32(ConvertInterfaceLuidToGuid(&luid, &round_trip), L"Verify target NET_LUID identity");
    if (luid.Value != target.luid || round_trip != target.guid) throw Error{L"Target GUID/NET_LUID changed during discovery."};
    return target;
}

} // namespace hyperv_xndis_filter::setup
