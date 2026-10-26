#include "../../install/notify/BindingPolicy.h"

#include <cstdio>
#include <cwchar>
#include <initializer_list>
#include <utility>
#include <vector>

using Microsoft::WRL::ComPtr;
using namespace hyperv_xndis_filter;

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

template<typename Interface>
class FakeCom : public Interface {
public:
    virtual ~FakeCom() = default;
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (iid != IID_IUnknown && iid != __uuidof(Interface)) return E_NOINTERFACE;
        *out = static_cast<Interface*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        const ULONG remaining = --refs_;
        if (!remaining) delete this;
        return remaining;
    }
private:
    ULONG refs_ = 1;
};

template<typename T, typename... Args>
ComPtr<T> Make(Args&&... args) {
    ComPtr<T> result;
    result.Attach(new T(std::forward<Args>(args)...));
    return result;
}

class Component final : public FakeCom<INetCfgComponent> {
public:
    Component(const GUID& cls, const GUID& instance) : component_class(cls), instance_guid(instance) {}
    GUID component_class{}, instance_guid{};
    HRESULT class_result = S_OK, instance_result = S_OK;
    unsigned id_calls = 0, class_calls = 0;
    HRESULT STDMETHODCALLTYPE GetDisplayName(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE SetDisplayName(LPCWSTR) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetHelpText(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetId(LPWSTR* out) override {
        ++id_calls;
        if (out) *out = nullptr;
        // The user-reported failure, despite a valid output pointer and usable
        // class/instance GUIDs. Inspection must not depend on this string query.
        return E_POINTER;
    }
    HRESULT STDMETHODCALLTYPE GetCharacteristics(LPDWORD) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetInstanceGuid(GUID* out) override {
        if (!out) return E_POINTER;
        *out = instance_guid;
        return instance_result;
    }
    HRESULT STDMETHODCALLTYPE GetPnpDevNodeId(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetClassGuid(GUID* out) override {
        ++class_calls;
        if (!out) return E_POINTER;
        *out = component_class;
        return class_result;
    }
    HRESULT STDMETHODCALLTYPE GetBindName(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDeviceStatus(ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE OpenParamKey(HKEY*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE RaisePropertyUi(HWND, DWORD, IUnknown*) override { return E_NOTIMPL; }
};

class ComponentEnumerator final : public FakeCom<IEnumNetCfgComponent> {
public:
    std::vector<ComPtr<INetCfgComponent>> components;
    HRESULT next_result = S_OK;
    bool bad_count = false, false_with_object = false;
    HRESULT STDMETHODCALLTYPE Next(ULONG count, INetCfgComponent** out, ULONG* fetched) override {
        if (count != 1 || !out || !fetched) return E_POINTER;
        *out = nullptr;
        *fetched = 0;
        if (next_result != S_OK) return next_result;
        if (position_ == components.size()) return S_FALSE;
        const HRESULT hr = components[position_++].CopyTo(out);
        if (FAILED(hr)) return hr;
        *fetched = bad_count ? 0u : 1u;
        return false_with_object ? S_FALSE : S_OK;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { position_ = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumNetCfgComponent**) override { return E_NOTIMPL; }
private:
    size_t position_ = 0;
};

class Configuration final : public FakeCom<INetCfg> {
public:
    std::vector<ComPtr<INetCfgComponent>> components;
    HRESULT enum_result = S_OK, next_result = S_OK;
    bool null_enumerator = false, bad_count = false, false_with_object = false;
    unsigned mutations = 0, class_queries = 0;
    GUID expected_class = GUID_DEVCLASS_NET;
    HRESULT STDMETHODCALLTYPE Initialize(PVOID) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Uninitialize() override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Apply() override { ++mutations; return E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE Cancel() override { ++mutations; return E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE EnumComponents(const GUID* cls, IEnumNetCfgComponent** out) override {
        if (!cls || !out) return E_POINTER;
        *out = nullptr;
        ++class_queries;
        if (*cls != expected_class) return E_INVALIDARG;
        if (enum_result != S_OK) return enum_result;
        if (null_enumerator) return S_OK;
        auto enumerator = Make<ComponentEnumerator>();
        enumerator->components = components;
        enumerator->next_result = next_result;
        enumerator->bad_count = bad_count;
        enumerator->false_with_object = false_with_object;
        *out = enumerator.Detach();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE FindComponent(LPCWSTR, INetCfgComponent**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE QueryNetCfgClass(const GUID*, REFIID, void**) override { return E_NOTIMPL; }
};

class Edge final : public FakeCom<INetCfgBindingInterface> {
public:
    Edge(INetCfgComponent* first, INetCfgComponent* second) : upper(first), lower(second) {}
    ComPtr<INetCfgComponent> upper, lower;
    HRESULT upper_result = S_OK, lower_result = S_OK;
    HRESULT STDMETHODCALLTYPE GetName(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetUpperComponent(INetCfgComponent** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (upper_result != S_OK) return upper_result;
        return upper.CopyTo(out);
    }
    HRESULT STDMETHODCALLTYPE GetLowerComponent(INetCfgComponent** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (lower_result != S_OK) return lower_result;
        return lower.CopyTo(out);
    }
};

class Enumerator final : public FakeCom<IEnumNetCfgBindingInterface> {
public:
    std::vector<ComPtr<INetCfgBindingInterface>> edges;
    HRESULT next_result = S_OK;
    bool bad_count = false, false_with_object = false;
    HRESULT STDMETHODCALLTYPE Next(ULONG count, INetCfgBindingInterface** out, ULONG* fetched) override {
        // Be deliberately strict about the fetched pointer. The shared code
        // passes it explicitly rather than relying on optional celt=1 behavior.
        if (count != 1 || !out || !fetched) return E_POINTER;
        *out = nullptr;
        *fetched = 0;
        if (next_result != S_OK) return next_result;
        if (position_ == edges.size()) return S_FALSE;
        const HRESULT hr = edges[position_++].CopyTo(out);
        if (FAILED(hr)) return hr;
        *fetched = bad_count ? 0u : 1u;
        return false_with_object ? S_FALSE : S_OK;
    }
    HRESULT STDMETHODCALLTYPE Skip(ULONG) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Reset() override { position_ = 0; return S_OK; }
    HRESULT STDMETHODCALLTYPE Clone(IEnumNetCfgBindingInterface**) override { return E_NOTIMPL; }
private:
    size_t position_ = 0;
};

class Path final : public FakeCom<INetCfgBindingPath> {
public:
    std::vector<ComPtr<INetCfgBindingInterface>> edges;
    HRESULT enum_result = S_OK, next_result = S_OK;
    bool null_enumerator = false, bad_count = false, false_with_object = false;
    unsigned enable_calls = 0;
    HRESULT STDMETHODCALLTYPE IsSamePathAs(INetCfgBindingPath*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE IsSubPathOf(INetCfgBindingPath*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE IsEnabled() override { return S_FALSE; }
    HRESULT STDMETHODCALLTYPE Enable(BOOL) override { ++enable_calls; return E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE GetPathToken(LPWSTR*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetOwner(INetCfgComponent**) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE GetDepth(ULONG*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE EnumBindingInterfaces(IEnumNetCfgBindingInterface** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (enum_result != S_OK) return enum_result;
        if (null_enumerator) return S_OK;
        auto enumerator = Make<Enumerator>();
        enumerator->edges = edges;
        enumerator->next_result = next_result;
        enumerator->bad_count = bad_count;
        enumerator->false_with_object = false_with_object;
        *out = enumerator.Detach();
        return S_OK;
    }
};

const GUID target_guid = {0x9eb6ca05, 0x3905, 0x4420, {0xa3, 0x4f, 0x4f, 0xa0, 0x9d, 0xcc, 0x6a, 0x2d}};
const GUID other_guid = {1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};

ComPtr<Path> Chain(std::initializer_list<INetCfgComponent*> components) {
    auto path = Make<Path>();
    INetCfgComponent* previous = nullptr;
    for (auto component : components) {
        if (previous) path->edges.push_back(Make<Edge>(previous, component));
        previous = component;
    }
    return path;
}

int main() {
    auto filter = Make<Component>(GUID_DEVCLASS_NETSERVICE, kFilterInstanceId);
    auto target = Make<Component>(GUID_DEVCLASS_NET, target_guid);
    auto foreign = Make<Component>(GUID_DEVCLASS_NET, other_guid);
    const GUID service_guid{3, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
    const GUID protocol_guid{4, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11}};
    auto service = Make<Component>(GUID_DEVCLASS_NETSERVICE, service_guid);
    auto protocol = Make<Component>(GUID_DEVCLASS_NETTRANS, protocol_guid);
    auto config = Make<Configuration>();
    config->components = {target, foreign};
    target->class_result = foreign->class_result = E_POINTER;
    std::vector<GUID> adapter_instances;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == S_OK);
    CHECK(adapter_instances == std::vector<GUID>({target_guid, other_guid}));
    CHECK(target->class_calls == 0 && foreign->class_calls == 0 && config->class_queries == 1);
    BindingPathIdentity identity;

    // Reject the same package GUID under any other component ID, without
    // querying display names/IDs or mutating the previous installation.
    auto services = Make<Configuration>();
    services->expected_class = GUID_DEVCLASS_NETSERVICE;
    CHECK(CheckFilterIdentityAvailable(nullptr) == E_POINTER);
    CHECK(CheckFilterIdentityAvailable(services.Get()) == S_OK);
    services->components = {service};
    CHECK(CheckFilterIdentityAvailable(services.Get()) == S_OK);
    services->components.push_back(filter);
    CHECK(CheckFilterIdentityAvailable(services.Get()) == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS));
    CHECK(filter->id_calls == 0 && service->id_calls == 0);
    services->components = {service};
    service->instance_guid = GUID_NULL;
    CHECK(CheckFilterIdentityAvailable(services.Get()) == E_UNEXPECTED);
    service->instance_guid = service_guid;
    for (const HRESULT result : {E_POINTER, E_ACCESSDENIED, S_FALSE}) {
        const HRESULT expected = FAILED(result) ? result : E_UNEXPECTED;
        services->enum_result = result;
        CHECK(CheckFilterIdentityAvailable(services.Get()) == expected);
        services->enum_result = S_OK;
        services->next_result = result;
        CHECK(CheckFilterIdentityAvailable(services.Get()) == (result == S_FALSE ? S_OK : expected));
        services->next_result = S_OK;
        service->instance_result = result;
        CHECK(CheckFilterIdentityAvailable(services.Get()) == expected);
        service->instance_result = S_OK;
    }
    services->bad_count = true;
    CHECK(CheckFilterIdentityAvailable(services.Get()) == E_UNEXPECTED);
    services->bad_count = false;
    services->false_with_object = true;
    CHECK(CheckFilterIdentityAvailable(services.Get()) == E_UNEXPECTED);
    services->false_with_object = false;
    services->null_enumerator = true;
    CHECK(CheckFilterIdentityAvailable(services.Get()) == E_UNEXPECTED);
    services->null_enumerator = false;
    services->components.assign(4096, service);
    CHECK(CheckFilterIdentityAvailable(services.Get()) == S_OK);
    services->components.push_back(service);
    CHECK(CheckFilterIdentityAvailable(services.Get()) == E_UNEXPECTED);
    CHECK(services->mutations == 0);

    // Reproduce the failing API independently, then run the production inspector
    // on exactly these components. No real NetCfg object or registry is used.
    LPWSTR text = nullptr;
    CHECK(filter->GetId(&text) == E_POINTER && text == nullptr);
    CHECK(target->GetId(&text) == E_POINTER && text == nullptr);
    auto path = Chain({filter.Get(), target.Get()});
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
    CHECK(identity.owns_path && identity.adapters == 1 && identity.adapter == target_guid);
    CHECK(filter->id_calls == 1 && target->id_calls == 1);
    CHECK(BindingDecision(NCN_ENABLE, identity.owns_path, true, identity.adapters, identity.adapter == target_guid) == S_OK);
    CHECK(BindingDecision(NCN_ADD, identity.owns_path, false, identity.adapters, true) == NETCFG_S_DISABLE_QUERY);

    // Intermediate components can appear on two adjacent interfaces. A filter
    // may be below a protocol; ownership is its NetService instance GUID.
    for (const auto components : {
             std::vector<INetCfgComponent*>{filter.Get(), service.Get(), target.Get()},
             std::vector<INetCfgComponent*>{protocol.Get(), filter.Get(), target.Get()}}) {
        auto chained = Make<Path>();
        for (size_t i = 1; i < components.size(); ++i) chained->edges.push_back(Make<Edge>(components[i - 1], components[i]));
        CHECK(InspectBindingPath(chained.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
        CHECK(identity.owns_path && identity.adapters == 1 && identity.adapter == target_guid);
        CHECK(chained->enable_calls == 0);
    }
    CHECK(service->id_calls == 0 && protocol->id_calls == 0);
    CHECK(target->class_calls == 0);
    target->class_result = foreign->class_result = S_OK;

    auto foreign_path = Chain({filter.Get(), foreign.Get()});
    CHECK(InspectBindingPath(foreign_path.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
    CHECK(identity.owns_path && identity.adapters == 1 && identity.adapter == other_guid);
    CHECK(BindingDecision(NCN_ENABLE, identity.owns_path, true, identity.adapters, identity.adapter == target_guid) == NETCFG_S_DISABLE_QUERY);

    auto unrelated = Chain({service.Get(), target.Get()});
    CHECK(InspectBindingPath(unrelated.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK && !identity.owns_path);
    CHECK(BindingDecision(NCN_ENABLE, identity.owns_path, false, identity.adapters, false) == S_OK);
    auto wrong_class = Make<Component>(GUID_DEVCLASS_NETTRANS, kFilterInstanceId);
    auto impostor = Chain({wrong_class.Get(), target.Get()});
    CHECK(InspectBindingPath(impostor.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK && !identity.owns_path);

    auto no_adapter = Chain({filter.Get(), protocol.Get()});
    CHECK(InspectBindingPath(no_adapter.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
    CHECK(identity.owns_path && identity.adapters == 0);
    CHECK(BindingDecision(NCN_ENABLE, identity.owns_path, true, identity.adapters, false) == NETCFG_S_DISABLE_QUERY);
    auto two_adapters = Chain({filter.Get(), foreign.Get(), target.Get()});
    CHECK(InspectBindingPath(two_adapters.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
    CHECK(identity.owns_path && identity.adapters == 2 && identity.adapter == target_guid);
    CHECK(BindingDecision(NCN_ENABLE, identity.owns_path, true, identity.adapters, true) == NETCFG_S_DISABLE_QUERY);

    // The class-scoped catalog replaces unreliable adapter GetClassGuid calls.
    // Actual instance-GUID failures still fail closed, without partial identity.
    for (const HRESULT result : {E_POINTER, E_ACCESSDENIED, S_FALSE}) {
        const HRESULT expected = FAILED(result) ? result : E_UNEXPECTED;
        target->class_result = result;
        CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
        CHECK(identity.owns_path && identity.adapters == 1 && identity.adapter == target_guid);
        target->class_result = S_OK;
        target->instance_result = result;
        CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == expected);
        CHECK(!identity.owns_path && identity.adapters == 0);
        target->instance_result = S_OK;
    }
    target->instance_guid = GUID_NULL;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == E_UNEXPECTED);
    target->instance_guid = target_guid;
    CHECK(InspectBindingPath(nullptr, kFilterInstanceId, adapter_instances, identity) == E_POINTER);
    CHECK(InspectBindingPath(path.Get(), GUID_NULL, adapter_instances, identity) == E_INVALIDARG);
    path->null_enumerator = true;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == E_UNEXPECTED);
    path->null_enumerator = false;
    path->enum_result = E_POINTER;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == E_POINTER);
    path->enum_result = S_OK;
    path->next_result = E_ACCESSDENIED;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == E_ACCESSDENIED);
    path->next_result = S_OK;
    path->bad_count = true;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == E_UNEXPECTED);
    path->bad_count = false;
    path->false_with_object = true;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity) == E_UNEXPECTED);
    path->false_with_object = false;
    auto null_endpoint = Chain({filter.Get(), target.Get()});
    auto edge = Make<Edge>(filter.Get(), nullptr);
    null_endpoint->edges = {edge};
    CHECK(InspectBindingPath(null_endpoint.Get(), kFilterInstanceId, adapter_instances, identity) == E_UNEXPECTED);
    edge->lower_result = E_POINTER;
    CHECK(InspectBindingPath(null_endpoint.Get(), kFilterInstanceId, adapter_instances, identity) == E_POINTER);

    auto bounded = Make<Path>();
    for (unsigned i = 0; i != 63; ++i) bounded->edges.push_back(Make<Edge>(filter.Get(), service.Get()));
    bounded->edges.push_back(Make<Edge>(service.Get(), target.Get()));
    CHECK(InspectBindingPath(bounded.Get(), kFilterInstanceId, adapter_instances, identity) == S_OK);
    CHECK(identity.owns_path && identity.adapters == 1);
    bounded->edges.push_back(Make<Edge>(service.Get(), target.Get()));
    CHECK(InspectBindingPath(bounded.Get(), kFilterInstanceId, adapter_instances, identity) == E_UNEXPECTED);
    CHECK(!identity.owns_path && identity.adapters == 0);
    CHECK(filter->id_calls == 1 && target->id_calls == 1 && foreign->id_calls == 0 && service->id_calls == 0);
    CHECK(path->enable_calls == 0 && foreign_path->enable_calls == 0 && unrelated->enable_calls == 0);
    const std::vector<GUID> no_adapters;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, no_adapters, identity) == S_OK);
    CHECK(identity.owns_path && identity.adapters == 1 && identity.adapter == target_guid);
    target->class_result = E_POINTER;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, no_adapters, identity) == E_POINTER);
    CHECK(!identity.owns_path && identity.adapters == 0);
    target->class_result = S_OK;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, {kFilterInstanceId}, identity) == E_INVALIDARG);
    BindingPathDiagnostic diagnostic;
    filter->class_result = E_POINTER;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity, &diagnostic) == E_POINTER);
    CHECK(std::wcscmp(diagnostic.operation, L"upper.GetClassGuid") == 0 && diagnostic.interface_index == 0);
    filter->class_result = S_OK;
    target->instance_result = E_ACCESSDENIED;
    CHECK(InspectBindingPath(path.Get(), kFilterInstanceId, adapter_instances, identity, &diagnostic) == E_ACCESSDENIED);
    CHECK(std::wcscmp(diagnostic.operation, L"lower.GetInstanceGuid") == 0);
    target->instance_result = S_OK;

    // A failed inventory read never publishes a partial adapter allowlist.
    CHECK(ReadBindingAdapters(nullptr, adapter_instances) == E_POINTER && adapter_instances.empty());
    config->components = {target, target};
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_UNEXPECTED && adapter_instances.empty());
    config->components = {target, foreign};
    foreign->instance_guid = GUID_NULL;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_UNEXPECTED && adapter_instances.empty());
    foreign->instance_guid = other_guid;
    foreign->instance_result = E_POINTER;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_POINTER && adapter_instances.empty());
    foreign->instance_result = S_OK;
    config->bad_count = true;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_UNEXPECTED && adapter_instances.empty());
    config->bad_count = false;
    config->false_with_object = true;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_UNEXPECTED && adapter_instances.empty());
    config->false_with_object = false;
    config->null_enumerator = true;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_UNEXPECTED && adapter_instances.empty());
    config->null_enumerator = false;
    for (const HRESULT result : {E_POINTER, E_ACCESSDENIED, S_FALSE}) {
        config->enum_result = result;
        CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == (FAILED(result) ? result : E_UNEXPECTED));
        CHECK(adapter_instances.empty());
    }
    config->enum_result = S_OK;
    config->next_result = E_ACCESSDENIED;
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_ACCESSDENIED && adapter_instances.empty());
    config->next_result = S_OK;
    config->components.clear();
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == S_OK && adapter_instances.empty());
    for (unsigned i = 0; i != 4096; ++i) {
        GUID guid{10 + i, 0, 0, {}};
        config->components.push_back(Make<Component>(GUID_DEVCLASS_NET, guid));
    }
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == S_OK && adapter_instances.size() == 4096);
    config->components.push_back(target);
    CHECK(ReadBindingAdapters(config.Get(), adapter_instances) == E_UNEXPECTED && adapter_instances.empty());
    CHECK(config->mutations == 0);
    std::puts("PASS: adapter GetClassGuid/E_POINTER regression, class-scoped inventory, fail-closed COM errors and bounds; fake COM only.");
    return 0;
}
