#include "../../install/notify/BindingPolicy.h"
#include <cstdio>
#include <initializer_list>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)
int main() {
    using hyperv_guard::BindingDecision;
    CHECK(NETCFG_S_DISABLE_QUERY == static_cast<HRESULT>(0x0004a022));
    for (DWORD flags : {DWORD(NCN_ADD), DWORD(NCN_ENABLE), DWORD(NCN_ADD | NCN_ENABLE),
                        DWORD(NCN_UPDATE | NCN_ENABLE)}) {
        CHECK(BindingDecision(flags, true, true, 1, true) == S_OK);
        CHECK(BindingDecision(flags, true, false, 1, true) == NETCFG_S_DISABLE_QUERY);
        CHECK(BindingDecision(flags, true, true, 1, false) == NETCFG_S_DISABLE_QUERY);
        CHECK(BindingDecision(flags, true, true, 0, true) == NETCFG_S_DISABLE_QUERY);
        CHECK(BindingDecision(flags, true, true, 2, true) == NETCFG_S_DISABLE_QUERY);
        // Unrelated components must not be restricted by our notification object.
        CHECK(BindingDecision(flags, false, false, 0, false) == S_OK);
    }
    for (DWORD flags : {DWORD(NCN_DISABLE), DWORD(NCN_REMOVE), DWORD(NCN_DISABLE | NCN_UPDATE),
                        DWORD(NCN_UPDATE), DWORD(0)}) {
        CHECK(BindingDecision(flags, true, false, 0, false) == S_OK);
    }
    std::puts("PASS own-component NetCfg add/enable veto, unarmed/missing/foreign target, disable/remove");
    return 0;
}
