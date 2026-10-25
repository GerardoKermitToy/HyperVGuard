#include "../../driver/shim/lwf_contract.h"
#include <climits>
#include <cstdio>
#include <initializer_list>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

int main() {
    CHECK(!HvTargetMatches(0, 0));
    CHECK(!HvTargetMatches(0, 123));
    CHECK(!HvTargetMatches(123, 0));
    CHECK(!HvTargetMatches(123, 124));
    CHECK(HvTargetMatches(123, 123));
    CHECK(HvTargetMatches(ULLONG_MAX, ULLONG_MAX));

    unsigned char first = 0, second = 0;
    int active = 0;
    // Attach starts paused. Repeated transitions must not double-count a device.
    active += HvSetFilterRunning(&first, 0);
    CHECK(active == 0 && first == 0);
    active += HvSetFilterRunning(&first, 1);
    CHECK(active == 1 && first == 1);
    active += HvSetFilterRunning(&first, 1);
    CHECK(active == 1);
    active += HvSetFilterRunning(&second, 1);
    CHECK(active == 2 && second == 1);
    // Pause excludes the module immediately, before any pending NBLs finish.
    active += HvSetFilterRunning(&first, 0);
    CHECK(active == 1 && first == 0 && second == 1);
    active += HvSetFilterRunning(&first, 0);
    CHECK(active == 1);
    active += HvSetFilterRunning(&second, 0);
    CHECK(active == 0);
    for (unsigned i = 0; i < 1000; ++i) {
        active += HvSetFilterRunning(&first, 1);
        CHECK(active == 1);
        active += HvSetFilterRunning(&first, 0);
        CHECK(active == 0);
    }

    CHECK(HvCopyFits(0, 0, 1));
    CHECK(HvCopyFits(HV_MAX_NB - 1, 0, HV_MAX_COPY_BYTES));
    CHECK(!HvCopyFits(HV_MAX_NB, 0, 1));
    CHECK(!HvCopyFits(0, 0, 0));
    CHECK(!HvCopyFits(0, 0, HV_MAX_COPY_BYTES + 1));
    CHECK(!HvCopyFits(0, HV_MAX_COPY_BYTES, 1));
    CHECK(!HvCopyFits(0, UINT_MAX, 1));
    CHECK(!HvCopyFits(0, 1, UINT_MAX));
    CHECK(HvCopyFits(0, HV_MAX_COPY_BYTES - 1, 1));
    CHECK(HvCopyPoolFits(0, HV_MAX_COPY_POOL_BYTES));
    CHECK(!HvCopyPoolFits(HV_MAX_COPY_POOL_BYTES, 1));
    CHECK(!HvCopyPoolFits(UINT_MAX, 1));
    CHECK(!HvCopyPoolFits(1, UINT_MAX));
    CHECK(!HvCopyPoolFits(0, 0));

    for (int copied : {0, 1}) {
        CHECK(HvFinishRoute(HV_DIRECTION_SEND, copied, 1) == HvRouteSend);
        CHECK(HvFinishRoute(HV_DIRECTION_SEND, copied, 0) == HvRouteCompleteSend);
        CHECK(HvFinishRoute(HV_DIRECTION_RECEIVE, copied, 1) == HvRouteIndicateReceive);
    }
    CHECK(HvFinishRoute(HV_DIRECTION_RECEIVE, 0, 0) == HvRouteReturnReceive);
    CHECK(HvFinishRoute(HV_DIRECTION_RECEIVE, 1, 0) == HvRouteFreeReceive);
    std::puts("PASS LWF target gate, running-device transitions, copy bounds and ownership routes");
    return 0;
}
