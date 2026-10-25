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
    std::puts("PASS LWF target gate, copy bounds and send/receive ownership routes");
    return 0;
}
