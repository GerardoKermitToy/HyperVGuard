#include "../../driver/shim/lwf_contract.h"
#include <climits>
#include <cstdio>
#include <initializer_list>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return 1; } } while (false)

int main() {
    CHECK(HvIoctlInputEmpty(0));
    CHECK(!HvIoctlInputEmpty(1));
    CHECK(!HvIoctlInputEmpty(~0ul));

    unsigned char session_closed = 0;
    CHECK(HvSessionGateClose(&session_closed) == 1 && session_closed == 1);
    // Cleanup and shutdown share one rundown close; only a new create reopens it.
    CHECK(HvSessionGateClose(&session_closed) == 0 && session_closed == 1);
    CHECK(HvSessionGateReopen(&session_closed) == 1 && session_closed == 0);
    CHECK(HvSessionGateReopen(&session_closed) == 0 && session_closed == 0);

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

    CHECK(HV_DEFAULT_DECISION_TIMEOUT_MS == 8000);
    CHECK(HV_DEFAULT_FAIL_CLOSED == 1);
    CHECK(HV_PENDING_CHECK_MS == 1000);
    CHECK(HV_CACHE_CHECK_MS == 10000);
    unsigned char pending_timer = 0, cache_timer = 0;
    CHECK(HvSetMaintenanceArmed(&pending_timer, 0) == 0);
    CHECK(HvSetMaintenanceArmed(&cache_timer, 0) == 0);
    CHECK(HvSetMaintenanceArmed(&pending_timer, 1) == 1);
    CHECK(pending_timer == 1 && cache_timer == 0);
    CHECK(HvSetMaintenanceArmed(&cache_timer, 1) == 1);
    // Packet/candidate updates must not reset an already running timer.
    for (unsigned i = 0; i < 1000; ++i) {
        CHECK(HvSetMaintenanceArmed(&pending_timer, 1) == 0);
        CHECK(HvSetMaintenanceArmed(&cache_timer, 1) == 0);
    }
    CHECK(HvSetMaintenanceArmed(&pending_timer, 0) == -1);
    CHECK(pending_timer == 0 && cache_timer == 1);
    CHECK(HvSetMaintenanceArmed(&pending_timer, 0) == 0);
    CHECK(HvSetMaintenanceArmed(&cache_timer, 0) == -1);
    CHECK(HvSetMaintenanceArmed(&cache_timer, 0) == 0);
    CHECK(HvSetMaintenanceArmed(&pending_timer, 1) == 1);
    CHECK(HvSetMaintenanceArmed(&pending_timer, 0) == -1);

    // Ownership references have arithmetic bounds, not admission quotas.
    unsigned long long value = 99;
    CHECK(HvAddU64(2048, 1, &value) && value == 2049);
    CHECK(HvAddU64(ULLONG_MAX - 1, 1, &value) && value == ULLONG_MAX);
    CHECK(!HvAddU64(value, 1, &value) && value == ULLONG_MAX);
    CHECK(HvSubtractU64(value, 1, &value) && value == ULLONG_MAX - 1);
    value = 99;
    CHECK(!HvMultiplyU64(ULLONG_MAX, 2, &value) && value == 99);
    CHECK(HvMultiplyU64(0, ULLONG_MAX, &value) && value == 0);
    CHECK(HvMultiplyU64(ULLONG_MAX, 1, &value) && value == ULLONG_MAX);
    CHECK(HvSubtractU64(value, 0, &value) && value == ULLONG_MAX);
    CHECK(HvSubtractU64(value, ULLONG_MAX, &value) && value == 0);
    CHECK(!HvSubtractU64(value, 1, &value) && value == 0);

    unsigned buckets[HV_TOKEN_BUCKET_COUNT]{};
    for (unsigned i = 0; i < 10000; ++i) {
        const auto send = HvTokenBucketIndex(static_cast<unsigned long long>(i) * 16, HV_DIRECTION_SEND);
        const auto receive = HvTokenBucketIndex(static_cast<unsigned long long>(i) * 16, HV_DIRECTION_RECEIVE);
        CHECK(send < HV_TOKEN_BUCKET_COUNT && receive < HV_TOKEN_BUCKET_COUNT && send != receive);
        ++buckets[send];
    }
    for (unsigned count : buckets) CHECK(count != 0); // Buckets, not a distinct-token limit.

    for (int copied : {0, 1}) {
        CHECK(HvFinishRoute(HV_DIRECTION_SEND, copied, 1) == HvRouteSend);
        CHECK(HvFinishRoute(HV_DIRECTION_SEND, copied, 0) == HvRouteCompleteSend);
        CHECK(HvFinishRoute(HV_DIRECTION_RECEIVE, copied, 1) == HvRouteIndicateReceive);
    }
    CHECK(HvFinishRoute(HV_DIRECTION_RECEIVE, 0, 0) == HvRouteReturnReceive);
    CHECK(HvFinishRoute(HV_DIRECTION_RECEIVE, 1, 0) == HvRouteFreeReceive);
    std::puts("PASS LWF target gate, running/maintenance transitions, checked arithmetic and ownership routes");
    return 0;
}
