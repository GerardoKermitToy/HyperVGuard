// Portable pieces of the kernel ownership contract, shared with offline tests.
#ifndef HYPERV_XNDIS_FILTER_LWF_CONTRACT_H
#define HYPERV_XNDIS_FILTER_LWF_CONTRACT_H

// Internal host-vNIC ownership paths, NOT public outbound/inbound values.
#define HV_DIRECTION_SEND 0u
#define HV_DIRECTION_RECEIVE 1u
// Hash buckets have unbounded chains; this is a lookup aid, not a token quota.
#define HV_TOKEN_BUCKET_COUNT 256u
#define HV_DEFAULT_DECISION_TIMEOUT_MS 8000
#define HV_DEFAULT_FAIL_CLOSED 1
#define HV_PENDING_CHECK_MS 1000
#define HV_CACHE_CHECK_MS 10000

typedef enum _HV_FINISH_ROUTE {
    HvRouteSend,
    HvRouteCompleteSend,
    HvRouteIndicateReceive,
    HvRouteReturnReceive,
    HvRouteFreeReceive
} HV_FINISH_ROUTE;

static int HvTargetMatches(unsigned long long target, unsigned long long actual) {
    return target != 0 && target == actual;
}
static int HvIoctlInputEmpty(unsigned long inputLength) {
    return inputLength == 0;
}
// Caller serializes these transitions with the device I/O mutex. The kernel
// wraps each close/open transition with rundown wait/reinitialization.
static int HvSessionGateClose(unsigned char* closed) {
    if (*closed != 0) return 0;
    *closed = 1;
    return 1;
}
static int HvSessionGateReopen(unsigned char* closed) {
    if (*closed == 0) return 0;
    *closed = 0;
    return 1;
}
// Caller holds the adapter lock and adds the returned delta to the global count.
static int HvSetFilterRunning(unsigned char* state, int running) {
    int previous = *state != 0;
    *state = (unsigned char)(running != 0);
    return (*state != 0) - previous;
}
// Caller serializes candidate transitions with the policy lock. Return +1 to
// arm, -1 to cancel, or zero to leave a running/idle timer untouched.
static int HvSetMaintenanceArmed(unsigned char* armed, int candidates) {
    int previous = *armed != 0;
    *armed = (unsigned char)(candidates != 0);
    return (*armed != 0) - previous;
}
// Checked arithmetic leaves the output unchanged on failure. These helpers
// also cover the adapter's ownership references; UINT64_MAX is representational,
// not a configurable outstanding-NBL quota.
static inline int HvAddU64(unsigned long long left, unsigned long long right,
    unsigned long long* out) {
    if (right > ~0ull - left) return 0;
    *out = left + right;
    return 1;
}
static inline int HvMultiplyU64(unsigned long long left, unsigned long long right,
    unsigned long long* out) {
    if (left != 0 && right > ~0ull / left) return 0;
    *out = left * right;
    return 1;
}
static inline int HvSubtractU64(unsigned long long left, unsigned long long right,
    unsigned long long* out) {
    if (right > left) return 0;
    *out = left - right;
    return 1;
}
static inline unsigned int HvTokenBucketIndex(unsigned long long nbl, unsigned int direction) {
    unsigned long long hash = nbl >> 4;
    hash ^= hash >> 17;
    hash ^= hash >> 9;
    return (unsigned int)(hash ^ direction) & (HV_TOKEN_BUCKET_COUNT - 1u);
}
static HV_FINISH_ROUTE HvFinishRoute(unsigned int direction, int copied, int allow) {
    if (direction == HV_DIRECTION_SEND) return allow ? HvRouteSend : HvRouteCompleteSend;
    if (allow) return HvRouteIndicateReceive;
    return copied ? HvRouteFreeReceive : HvRouteReturnReceive;
}
#endif
