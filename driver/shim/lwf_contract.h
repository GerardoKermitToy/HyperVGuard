// Portable pieces of the kernel ownership contract, shared with offline tests.
#ifndef HYPERV_XNDIS_FILTER_LWF_CONTRACT_H
#define HYPERV_XNDIS_FILTER_LWF_CONTRACT_H

// Internal host-vNIC ownership paths, NOT public outbound/inbound values.
#define HV_DIRECTION_SEND 0u
#define HV_DIRECTION_RECEIVE 1u
#define HV_MAX_NB 64u
#define HV_MAX_COPY_BYTES (256u * 1024u)
#define HV_MAX_COPY_POOL_BYTES (16u * 1024u * 1024u)
// Retained buffered-read memory is independent of packet/copy storage. Admission
// is by bytes (including the original requested buffer), never by IRP count.
#define HV_MAX_QUEUED_READ_BYTES (16u * 1024u * 1024u)
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
static inline int HvReserveBytes(unsigned long long* used, unsigned long long cost,
    unsigned long long budget) {
    if (cost == 0 || *used > budget || cost > budget - *used) return 0;
    *used += cost;
    return 1;
}
static inline int HvReleaseBytes(unsigned long long* used, unsigned long long cost) {
    if (cost == 0 || cost > *used) return 0;
    *used -= cost;
    return 1;
}
static inline int HvQueuedReadCost(unsigned long long requested,
    unsigned long long irpBytes, unsigned long long stackCount,
    unsigned long long stackBytes, unsigned long long mdlBytes,
    unsigned long long bookkeepingBytes, unsigned long long* out) {
    unsigned long long cost;
    if (!HvMultiplyU64(stackCount, stackBytes, &cost) ||
        !HvAddU64(cost, irpBytes, &cost) || !HvAddU64(cost, mdlBytes, &cost) ||
        !HvAddU64(cost, bookkeepingBytes, &cost) || !HvAddU64(cost, requested, &cost)) return 0;
    *out = cost;
    return 1;
}
static inline unsigned int HvTokenBucketIndex(unsigned long long nbl, unsigned int direction) {
    unsigned long long hash = nbl >> 4;
    hash ^= hash >> 17;
    hash ^= hash >> 9;
    return (unsigned int)(hash ^ direction) & (HV_TOKEN_BUCKET_COUNT - 1u);
}
static int HvCopyFits(unsigned int count, unsigned int total, unsigned int length) {
    return count < HV_MAX_NB && length != 0 && total <= HV_MAX_COPY_BYTES &&
        length <= HV_MAX_COPY_BYTES - total;
}
static int HvCopyPoolFits(unsigned int used, unsigned int length) {
    return length != 0 && used <= HV_MAX_COPY_POOL_BYTES && length <= HV_MAX_COPY_POOL_BYTES - used;
}
static HV_FINISH_ROUTE HvFinishRoute(unsigned int direction, int copied, int allow) {
    if (direction == HV_DIRECTION_SEND) return allow ? HvRouteSend : HvRouteCompleteSend;
    if (allow) return HvRouteIndicateReceive;
    return copied ? HvRouteFreeReceive : HvRouteReturnReceive;
}
#endif
