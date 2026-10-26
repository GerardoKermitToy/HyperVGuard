// Portable pieces of the kernel ownership contract, shared with offline tests.
#ifndef HYPERV_XNDIS_FILTER_LWF_CONTRACT_H
#define HYPERV_XNDIS_FILTER_LWF_CONTRACT_H

// Internal host-vNIC ownership paths, NOT public outbound/inbound values.
#define HV_DIRECTION_SEND 0u
#define HV_DIRECTION_RECEIVE 1u
#define HV_MAX_NB 64u
#define HV_MAX_COPY_BYTES (256u * 1024u)
#define HV_MAX_COPY_POOL_BYTES (16u * 1024u * 1024u)

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
