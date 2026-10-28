// WDK ABI shim. Rust owns parsing, policy queues, wire API and verdicts.
#include <ntifs.h>
#include <ndis.h>
#include <netioapi.h>
#include "lwf_contract.h"
#include "driver_ready.h"
#include "adapter_info.h"

// C++20 branch attributes are hints only; retain the Rust/NDIS C ABI.
extern "C" {

#define TAG 'gVHH'
#define CACHE_TAG 'cVHH'
#define INFO_TAG 'iVHH'
#define VERSION_IOCTL CTL_CODE(40000, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SHUTDOWN_IOCTL CTL_CODE(40000, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define FILTERED_DEVICE_COUNT_IOCTL CTL_CODE(40000, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define ADAPTER_INFO_IOCTL CTL_CODE(40000, 0x803, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

C_ASSERT(NDIS_MAX_PHYS_ADDRESS_LENGTH == HV_ADAPTER_INFO_MAC_CAPACITY);

typedef struct _HV_ADAPTER HV_ADAPTER;
typedef struct _HV_TOKEN {
    LIST_ENTRY Link;
    HV_ADAPTER* Adapter;
    PNET_BUFFER_LIST Nbl;
    NDIS_PORT_NUMBER Port;
    ULONG Flags, Direction;
    BOOLEAN Copied, Forwarded;
} HV_TOKEN;
struct _HV_ADAPTER {
    NDIS_HANDLE Filter, NblPool, NbPool;
    NDIS_SPIN_LOCK Lock;
    PNDIS_RW_LOCK_EX ClassificationLock;
    EX_RUNDOWN_REF OidRundown;
    LIST_ENTRY Tokens[HV_TOKEN_BUCKET_COUNT], AdapterLink;
    HV_ADAPTER_INFO Info; // Protected by AdapterInfoLock; no borrowed NDIS pointers.
    UINT64 Id; // Diagnostic module ID only; policy uses InterfaceIndex.
    UINT64 Active; // Callback guards plus retained/forwarded NBL ownership.
    ULONG InterfaceIndex;
    BOOLEAN Running, PausePending;
};

extern const UCHAR HV_API_VERSION[4];
extern void HvConfigure(ULONG, ULONG, ULONG);
extern ULONG HvAttach(ULONG);
extern ULONG HvRestart(ULONG);
extern void HvInvalidate(ULONG, ULONG);
extern void HvDetach(ULONG);
extern void HvDrain(void);
extern void HvCleanCaches(void);
extern void HvConnect(void);
extern void HvDisconnect(void);
extern void HvCancel(ULONG, ULONG_PTR);
extern int HvClassify(ULONG_PTR, ULONG, ULONG, ULONG_PTR, ULONG);
extern void HvResourceDrop(void);
extern ULONG HvRead(UCHAR*, ULONG);
extern NTSTATUS HvWrite(const UCHAR*, ULONG);

static NDIS_HANDLE DriverHandle, DeviceHandle;
static PDEVICE_OBJECT ControlDevice;
static HANDLE ReadyEventHandle;
static PKEVENT ReadyEvent;
static KSPIN_LOCK PolicyLock;
// List/lifetime and diagnostic fields only. When both locks are needed, the
// adapter admission lock precedes this lock; queries never take adapter locks.
static KSPIN_LOCK AdapterInfoLock;
static LIST_ENTRY Adapters;
static UINT64 AdapterCount;
static FAST_MUTEX IoMutex;
static PFILE_OBJECT Client;
static volatile LONG Stopping;
static KTIMER PendingTimer, CacheTimer;
static KDPC PendingTimerDpc, CacheTimerDpc;
static UCHAR PendingTimerArmed, CacheTimerArmed;
static volatile LONG64 NextAdapter;
static volatile LONG64 FilteredDeviceCount;
static NDIS_STRING Friendly = RTL_CONSTANT_STRING(L"HyperVXNdisFilter Rust Host Adapter LWF");
static NDIS_STRING Unique = RTL_CONSTANT_STRING(L"{6E76EAD1-7BCB-49C4-9547-D3E6B3488F71}");
static NDIS_STRING ServiceName = RTL_CONSTANT_STRING(L"HyperVXNdisFilter");

DRIVER_UNLOAD HvUnload;
DRIVER_DISPATCH HvDispatch;
FILTER_ATTACH HvFilterAttach;
FILTER_DETACH HvFilterDetach;
FILTER_PAUSE HvFilterPause;
FILTER_RESTART HvFilterRestart;
FILTER_SEND_NET_BUFFER_LISTS HvSend;
FILTER_SEND_NET_BUFFER_LISTS_COMPLETE HvSendComplete;
FILTER_RECEIVE_NET_BUFFER_LISTS HvReceive;
FILTER_RETURN_NET_BUFFER_LISTS HvReturn;
FILTER_CANCEL_SEND_NET_BUFFER_LISTS HvCancelSend;
FILTER_OID_REQUEST HvOid;
FILTER_OID_REQUEST_COMPLETE HvOidComplete;
FILTER_CANCEL_OID_REQUEST HvCancelOid;
FILTER_NET_PNP_EVENT HvPnp;
FILTER_STATUS HvStatus;
static BOOLEAN TargetAdapter(PNDIS_FILTER_ATTACH_PARAMETERS p, GUID* interfaceGuid);
__declspec(noreturn) void hv_bugcheck(void);

// A cancel-safe queue without an admission quota. NDIS only schedules the reader;
// a system work item copies bytes in short policy-locked chunks and completes
// IRPs outside policy/NDIS locks.
static IO_CSQ ReadCsq;
static LIST_ENTRY ReadIrps;
static KSPIN_LOCK ReadLock;
static PFILE_OBJECT ReadClient;
static EX_RUNDOWN_REF ClassificationRundown, ReadRundown, CacheRundown;
static UCHAR ClassificationClosed;
static PIO_WORKITEM ReadWorkItem, CacheWorkItem;
static volatile LONG ReadPending, ReadReady, ReadOnline, ReadScheduled; // ReadPending is a boolean.
static volatile LONG CacheScheduled;
static IO_CSQ_INSERT_IRP_EX ReadInsert;
static IO_CSQ_REMOVE_IRP ReadRemove;
static IO_CSQ_PEEK_NEXT_IRP ReadPeek;
static IO_CSQ_ACQUIRE_LOCK HvReadQueueAcquire;
static IO_CSQ_RELEASE_LOCK HvReadQueueRelease;
static IO_CSQ_COMPLETE_CANCELED_IRP ReadCancelled;
static IO_WORKITEM_ROUTINE ReadWorker;
static IO_WORKITEM_ROUTINE CacheWorker;

static void CompleteRead(PIRP irp, NTSTATUS status, ULONG bytes) {
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytes;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    ExReleaseRundownProtection(&ReadRundown);
}
_Use_decl_annotations_
static NTSTATUS ReadInsert(PIO_CSQ csq, PIRP irp, PVOID context) {
    UNREFERENCED_PARAMETER(csq); UNREFERENCED_PARAMETER(context);
    if (Stopping || ReadClient != IoGetCurrentIrpStackLocation(irp)->FileObject || !ReadOnline)
        return STATUS_DEVICE_NOT_CONNECTED;
    InsertTailList(&ReadIrps, &irp->Tail.Overlay.ListEntry);
    InterlockedExchange(&ReadPending, 1);
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
static void ReadRemove(PIO_CSQ csq, PIRP irp) {
    UNREFERENCED_PARAMETER(csq);
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
    InterlockedExchange(&ReadPending, !IsListEmpty(&ReadIrps));
}
_Use_decl_annotations_
static PIRP ReadPeek(PIO_CSQ csq, PIRP irp, PVOID context) {
    PLIST_ENTRY entry = irp ? irp->Tail.Overlay.ListEntry.Flink : ReadIrps.Flink;
    UNREFERENCED_PARAMETER(csq);
    while (entry != &ReadIrps) {
        PIRP next = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        if (context == NULL || IoGetCurrentIrpStackLocation(next)->FileObject == context) return next;
        entry = entry->Flink;
    }
    return NULL;
}
_Use_decl_annotations_
static void HvReadQueueAcquire(PIO_CSQ csq, PKIRQL irql) {
    UNREFERENCED_PARAMETER(csq); KeAcquireSpinLock(&ReadLock, irql);
}
_Use_decl_annotations_
static void HvReadQueueRelease(PIO_CSQ csq, KIRQL irql) {
    UNREFERENCED_PARAMETER(csq); KeReleaseSpinLock(&ReadLock, irql);
}
_Use_decl_annotations_
static void ReadCancelled(PIO_CSQ csq, PIRP irp) {
    UNREFERENCED_PARAMETER(csq); CompleteRead(irp, STATUS_CANCELLED, 0);
}
static void SetReadClient(PFILE_OBJECT file) {
    KIRQL irql;
    KeAcquireSpinLock(&ReadLock, &irql); ReadClient = file; KeReleaseSpinLock(&ReadLock, irql);
}
// Device cleanup/shutdown closes admission before waiting for classifiers. The
// rundown cycle is reopened only by the next exclusive device create.
static void CloseClassificationSession(void) {
    if (!HvSessionGateClose(&ClassificationClosed)) return;
    ExWaitForRundownProtectionRelease(&ClassificationRundown);
    HvDisconnect();
}
static void OpenClassificationSession(void) {
    if (ClassificationClosed) {
        ExReInitializeRundownProtection(&ClassificationRundown);
        (void)HvSessionGateReopen(&ClassificationClosed);
    }
    HvConnect();
}
static void CancelReads(PFILE_OBJECT file) {
    PIRP irp;
    while ((irp = IoCsqRemoveNextIrp(&ReadCsq, file)) != NULL)
        CompleteRead(irp, STATUS_CANCELLED, 0);
}
static void ScheduleRead(void) {
    if (Stopping || ReadWorkItem == NULL || ReadPending == 0 || (!ReadReady && ReadOnline)) return;
    if (!ExAcquireRundownProtection(&ReadRundown)) return;
    if (InterlockedCompareExchange(&ReadScheduled, 1, 0) == 0)
        IoQueueWorkItem(ReadWorkItem, ReadWorker, DelayedWorkQueue, NULL);
    else ExReleaseRundownProtection(&ReadRundown);
}
// Coalesce timer and explicit requests; only one full cache pass may run.
void hv_request_cache_cleanup(void) {
    if (Stopping || CacheWorkItem == NULL) return;
    if (!ExAcquireRundownProtection(&CacheRundown)) return;
    if (InterlockedCompareExchange(&CacheScheduled, 1, 0) == 0)
        IoQueueWorkItem(CacheWorkItem, CacheWorker, DelayedWorkQueue, NULL);
    else ExReleaseRundownProtection(&CacheRundown);
}
_Use_decl_annotations_
static void CacheWorker(PDEVICE_OBJECT device, PVOID context) {
    UNREFERENCED_PARAMETER(device); UNREFERENCED_PARAMETER(context);
    if (!Stopping) HvCleanCaches();
    InterlockedExchange(&CacheScheduled, 0);
    ExReleaseRundownProtection(&CacheRundown);
}
static void UpdateMaintenanceTimer(PKTIMER timer, PKDPC dpc, UCHAR* armed,
    LONG interval, BOOLEAN candidates) {
    int transition = HvSetMaintenanceArmed(armed, !Stopping && candidates);
    if (transition > 0) {
        LARGE_INTEGER due;
        due.QuadPart = -(LONGLONG)interval * 10000;
        KeSetTimerEx(timer, due, interval, dpc);
    } else if (transition < 0) KeCancelTimer(timer);
}
// Called only with PolicyLock held. Constant-time candidate publication; timers
// start/stop only on transitions, never reset on each packet or cache hit.
void hv_publish_state(ULONG ready, ULONG online, ULONG pending, ULONG cached) {
    if (ReadReady != (LONG)ready) InterlockedExchange(&ReadReady, (LONG)ready);
    if (ReadOnline != (LONG)online) InterlockedExchange(&ReadOnline, (LONG)online);
    UpdateMaintenanceTimer(&PendingTimer, &PendingTimerDpc, &PendingTimerArmed,
        HV_PENDING_CHECK_MS, pending != 0);
    UpdateMaintenanceTimer(&CacheTimer, &CacheTimerDpc, &CacheTimerArmed,
        HV_CACHE_CHECK_MS, cached != 0);
    ScheduleRead();
}
_Use_decl_annotations_
static void ReadWorker(PDEVICE_OBJECT device, PVOID context) {
    UNREFERENCED_PARAMETER(device); UNREFERENCED_PARAMETER(context);
    for (;;) {
        PIRP irp;
        NTSTATUS status = STATUS_SUCCESS;
        ULONG bytes = 0;
        if (Stopping || (!ReadReady && ReadOnline)) break;
        irp = IoCsqRemoveNextIrp(&ReadCsq, NULL);
        if (irp == NULL) break;
        ExAcquireFastMutex(&IoMutex);
        if (Stopping || !ReadOnline || Client != IoGetCurrentIrpStackLocation(irp)->FileObject)
            status = STATUS_CANCELLED;
        else bytes = HvRead(static_cast<UCHAR*>(irp->AssociatedIrp.SystemBuffer),
            IoGetCurrentIrpStackLocation(irp)->Parameters.Read.Length);
        ExReleaseFastMutex(&IoMutex);
        if (!NT_SUCCESS(status) || bytes != 0) CompleteRead(irp, status, bytes);
        else {
            // A timeout may have removed every unread event. Keep waiting instead
            // of completing with zero. InsertEx also closes the cleanup race.
            status = IoCsqInsertIrpEx(&ReadCsq, irp, NULL, NULL);
            if (!NT_SUCCESS(status)) CompleteRead(irp, status, 0);
            break;
        }
    }
    InterlockedExchange(&ReadScheduled, 0);
    ScheduleRead(); // Recheck after releasing ownership: no enqueue/wakeup gap.
    ExReleaseRundownProtection(&ReadRundown);
}

ULONG_PTR hv_lock(void) {
    KIRQL irql; KeAcquireSpinLock(&PolicyLock, &irql); return irql;
}
void hv_unlock(ULONG_PTR irql) { KeReleaseSpinLock(&PolicyLock, (KIRQL)irql); }
UINT64 hv_now(void) { return KeQueryInterruptTime() / 10000; }
// Nonpaged allocations are fallible, with no driver-defined byte budget.
void* hv_allocate(SIZE_T size) {
    if (size == 0) [[unlikely]] return NULL;
    return ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, size, TAG);
}
void hv_free(void* data, SIZE_T size) {
    UNREFERENCED_PARAMETER(size);
    ExFreePoolWithTag(data, TAG);
}
// Cache preparation and retirement use a separate allocator outside PolicyLock.
void* hv_cache_allocate(SIZE_T size) {
    if (size == 0) [[unlikely]] return NULL;
    return ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, size, CACHE_TAG);
}
void hv_cache_free(void* data, SIZE_T size) {
    UNREFERENCED_PARAMETER(size);
    ExFreePoolWithTag(data, CACHE_TAG);
}
__declspec(noreturn) void hv_bugcheck(void) {
    KeBugCheckEx(DRIVER_VERIFIER_DETECTED_VIOLATION, 0x48565253, 0, 0, 0);
}
static ULONG SendCompleteFlags(void) {
    return KeGetCurrentIrql() == DISPATCH_LEVEL ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0;
}
static ULONG ReturnFlags(void) {
    return KeGetCurrentIrql() == DISPATCH_LEVEL ? NDIS_RETURN_FLAGS_DISPATCH_LEVEL : 0;
}
// Called with the adapter lock held. Ownership cannot be saturated or wrapped;
// an impossible representational overflow is fatal rather than losing rundown.
static void RetainActiveLocked(HV_ADAPTER* a) {
    if (!HvAddU64(a->Active, 1, &a->Active)) [[unlikely]] hv_bugcheck();
}
static void ReleaseActive(HV_ADAPTER* a, UINT64 count) {
    BOOLEAN complete = FALSE;
    NDIS_HANDLE filter = a->Filter;
    NdisAcquireSpinLock(&a->Lock);
    if (!HvSubtractU64(a->Active, count, &a->Active)) [[unlikely]] hv_bugcheck();
    if (a->Active == 0 && a->PausePending) { a->PausePending = FALSE; complete = TRUE; }
    NdisReleaseSpinLock(&a->Lock);
    // Last access to a: PauseComplete may synchronously cause detach/free.
    if (complete) NdisFPauseComplete(filter);
}
static void SetFilterRunning(HV_ADAPTER* a, BOOLEAN running) {
    LONG64 count;
    int delta;
    NdisAcquireSpinLock(&a->Lock);
    KeAcquireSpinLockAtDpcLevel(&AdapterInfoLock);
    delta = HvSetFilterRunning(&a->Running, running);
    if (FilteredDeviceCount < 0 || (delta < 0 && FilteredDeviceCount == 0) ||
        (delta > 0 && FilteredDeviceCount == MAXLONGLONG)) hv_bugcheck();
    count = InterlockedAdd64(&FilteredDeviceCount, delta);
    if (running) a->Info.Flags |= HV_ADAPTER_RUNNING;
    else a->Info.Flags &= ~HV_ADAPTER_RUNNING;
    KeReleaseSpinLockFromDpcLevel(&AdapterInfoLock);
    NT_ASSERT(count >= 0);
    UNREFERENCED_PARAMETER(count);
    NdisReleaseSpinLock(&a->Lock);
}
static BOOLEAN BeginIo(HV_ADAPTER* a, BOOLEAN* session) {
    BOOLEAN running;
    // Acquire before taking the per-adapter lock so cleanup can close this
    // session and wait for every admitted classifier before disconnecting.
    *session = ExAcquireRundownProtection(&ClassificationRundown);
    NdisAcquireSpinLock(&a->Lock);
    running = a->Running;
    RetainActiveLocked(a); // Callback guard also protects rejects while pausing.
    NdisReleaseSpinLock(&a->Lock);
    return running;
}

static void EndIo(HV_ADAPTER* a, BOOLEAN session) {
    if (session) ExReleaseRundownProtection(&ClassificationRundown);
    ReleaseActive(a, 1);
}
static void FreeReceiveCopy(PNET_BUFFER_LIST nbl) {
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb != NULL) {
        PNET_BUFFER next = NET_BUFFER_NEXT_NB(nb);
        PMDL mdl = NET_BUFFER_FIRST_MDL(nb);
        void* data = MmGetMdlVirtualAddress(mdl);
        NdisFreeNetBuffer(nb);
        IoFreeMdl(mdl);
        ExFreePoolWithTag(data, TAG);
        nb = next;
    }
    NdisFreeNetBufferList(nbl);
}
static BOOLEAN CopyMetadataSupported(PNET_BUFFER_LIST nbl) {
    ULONG i;
    // Only inline receive OOB with a known lifetime is supported for resources
    // copies. Do not retain media/IPsec/WFP/RSC/virtualization metadata pointers.
    for (i = 0; i < MaxNetBufferListInfo; ++i) {
        if (NET_BUFFER_LIST_INFO(nbl, i) == NULL) continue;
        switch (i) {
        case TcpIpChecksumNetBufferListInfo:
        case TcpReceiveNoPush:
        case Ieee8021QNetBufferListInfo:
        case NetBufferListFrameType:
        case NetBufferListHashValue:
        case NetBufferListHashInfo:
            break;
        default:
            return FALSE;
        }
    }
    return TRUE;
}
static PNET_BUFFER_LIST CopyReceive(HV_ADAPTER* a, PNET_BUFFER_LIST source) {
    PNET_BUFFER nb, tail = NULL;
    PNET_BUFFER_LIST copy;
    if (!CopyMetadataSupported(source) || NET_BUFFER_LIST_FIRST_NB(source) == NULL) return NULL;
    copy = NdisAllocateNetBufferList(a->NblPool, 0, 0);
    if (copy == NULL) [[unlikely]] return NULL;
    NET_BUFFER_LIST_FIRST_NB(copy) = NULL;
    NET_BUFFER_LIST_NEXT_NBL(copy) = NULL;
    for (nb = NET_BUFFER_LIST_FIRST_NB(source); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
        ULONG length = NET_BUFFER_DATA_LENGTH(nb);
        void* storage;
        void* data;
        PMDL mdl;
        PNET_BUFFER created;
        if (length == 0) [[unlikely]] goto Fail;
        storage = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, TAG);
        if (storage == NULL) [[unlikely]] goto Fail;
        data = NdisGetDataBuffer(nb, length, storage, 1, 0);
        if (data == NULL) [[unlikely]] { ExFreePoolWithTag(storage, TAG); goto Fail; }
        if (data != storage) RtlCopyMemory(storage, data, length);
        mdl = IoAllocateMdl(storage, length, FALSE, FALSE, NULL);
        if (mdl == NULL) [[unlikely]] { ExFreePoolWithTag(storage, TAG); goto Fail; }
        MmBuildMdlForNonPagedPool(mdl);
        created = NdisAllocateNetBuffer(a->NbPool, mdl, 0, length);
        if (created == NULL) [[unlikely]] { IoFreeMdl(mdl); ExFreePoolWithTag(storage, TAG); goto Fail; }
        NET_BUFFER_NEXT_NB(created) = NULL;
        if (tail != NULL) NET_BUFFER_NEXT_NB(tail) = created;
        else NET_BUFFER_LIST_FIRST_NB(copy) = created;
        tail = created;
    }
    NdisCopyReceiveNetBufferListInfo(copy, source);
    NET_BUFFER_LIST_NBL_FLAGS(copy) = NET_BUFFER_LIST_NBL_FLAGS(source) &
        (NDIS_NBL_FLAGS_IS_IPV4 | NDIS_NBL_FLAGS_IS_IPV6 |
         NDIS_NBL_FLAGS_IS_TCP | NDIS_NBL_FLAGS_IS_UDP | NDIS_NBL_FLAGS_IS_LOOPBACK_PACKET);
    copy->SourceHandle = a->Filter;
    return copy;
Fail:
    FreeReceiveCopy(copy);
    return NULL;
}
static PLIST_ENTRY TokenBucket(HV_ADAPTER* a, PNET_BUFFER_LIST nbl, ULONG direction) {
    return &a->Tokens[HvTokenBucketIndex((ULONG_PTR)nbl, direction)];
}
static BOOLEAN TokensEmpty(HV_ADAPTER* a) {
    ULONG i;
    for (i = 0; i < HV_TOKEN_BUCKET_COUNT; ++i) if (!IsListEmpty(&a->Tokens[i])) return FALSE;
    return TRUE;
}
static void ReleaseToken(HV_TOKEN* t) {
    HV_ADAPTER* a = t->Adapter;
    hv_free(t, sizeof(*t));
    ReleaseActive(a, 1);
}
static HV_TOKEN* CreateToken(HV_ADAPTER* a, PNET_BUFFER_LIST nbl, NDIS_PORT_NUMBER port,
    ULONG flags, ULONG direction, BOOLEAN resources) {
    HV_TOKEN* t;
    NdisAcquireSpinLock(&a->Lock);
    if (!a->Running) [[unlikely]] { NdisReleaseSpinLock(&a->Lock); return NULL; }
    RetainActiveLocked(a);
    NdisReleaseSpinLock(&a->Lock);
    // Tokens grow fallibly without a count or byte quota.
    // Allocation failure preserves the existing drop path.
    t = static_cast<HV_TOKEN*>(hv_allocate(sizeof(*t)));
    if (t == NULL) [[unlikely]] { ReleaseActive(a, 1); return NULL; }
    RtlZeroMemory(t, sizeof(*t));
    t->Adapter = a; t->Nbl = nbl; t->Port = port; t->Flags = flags;
    t->Direction = direction;
    if (resources) {
        t->Nbl = CopyReceive(a, nbl);
        if (t->Nbl == NULL) { ReleaseToken(t); return NULL; }
        t->Copied = TRUE;
        // The new storage has no shared-memory/header-split/queue assertions.
        t->Flags = 0;
    }
    NdisAcquireSpinLock(&a->Lock);
    InsertTailList(TokenBucket(a, t->Nbl, direction), &t->Link);
    NdisReleaseSpinLock(&a->Lock);
    return t;
}
void hv_finish(ULONG_PTR token, ULONG finish) {
    HV_TOKEN* t = (HV_TOKEN*)token;
    HV_ADAPTER* a = t->Adapter;
    PNET_BUFFER_LIST nbl = t->Nbl;
    ULONG flags;
    BOOLEAN allow;
    HV_FINISH_ROUTE route;
    NdisAcquireSpinLock(&a->Lock);
    allow = finish == 0 && a->Running;
    if (allow) t->Forwarded = TRUE;
    else RemoveEntryList(&t->Link);
    NdisReleaseSpinLock(&a->Lock);
    route = HvFinishRoute(t->Direction, t->Copied, allow);
    switch (route) {
    case HvRouteSend:
        flags = t->Flags & ~NDIS_SEND_FLAGS_DISPATCH_LEVEL;
        if (KeGetCurrentIrql() == DISPATCH_LEVEL) flags |= NDIS_SEND_FLAGS_DISPATCH_LEVEL;
        NdisFSendNetBufferLists(a->Filter, nbl, t->Port, flags);
        return; // Synchronous completion can already have freed t.
    case HvRouteIndicateReceive:
        flags = t->Flags & ~(NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL | NDIS_RECEIVE_FLAGS_RESOURCES);
        if (KeGetCurrentIrql() == DISPATCH_LEVEL) flags |= NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL;
        NdisFIndicateReceiveNetBufferLists(a->Filter, nbl, t->Port, 1, flags);
        return; // An upper return may already have freed t.
    case HvRouteCompleteSend:
        NET_BUFFER_LIST_STATUS(nbl) = finish == 2 ? NDIS_STATUS_SEND_ABORTED : NDIS_STATUS_SUCCESS;
        NdisFSendNetBufferListsComplete(a->Filter, nbl, SendCompleteFlags());
        break;
    case HvRouteReturnReceive:
        NdisFReturnNetBufferLists(a->Filter, nbl, ReturnFlags());
        break;
    case HvRouteFreeReceive:
        FreeReceiveCopy(nbl);
        break;
    }
    ReleaseToken(t);
}
void* hv_first_nb(ULONG_PTR token) { return NET_BUFFER_LIST_FIRST_NB(((HV_TOKEN*)token)->Nbl); }
void* hv_next_nb(PNET_BUFFER nb) { return NET_BUFFER_NEXT_NB(nb); }
ULONG hv_snapshot(PNET_BUFFER nb, ULONG_PTR token, UCHAR* out, ULONG cap,
    ULONG* copied, ULONG* trusted, ULONG* frameLength, ULONG* offload) {
    HV_TOKEN* t = (HV_TOKEN*)token;
    ULONG n = min(cap, NET_BUFFER_DATA_LENGTH(nb));
    void* data;
    *copied = 0; *trusted = 0; *frameLength = NET_BUFFER_DATA_LENGTH(nb);
    *offload = NET_BUFFER_LIST_INFO(t->Nbl, TcpRecvSegCoalesceInfo) != NULL ||
        (t->Direction == HV_DIRECTION_SEND ?
            NET_BUFFER_LIST_INFO(t->Nbl, TcpLargeSendNetBufferListInfo) != NULL :
            NET_BUFFER_LIST_INFO(t->Nbl, TcpReceiveBytesTransferred) != NULL);
    if (n == 0) [[unlikely]] return 0;
    data = NdisGetDataBuffer(nb, n, out, 1, 0);
    if (data == NULL) [[unlikely]] return 0;
    if (data != out) RtlCopyMemory(out, data, n);
    *copied = n; *trusted = n; return 1;
}
static HV_TOKEN* TakeForwarded(HV_ADAPTER* a, PNET_BUFFER_LIST nbl, ULONG direction) {
    HV_TOKEN* t = NULL;
    LIST_ENTRY* entry;
    LIST_ENTRY* bucket = TokenBucket(a, nbl, direction);
    NdisAcquireSpinLock(&a->Lock);
    for (entry = bucket->Flink; entry != bucket; entry = entry->Flink) {
        HV_TOKEN* found = CONTAINING_RECORD(entry, HV_TOKEN, Link);
        if (found->Nbl == nbl && found->Direction == direction && found->Forwarded) {
            t = found; RemoveEntryList(entry); break;
        }
    }
    NdisReleaseSpinLock(&a->Lock);
    NT_ASSERT(t != NULL);
    return t;
}
static void ClassifyChain(HV_ADAPTER* a, PNET_BUFFER_LIST chain, NDIS_PORT_NUMBER port,
    ULONG flags, ULONG direction, BOOLEAN resources, BOOLEAN admitted, BOOLEAN session) {
    while (chain != NULL) {
        PNET_BUFFER_LIST nbl = chain;
        HV_TOKEN* t = NULL;
        LOCK_STATE_EX state;
        int result = 1;
        chain = NET_BUFFER_LIST_NEXT_NBL(nbl);
        // RESOURCES originals and their chain must be unchanged at callback exit.
        if (!resources) NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        if (HvClassifyAdmission(admitted, session)) {
            NdisAcquireRWLockRead(a->ClassificationLock, &state, 0);
            t = CreateToken(a, nbl, port, flags, direction, resources);
            if (t != NULL) [[likely]] {
                ULONG_PTR cancel = direction == HV_DIRECTION_SEND ?
                    (ULONG_PTR)NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(nbl) : 0;
                result = HvClassify((ULONG_PTR)t, a->InterfaceIndex, direction, cancel,
                    session ? 1u : 0u);
            }
            NdisReleaseRWLock(a->ClassificationLock, &state);
        }
        if (t == NULL) {
            HvResourceDrop();
            if (direction == HV_DIRECTION_SEND) {
                NET_BUFFER_LIST_STATUS(nbl) = admitted ? NDIS_STATUS_RESOURCES : NDIS_STATUS_PAUSED;
                NdisFSendNetBufferListsComplete(a->Filter, nbl, SendCompleteFlags());
            } else if (!resources) NdisFReturnNetBufferLists(a->Filter, nbl, ReturnFlags());
        } else if (result >= 0) hv_finish((ULONG_PTR)t, (ULONG)result);
    }
}
_Use_decl_annotations_
void HvSend(NDIS_HANDLE context, PNET_BUFFER_LIST chain, NDIS_PORT_NUMBER port, ULONG flags) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    BOOLEAN session;
    BOOLEAN admitted = BeginIo(a, &session);
    ClassifyChain(a, chain, port, flags, HV_DIRECTION_SEND, FALSE, admitted, session);
    EndIo(a, session);
}
_Use_decl_annotations_
void HvSendComplete(NDIS_HANDLE context, PNET_BUFFER_LIST chain, ULONG flags) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    NdisAcquireSpinLock(&a->Lock); RetainActiveLocked(a); NdisReleaseSpinLock(&a->Lock);
    while (chain != NULL) {
        PNET_BUFFER_LIST nbl = chain;
        HV_TOKEN* t;
        chain = NET_BUFFER_LIST_NEXT_NBL(nbl); NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        t = TakeForwarded(a, nbl, HV_DIRECTION_SEND);
        NdisFSendNetBufferListsComplete(a->Filter, nbl, flags);
        if (t != NULL) [[likely]] ReleaseToken(t);
    }
    ReleaseActive(a, 1);
}
_Use_decl_annotations_
void HvCancelSend(NDIS_HANDLE context, PVOID cancel) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    NdisAcquireSpinLock(&a->Lock); RetainActiveLocked(a); NdisReleaseSpinLock(&a->Lock);
    HvCancel(a->InterfaceIndex, (ULONG_PTR)cancel);
    NdisFCancelSendNetBufferLists(a->Filter, cancel);
    ReleaseActive(a, 1);
}
_Use_decl_annotations_
void HvReceive(NDIS_HANDLE context, PNET_BUFFER_LIST chain, NDIS_PORT_NUMBER port, ULONG count, ULONG flags) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    BOOLEAN session;
    BOOLEAN admitted = BeginIo(a, &session);
    UNREFERENCED_PARAMETER(count);
    ClassifyChain(a, chain, port, flags, HV_DIRECTION_RECEIVE,
        (flags & NDIS_RECEIVE_FLAGS_RESOURCES) != 0, admitted, session);
    EndIo(a, session);
}
_Use_decl_annotations_
void HvReturn(NDIS_HANDLE context, PNET_BUFFER_LIST chain, ULONG flags) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    NdisAcquireSpinLock(&a->Lock); RetainActiveLocked(a); NdisReleaseSpinLock(&a->Lock);
    while (chain != NULL) {
        PNET_BUFFER_LIST nbl = chain;
        HV_TOKEN* t;
        chain = NET_BUFFER_LIST_NEXT_NBL(nbl); NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        t = TakeForwarded(a, nbl, HV_DIRECTION_RECEIVE);
        if (t != NULL && t->Copied) FreeReceiveCopy(nbl);
        else NdisFReturnNetBufferLists(a->Filter, nbl, flags);
        if (t != NULL) [[likely]] ReleaseToken(t);
    }
    ReleaseActive(a, 1);
}
static void Invalidate(HV_ADAPTER* a) {
    LOCK_STATE_EX state;
    NdisAcquireRWLockWrite(a->ClassificationLock, &state, 0);
    HvInvalidate(a->InterfaceIndex, TRUE);
    NdisReleaseRWLock(a->ClassificationLock, &state);
    HvDrain(); // No NDIS call under the classification/policy locks.
}
static void HvOidCopyResult(PNDIS_OID_REQUEST original, PNDIS_OID_REQUEST clone) {
    switch (clone->RequestType) {
    case NdisRequestMethod:
        original->DATA.METHOD_INFORMATION.OutputBufferLength = clone->DATA.METHOD_INFORMATION.OutputBufferLength;
        original->DATA.METHOD_INFORMATION.BytesRead = clone->DATA.METHOD_INFORMATION.BytesRead;
        original->DATA.METHOD_INFORMATION.BytesWritten = clone->DATA.METHOD_INFORMATION.BytesWritten;
        original->DATA.METHOD_INFORMATION.BytesNeeded = clone->DATA.METHOD_INFORMATION.BytesNeeded;
        break;
    case NdisRequestSetInformation:
        original->DATA.SET_INFORMATION.BytesRead = clone->DATA.SET_INFORMATION.BytesRead;
        original->DATA.SET_INFORMATION.BytesNeeded = clone->DATA.SET_INFORMATION.BytesNeeded;
        break;
    default:
        original->DATA.QUERY_INFORMATION.BytesWritten = clone->DATA.QUERY_INFORMATION.BytesWritten;
        original->DATA.QUERY_INFORMATION.BytesNeeded = clone->DATA.QUERY_INFORMATION.BytesNeeded;
        break;
    }
}
static PNDIS_OID_REQUEST HvOidFreeClone(HV_ADAPTER* a, PNDIS_OID_REQUEST clone) {
    PNDIS_OID_REQUEST original = static_cast<PNDIS_OID_REQUEST>(*(PVOID*)&clone->SourceReserved[0]);
    HvOidCopyResult(original, clone);
    NdisFreeCloneOidRequest(a->Filter, clone);
    return original;
}
_Use_decl_annotations_
NDIS_STATUS HvOid(NDIS_HANDLE context, PNDIS_OID_REQUEST r) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    PNDIS_OID_REQUEST clone;
    NDIS_STATUS status;
    if (!ExAcquireRundownProtection(&a->OidRundown)) return NDIS_STATUS_CLOSING;
    status = NdisAllocateCloneOidRequest(a->Filter, r, TAG, &clone);
    if (status != NDIS_STATUS_SUCCESS) [[unlikely]] {ExReleaseRundownProtection(&a->OidRundown); return status;}
    *(PVOID*)&clone->SourceReserved[0] = r;
    status = NdisFOidRequest(a->Filter, clone);
    if (status != NDIS_STATUS_PENDING) {
        (void)HvOidFreeClone(a, clone);
        ExReleaseRundownProtection(&a->OidRundown);
        return (NDIS_STATUS)HvOidHandlerReturn(status);
    }
    return status;
}
_Use_decl_annotations_
void HvOidComplete(NDIS_HANDLE context, PNDIS_OID_REQUEST clone, NDIS_STATUS status) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    PNDIS_OID_REQUEST original = HvOidFreeClone(a, clone);
    NdisFOidRequestComplete(a->Filter, original, status);
    ExReleaseRundownProtection(&a->OidRundown);
}
_Use_decl_annotations_
void HvCancelOid(NDIS_HANDLE context, PVOID id) {NdisFCancelOidRequest(((HV_ADAPTER*)context)->Filter, id);}
_Use_decl_annotations_
NDIS_STATUS HvPnp(NDIS_HANDLE context, PNET_PNP_EVENT_NOTIFICATION event) {
    return NdisFNetPnPEvent(((HV_ADAPTER*)context)->Filter, event);
}
static uint32_t CopyAdapterName(uint16_t* out, PNDIS_STRING name, uint32_t* flags, uint32_t truncatedFlag) {
    return HvCopyAdapterName(out, name ? (const uint16_t*)name->Buffer : NULL,
        name ? name->Length / sizeof(WCHAR) : 0, flags, truncatedFlag);
}
static void CaptureAttachInfo(HV_ADAPTER* a, PNDIS_FILTER_ATTACH_PARAMETERS p, const GUID* guid) {
    HV_ADAPTER_INFO* info = &a->Info;
    info->ModuleId = a->Id;
    info->InterfaceIndex = p->BaseMiniportIfIndex;
    info->FilterInterfaceIndex = p->IfIndex;
    info->LowerInterfaceIndex = p->LowerIfIndex;
    info->InterfaceLuid = p->BaseMiniportNetLuid.Value;
    info->FilterInterfaceLuid = p->NetLuid.Value;
    info->LowerInterfaceLuid = p->LowerIfNetLuid.Value;
    HvInfoWrite32(info->InterfaceGuid, guid->Data1);
    info->InterfaceGuid[4] = (UCHAR)guid->Data2; info->InterfaceGuid[5] = (UCHAR)(guid->Data2 >> 8);
    info->InterfaceGuid[6] = (UCHAR)guid->Data3; info->InterfaceGuid[7] = (UCHAR)(guid->Data3 >> 8);
    RtlCopyMemory(info->InterfaceGuid + 8, guid->Data4, sizeof(guid->Data4));
    info->MediaType = p->MiniportMediaType;
    info->PhysicalMedium = p->MiniportPhysicalMediaType;
    info->MediaConnectState = p->MediaConnectState;
    info->MediaDuplexState = p->MediaDuplexState;
    info->XmitLinkSpeed = p->XmitLinkSpeed;
    info->RcvLinkSpeed = p->RcvLinkSpeed;
    info->AttachFlags = p->Flags;
    info->MacAddressLength = min(p->MacAddressLength, HV_ADAPTER_INFO_MAC_CAPACITY);
    RtlCopyMemory(info->MacAddress, p->CurrentMacAddress, info->MacAddressLength);
    if (p->Header.Revision >= NDIS_FILTER_ATTACH_PARAMETERS_REVISION_4 &&
        p->Header.Size >= NDIS_SIZEOF_FILTER_ATTACH_PARAMETERS_REVISION_4) {
        info->Flags |= HV_ADAPTER_CONNECTOR_VALID;
        info->ConnectorPresent = p->BaseMiniportIfConnectorPresent != FALSE;
    }
    // Counted strings belong to NDIS only for this callback, so copy now.
    info->InstanceNameLength = CopyAdapterName(info->InstanceName, p->BaseMiniportInstanceName,
        &info->Flags, HV_ADAPTER_INSTANCE_NAME_TRUNCATED);
    info->BaseNameLength = CopyAdapterName(info->BaseName, p->BaseMiniportName,
        &info->Flags, HV_ADAPTER_BASE_NAME_TRUNCATED);
    info->FilterModuleNameLength = CopyAdapterName(info->FilterModuleName, p->FilterModuleGuidName,
        &info->Flags, HV_ADAPTER_FILTER_NAME_TRUNCATED);
}
static void CaptureRestartInfo(HV_ADAPTER* a, PNDIS_FILTER_RESTART_PARAMETERS p) {
    PNDIS_RESTART_ATTRIBUTES attribute;
    NDIS_RESTART_GENERAL_ATTRIBUTES general = {0};
    ULONG mediaType = p->MiniportMediaType, physicalMedium = p->MiniportPhysicalMediaType;
    ULONG lowerIndex = p->LowerIfIndex;
    UINT64 lowerLuid = p->LowerIfNetLuid.Value;
    BOOLEAN haveGeneral = FALSE;
    KIRQL irql;
    // Traverse/copy borrowed restart data at callback IRQL, before taking a spin
    // lock. Only our nonpaged snapshot and small local values are used below it.
    for (attribute = p->RestartAttributes; attribute != NULL; attribute = attribute->Next) {
        const NDIS_RESTART_GENERAL_ATTRIBUTES* candidate;
        if (attribute->Oid != OID_GEN_MINIPORT_RESTART_ATTRIBUTES ||
            attribute->DataLength < NDIS_SIZEOF_RESTART_GENERAL_ATTRIBUTES_REVISION_1) continue;
        candidate = (const NDIS_RESTART_GENERAL_ATTRIBUTES*)attribute->Data;
        if (candidate->Header.Type != NDIS_OBJECT_TYPE_RESTART_GENERAL_ATTRIBUTES ||
            candidate->Header.Revision < NDIS_RESTART_GENERAL_ATTRIBUTES_REVISION_1 ||
            candidate->Header.Size < NDIS_SIZEOF_RESTART_GENERAL_ATTRIBUTES_REVISION_1 ||
            candidate->Header.Size > attribute->DataLength) continue;
        RtlCopyMemory(&general, candidate, NDIS_SIZEOF_RESTART_GENERAL_ATTRIBUTES_REVISION_1);
        haveGeneral = TRUE;
        break;
    }
    KeAcquireSpinLock(&AdapterInfoLock, &irql);
    a->Info.MediaType = mediaType;
    a->Info.PhysicalMedium = physicalMedium;
    a->Info.LowerInterfaceIndex = lowerIndex;
    a->Info.LowerInterfaceLuid = lowerLuid;
    HvClearGeneralAttributes(&a->Info);
    if (haveGeneral) {
        a->Info.Flags |= HV_ADAPTER_GENERAL_VALID;
        a->Info.Mtu = general.MtuSize;
        a->Info.MaxXmitLinkSpeed = general.MaxXmitLinkSpeed;
        a->Info.MaxRcvLinkSpeed = general.MaxRcvLinkSpeed;
        a->Info.LookaheadSize = general.LookaheadSize;
        a->Info.MacOptions = general.MacOptions;
        a->Info.SupportedPacketFilters = general.SupportedPacketFilters;
        a->Info.MaxMulticastListSize = general.MaxMulticastListSize;
        a->Info.AccessType = general.AccessType;
        a->Info.RestartFlags = general.Flags;
        a->Info.ConnectionType = general.ConnectionType;
        a->Info.SupportedStatistics = general.SupportedStatistics;
        a->Info.DataBackFillSize = general.DataBackFillSize;
        a->Info.ContextBackFillSize = general.ContextBackFillSize;
    }
    KeReleaseSpinLock(&AdapterInfoLock, irql);
}
static NTSTATUS QueryAdapterInfo(UCHAR* out, ULONG capacity, ULONG_PTR* transferred) {
    HV_ADAPTER_INFO* snapshot = NULL;
    UINT64 allocatedCount = 0;
    ULONG attempt, i, count = 0, running = 0;
    uint32_t size = 0;
    NTSTATUS status = STATUS_RETRY;
    if (capacity < HV_ADAPTER_INFO_HEADER_SIZE) return STATUS_BUFFER_TOO_SMALL;
    if (out == NULL) return STATUS_INVALID_PARAMETER;
    // Allocate only the observed count, outside the diagnostic spin lock. Retry
    // staging growth under attachment churn; this bounds attempts, not adapters.
    for (attempt = 0; attempt < HV_ADAPTER_INFO_MAX_STAGING_ATTEMPTS; ++attempt) {
        PLIST_ENTRY entry;
        KIRQL irql;
        HV_ADAPTER_INFO_ACTION action;
        KeAcquireSpinLock(&AdapterInfoLock, &irql);
        action = HvPlanAdapterInfo(AdapterCount, capacity, allocatedCount, &size);
        if (action == HvAdapterInfoCountOverflow) {
            status = STATUS_INTEGER_OVERFLOW;
            KeReleaseSpinLock(&AdapterInfoLock, irql);
            break;
        }
        count = (ULONG)AdapterCount;
        running = (ULONG)FilteredDeviceCount;
        NT_ASSERT(running <= count && size != 0 && action != HvAdapterInfoTooSmall);
        if (action == HvAdapterInfoHeaderOnly) {
            // METHOD_BUFFERED warnings return this header even on a failed
            // DeviceIoControl/GetOverlappedResult (Win32 ERROR_MORE_DATA).
            HvEncodeAdapterInfoHeader(out, count, running);
            *transferred = HV_ADAPTER_INFO_HEADER_SIZE;
            status = STATUS_BUFFER_OVERFLOW;
            KeReleaseSpinLock(&AdapterInfoLock, irql);
            break;
        }
        if (action == HvAdapterInfoGrowStaging) {
            UINT64 bytes;
            KeReleaseSpinLock(&AdapterInfoLock, irql);
            if (snapshot != NULL) { ExFreePoolWithTag(snapshot, INFO_TAG); snapshot = NULL; }
            if (!HvMultiplyU64(count, sizeof(*snapshot), &bytes) || bytes > MAXULONG_PTR) {
                status = STATUS_INTEGER_OVERFLOW;
                break;
            }
            snapshot = static_cast<HV_ADAPTER_INFO*>(ExAllocatePool2(
                POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, (SIZE_T)bytes, INFO_TAG));
            if (snapshot == NULL) [[unlikely]] { status = STATUS_INSUFFICIENT_RESOURCES; break; }
            allocatedCount = count;
            continue;
        }
        // Lifetime, metadata and running_count are one consistent snapshot.
        // Copying the list is still O(count) under this lock; encoding every
        // integer/name is deliberately deferred until after releasing it.
        count = 0;
        for (entry = Adapters.Flink; entry != &Adapters; entry = entry->Flink) {
            HV_ADAPTER* a = CONTAINING_RECORD(entry, HV_ADAPTER, AdapterLink);
            RtlCopyMemory(&snapshot[count++], &a->Info, sizeof(*snapshot));
        }
        NT_ASSERT(count == AdapterCount);
        KeReleaseSpinLock(&AdapterInfoLock, irql);
        HvEncodeAdapterInfoHeader(out, count, running);
        for (i = 0; i < count; ++i)
            HvEncodeAdapterInfo(out + HV_ADAPTER_INFO_HEADER_SIZE + (SIZE_T)i * HV_ADAPTER_INFO_ENTRY_SIZE, &snapshot[i]);
        *transferred = size;
        status = STATUS_SUCCESS;
        break;
    }
    if (snapshot != NULL) ExFreePoolWithTag(snapshot, INFO_TAG);
    return status;
}
_Use_decl_annotations_
void HvStatus(NDIS_HANDLE context, PNDIS_STATUS_INDICATION status) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    if (status->StatusCode == NDIS_STATUS_LINK_STATE && status->StatusBuffer != NULL &&
        status->StatusBufferSize >= NDIS_SIZEOF_LINK_STATE_REVISION_1) {
        const NDIS_LINK_STATE* link = static_cast<const NDIS_LINK_STATE*>(status->StatusBuffer);
        if (link->Header.Type == NDIS_OBJECT_TYPE_DEFAULT && link->Header.Revision >= NDIS_LINK_STATE_REVISION_1 &&
            link->Header.Size >= NDIS_SIZEOF_LINK_STATE_REVISION_1 && link->Header.Size <= status->StatusBufferSize) {
            KIRQL irql;
            KeAcquireSpinLock(&AdapterInfoLock, &irql);
            a->Info.Flags |= HV_ADAPTER_LINK_STATE_VALID;
            a->Info.MediaConnectState = link->MediaConnectState;
            a->Info.MediaDuplexState = link->MediaDuplexState;
            a->Info.XmitLinkSpeed = link->XmitLinkSpeed;
            a->Info.RcvLinkSpeed = link->RcvLinkSpeed;
            a->Info.AutoNegotiationFlags = link->AutoNegotiationFlags;
            KeReleaseSpinLock(&AdapterInfoLock, irql);
        }
    }
    NdisFIndicateStatus(a->Filter, status);
}
_Use_decl_annotations_
NDIS_STATUS HvFilterAttach(NDIS_HANDLE filter, NDIS_HANDLE context, PNDIS_FILTER_ATTACH_PARAMETERS p) {
    HV_ADAPTER* a;
    NDIS_FILTER_ATTRIBUTES attributes = {0};
    NET_BUFFER_LIST_POOL_PARAMETERS nblPool = {0};
    NET_BUFFER_POOL_PARAMETERS nbPool = {0};
    NDIS_STATUS status = NDIS_STATUS_RESOURCES;
    GUID interfaceGuid;
    KIRQL irql;
    ULONG bucket;
    UNREFERENCED_PARAMETER(context);
    // No fallback by friendly name, media type or wildcard. Missing/stale target
    // configuration means no adapter attaches; optional LWFs are bypassed by NDIS.
    if (p->MiniportMediaType != NdisMedium802_3 ||
        !TargetAdapter(p, &interfaceGuid)) return NDIS_STATUS_NOT_SUPPORTED;
    a = static_cast<HV_ADAPTER*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*a), TAG));
    if (a == NULL) [[unlikely]] return NDIS_STATUS_RESOURCES;
    a->Filter = filter; a->InterfaceIndex = p->BaseMiniportIfIndex;
    a->Id = (UINT64)InterlockedIncrement64(&NextAdapter);
    CaptureAttachInfo(a, p, &interfaceGuid);
    NdisAllocateSpinLock(&a->Lock);
    for (bucket = 0; bucket < HV_TOKEN_BUCKET_COUNT; ++bucket) InitializeListHead(&a->Tokens[bucket]);
    ExInitializeRundownProtection(&a->OidRundown);
    a->ClassificationLock = NdisAllocateRWLock(filter);
    if (a->ClassificationLock == NULL) [[unlikely]] goto FreeLock;
    nblPool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nblPool.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPool.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPool.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    nblPool.PoolTag = TAG;
    a->NblPool = NdisAllocateNetBufferListPool(filter, &nblPool);
    if (a->NblPool == NULL) [[unlikely]] goto FreeRw;
    nbPool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbPool.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPool.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPool.PoolTag = TAG;
    a->NbPool = NdisAllocateNetBufferPool(filter, &nbPool);
    if (a->NbPool == NULL) [[unlikely]] goto FreeNblPool;
    if (!HvAttach(a->InterfaceIndex)) goto FreeNbPool;
    attributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attributes.Header.Size = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
    status = NdisFSetAttributes(filter, a, &attributes);
    if (status == NDIS_STATUS_SUCCESS) {
        KeAcquireSpinLock(&AdapterInfoLock, &irql);
        if (!HvAddU64(AdapterCount, 1, &AdapterCount)) hv_bugcheck();
        InsertTailList(&Adapters, &a->AdapterLink);
        KeReleaseSpinLock(&AdapterInfoLock, irql);
        return status;
    }
    HvDetach(a->InterfaceIndex);
FreeNbPool:
    NdisFreeNetBufferPool(a->NbPool);
FreeNblPool:
    NdisFreeNetBufferListPool(a->NblPool);
FreeRw:
    NdisFreeRWLock(a->ClassificationLock);
FreeLock:
    NdisFreeSpinLock(&a->Lock); ExFreePoolWithTag(a, TAG); return status;
}
_Use_decl_annotations_
NDIS_STATUS HvFilterRestart(NDIS_HANDLE context, PNDIS_FILTER_RESTART_PARAMETERS parameters) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    if (!HvRestart(a->InterfaceIndex)) return NDIS_STATUS_FAILURE;
    CaptureRestartInfo(a, parameters);
    SetFilterRunning(a, TRUE);
    return NDIS_STATUS_SUCCESS;
}
_Use_decl_annotations_
NDIS_STATUS HvFilterPause(NDIS_HANDLE context, PNDIS_FILTER_PAUSE_PARAMETERS parameters) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    NDIS_STATUS status;
    KIRQL irql;
    SetFilterRunning(a, FALSE);
    KeAcquireSpinLock(&AdapterInfoLock, &irql);
    a->Info.Flags |= HV_ADAPTER_PAUSE_VALID;
    a->Info.PauseReason = parameters->PauseReason;
    a->Info.PauseFlags = parameters->Flags;
    KeReleaseSpinLock(&AdapterInfoLock, irql);
    Invalidate(a);
    NdisAcquireSpinLock(&a->Lock);
    status = a->Active == 0 ? NDIS_STATUS_SUCCESS : NDIS_STATUS_PENDING;
    if (status == NDIS_STATUS_PENDING) a->PausePending = TRUE;
    NdisReleaseSpinLock(&a->Lock);
    return status;
}
_Use_decl_annotations_
void HvFilterDetach(NDIS_HANDLE context) {
    HV_ADAPTER* a = static_cast<HV_ADAPTER*>(context);
    KIRQL irql;
    if (a->Running || a->Active != 0 || !TokensEmpty(a)) hv_bugcheck();
    KeAcquireSpinLock(&AdapterInfoLock, &irql);
    RemoveEntryList(&a->AdapterLink);
    if (!HvSubtractU64(AdapterCount, 1, &AdapterCount)) hv_bugcheck();
    KeReleaseSpinLock(&AdapterInfoLock, irql);
    ExWaitForRundownProtectionRelease(&a->OidRundown);
    HvDetach(a->InterfaceIndex);
    NdisFreeNetBufferPool(a->NbPool); NdisFreeNetBufferListPool(a->NblPool);
    NdisFreeRWLock(a->ClassificationLock); NdisFreeSpinLock(&a->Lock); ExFreePoolWithTag(a, TAG);
}
_Use_decl_annotations_
NTSTATUS HvDispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR transferred = 0;
    BOOLEAN queueRead = FALSE, cancelReads = FALSE;
    UNREFERENCED_PARAMETER(device);
    // Buffered reads wait in a cancel-safe queue; other I/O stays synchronous.
    ExAcquireFastMutex(&IoMutex);
    switch (stack->MajorFunction) {
    case IRP_MJ_CREATE:
        if (Stopping) status = STATUS_DELETE_PENDING;
        else if (Client != NULL) status = STATUS_SHARING_VIOLATION;
        else {Client = stack->FileObject; SetReadClient(Client); OpenClassificationSession();}
        break;
    case IRP_MJ_CLEANUP:
        if (Client == stack->FileObject) {SetReadClient(NULL); CloseClassificationSession(); Client = NULL;}
        cancelReads = TRUE;
        break;
    case IRP_MJ_CLOSE: break;
    default:
        if (Stopping || Client != stack->FileObject) {status = STATUS_DEVICE_NOT_CONNECTED; break;}
        if (stack->MajorFunction == IRP_MJ_READ) {
            ULONG n = stack->Parameters.Read.Length;
            if (n && irp->AssociatedIrp.SystemBuffer == NULL) status = STATUS_INVALID_PARAMETER;
            else if (n != 0) {
                if (!ExAcquireRundownProtection(&ReadRundown)) status = STATUS_DEVICE_NOT_CONNECTED;
                else queueRead = TRUE;
            }
        } else if (stack->MajorFunction == IRP_MJ_WRITE) {
            status = HvWrite(static_cast<const UCHAR*>(irp->AssociatedIrp.SystemBuffer), stack->Parameters.Write.Length);
            if (NT_SUCCESS(status)) transferred = stack->Parameters.Write.Length;
            if (!ReadOnline) cancelReads = TRUE;
        } else if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
            ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
            if (code == VERSION_IOCTL) {
                if (!HvIoctlInputEmpty(stack->Parameters.DeviceIoControl.InputBufferLength)) status = STATUS_INVALID_PARAMETER;
                else if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(HV_API_VERSION)) status = STATUS_BUFFER_TOO_SMALL;
                else {RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, HV_API_VERSION, sizeof(HV_API_VERSION)); transferred = sizeof(HV_API_VERSION);}
            } else if (code == SHUTDOWN_IOCTL) {
                if (!HvIoctlInputEmpty(stack->Parameters.DeviceIoControl.InputBufferLength)) status = STATUS_INVALID_PARAMETER;
                else {CloseClassificationSession(); cancelReads = TRUE;}
            }
            else if (code == FILTERED_DEVICE_COUNT_IOCTL) {
                if (!HvIoctlInputEmpty(stack->Parameters.DeviceIoControl.InputBufferLength)) status = STATUS_INVALID_PARAMETER;
                else if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) status = STATUS_BUFFER_TOO_SMALL;
                else if (irp->AssociatedIrp.SystemBuffer == NULL) status = STATUS_INVALID_PARAMETER;
                else {
                    UINT64 count = (UINT64)InterlockedCompareExchange64(&FilteredDeviceCount, 0, 0);
                    if (count > MAXULONG) status = STATUS_INTEGER_OVERFLOW;
                    else {
                        HvInfoWrite32(static_cast<UCHAR*>(irp->AssociatedIrp.SystemBuffer), (ULONG)count);
                        transferred = sizeof(ULONG);
                    }
                }
            } else if (code == ADAPTER_INFO_IOCTL) {
                if (!HvIoctlInputEmpty(stack->Parameters.DeviceIoControl.InputBufferLength)) status = STATUS_INVALID_PARAMETER;
                else status = QueryAdapterInfo(static_cast<UCHAR*>(irp->AssociatedIrp.SystemBuffer),
                    stack->Parameters.DeviceIoControl.OutputBufferLength, &transferred);
            } else status = STATUS_NOT_SUPPORTED;
        } else status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    ExReleaseFastMutex(&IoMutex);
    if (cancelReads) CancelReads(stack->FileObject);
    if (queueRead) {
        // No locks across CSQ insertion: an already-cancelled IRP can complete
        // inline. Never touch it after successful insertion.
        IoMarkIrpPending(irp);
        status = IoCsqInsertIrpEx(&ReadCsq, irp, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            CompleteRead(irp, status, 0);
            return status;
        }
        ScheduleRead();
        return STATUS_PENDING;
    }
    irp->IoStatus.Status = status; irp->IoStatus.Information = transferred;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}
static VOID PendingDpc(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2) {
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2);
    if (!Stopping) HvDrain();
}
static VOID CacheDpc(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2) {
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2);
    hv_request_cache_cleanup();
}
static ULONG ReadDword(HANDLE key, PCWSTR name, ULONG fallback) {
    UNICODE_STRING value;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG size;
    RtlInitUnicodeString(&value, name);
    if (NT_SUCCESS(ZwQueryValueKey(key, &value, KeyValuePartialInformation, buffer, sizeof(buffer), &size)) &&
        info->Type == REG_DWORD && info->DataLength == sizeof(ULONG)) return *(ULONG*)info->Data;
    return fallback;
}
static UINT64 ReadQword(HANDLE key, PCWSTR name) {
    UNICODE_STRING value;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(UINT64)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG size;
    UINT64 result = 0;
    RtlInitUnicodeString(&value, name);
    if (NT_SUCCESS(ZwQueryValueKey(key, &value, KeyValuePartialInformation, buffer, sizeof(buffer), &size)) &&
        info->Type == REG_QWORD && info->DataLength == sizeof(result)) RtlCopyMemory(&result, info->Data, sizeof(result));
    return result;
}
static BOOLEAN TargetAdapter(PNDIS_FILTER_ATTACH_PARAMETERS p, GUID* interfaceGuid) {
    UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\HyperVXNdisFilter\\Lwf");
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"TargetInterfaceGuid");
    UNICODE_STRING text;
    OBJECT_ATTRIBUTES attributes;
    HANDLE key;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 40 * sizeof(WCHAR)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG size;
    GUID target, actual;
    BOOLEAN match = FALSE;
    InitializeObjectAttributes(&attributes, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attributes))) return FALSE;
    if (ReadDword(key, L"ConfigVersion", 0) != 2 || ReadDword(key, L"AllowBindings", 0) != 1) goto Exit;
    if (!HvTargetMatches(ReadQword(key, L"TargetNetLuid"), p->BaseMiniportNetLuid.Value)) goto Exit;
    if (!NT_SUCCESS(ZwQueryValueKey(key, &name, KeyValuePartialInformation, buffer, sizeof(buffer), &size)) ||
        info->Type != REG_SZ || info->DataLength != 39 * sizeof(WCHAR)) goto Exit;
    text.Buffer = (PWCHAR)info->Data;
    text.Length = 38 * sizeof(WCHAR); text.MaximumLength = 39 * sizeof(WCHAR);
    if (text.Buffer[38] != 0 || !NT_SUCCESS(RtlGUIDFromString(&text, &target))) goto Exit;
    if (!NT_SUCCESS(ConvertInterfaceLuidToGuid(&p->BaseMiniportNetLuid, &actual))) goto Exit;
    match = RtlEqualMemory(&target, &actual, sizeof(GUID));
    if (match) *interfaceGuid = actual;
Exit:
    ZwClose(key); return match;
}
static void ReadConfiguration(PUNICODE_STRING registry) {
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"Parameters");
    HANDLE service = NULL, parameters = NULL;
    InitializeObjectAttributes(&attributes, registry, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (!NT_SUCCESS(ZwOpenKey(&service, KEY_READ, &attributes))) return;
    InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, service, NULL);
    if (NT_SUCCESS(ZwOpenKey(&parameters, KEY_READ, &attributes))) {
        HvConfigure(ReadDword(parameters,L"DecisionTimeoutMs",HV_DEFAULT_DECISION_TIMEOUT_MS),
            ReadDword(parameters,L"CacheTtlMs",60000), ReadDword(parameters,L"FailClosed",HV_DEFAULT_FAIL_CLOSED));
        ZwClose(parameters);
    }
    ZwClose(service);
}
static void SignalDriverReady(void) {
    UNICODE_STRING name = RTL_CONSTANT_STRING(HV_READY_EVENT_KERNEL_NAME);
    OBJECT_ATTRIBUTES attributes;
    SECURITY_DESCRIPTOR descriptor;
    struct {
        ACL Header;
        UCHAR Aces[2 * (sizeof(ACCESS_ALLOWED_ACE) + SECURITY_MAX_SID_SIZE)];
    } acl;
    NTSTATUS status;
    status = RtlCreateSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status)) goto Failed;
    status = RtlCreateAcl(&acl.Header, sizeof(acl), ACL_REVISION);
    if (!NT_SUCCESS(status)) goto Failed;
    status = RtlAddAccessAllowedAce(&acl.Header, ACL_REVISION, EVENT_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (!NT_SUCCESS(status)) goto Failed;
    status = RtlAddAccessAllowedAce(&acl.Header, ACL_REVISION, EVENT_ALL_ACCESS, SeExports->SeAliasAdminsSid);
    if (!NT_SUCCESS(status)) goto Failed;
    status = RtlSetDaclSecurityDescriptor(&descriptor, TRUE, &acl.Header, FALSE);
    if (!NT_SUCCESS(status)) goto Failed;
    descriptor.Control |= SE_DACL_PROTECTED;
    InitializeObjectAttributes(&attributes, &name,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, &descriptor);
    status = ZwCreateEvent(&ReadyEventHandle, EVENT_MODIFY_STATE | SYNCHRONIZE,
        &attributes, NotificationEvent, FALSE);
    if (!NT_SUCCESS(status)) goto Failed;
    status = ObReferenceObjectByHandle(ReadyEventHandle, EVENT_MODIFY_STATE,
        *ExEventObjectType, KernelMode, (PVOID*)&ReadyEvent, NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(ReadyEventHandle); ReadyEventHandle = NULL;
        goto Failed;
    }
    KeSetEvent(ReadyEvent, IO_NO_INCREMENT, FALSE);
    return;
Failed:
    // At system boot BaseNamedObjects may not exist yet, so no monitor can be
    // waiting there. Notification failure must not disable an otherwise ready LWF.
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_WARNING_LEVEL,
        "HyperVXNdisFilter: driver-ready event unavailable: 0x%08lX\n", (ULONG)status);
}
NTSTATUS hv_initialize(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    NDIS_FILTER_DRIVER_CHARACTERISTICS c = {0};
    NDIS_DEVICE_OBJECT_ATTRIBUTES attributes = {0};
    PDRIVER_DISPATCH dispatch[IRP_MJ_MAXIMUM_FUNCTION + 1] = {0};
    NDIS_STRING device = RTL_CONSTANT_STRING(L"\\Device\\HyperVXNdisFilter");
    NDIS_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\HyperVXNdisFilter");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    NDIS_STATUS status;
    KeInitializeSpinLock(&PolicyLock); ExInitializeFastMutex(&IoMutex);
    KeInitializeTimer(&PendingTimer); KeInitializeDpc(&PendingTimerDpc, PendingDpc, NULL);
    KeInitializeTimer(&CacheTimer); KeInitializeDpc(&CacheTimerDpc, CacheDpc, NULL);
    KeInitializeSpinLock(&AdapterInfoLock); InitializeListHead(&Adapters);
    KeInitializeSpinLock(&ReadLock); InitializeListHead(&ReadIrps);
    ExInitializeRundownProtection(&ClassificationRundown);
    ExInitializeRundownProtection(&ReadRundown);
    ExInitializeRundownProtection(&CacheRundown);
    status = IoCsqInitializeEx(&ReadCsq, ReadInsert, ReadRemove, ReadPeek,
        HvReadQueueAcquire, HvReadQueueRelease, ReadCancelled);
    if (!NT_SUCCESS(status)) return status;
    ReadConfiguration(registry);
    c.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    c.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
    c.Header.Size = NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2;
    c.MajorNdisVersion = 6; c.MinorNdisVersion = 40;
    c.MajorDriverVersion = 0; c.MinorDriverVersion = 3;
    c.FriendlyName = Friendly; c.UniqueName = Unique; c.ServiceName = ServiceName;
    c.AttachHandler = HvFilterAttach; c.DetachHandler = HvFilterDetach;
    c.RestartHandler = HvFilterRestart; c.PauseHandler = HvFilterPause;
    c.SendNetBufferListsHandler = HvSend; c.SendNetBufferListsCompleteHandler = HvSendComplete;
    c.CancelSendNetBufferListsHandler = HvCancelSend;
    c.ReceiveNetBufferListsHandler = HvReceive; c.ReturnNetBufferListsHandler = HvReturn;
    c.OidRequestHandler = HvOid; c.OidRequestCompleteHandler = HvOidComplete;
    c.CancelOidRequestHandler = HvCancelOid; c.NetPnPEventHandler = HvPnp; c.StatusHandler = HvStatus;
    // Direct OID callbacks remain NULL: NDIS bypasses this non-intercepting LWF.
    driver->DriverUnload = HvUnload;
    status = NdisFRegisterFilterDriver(driver, driver, &c, &DriverHandle);
    if (status != NDIS_STATUS_SUCCESS) return status;
    dispatch[IRP_MJ_CREATE] = HvDispatch; dispatch[IRP_MJ_CLEANUP] = HvDispatch;
    dispatch[IRP_MJ_CLOSE] = HvDispatch; dispatch[IRP_MJ_READ] = HvDispatch;
    dispatch[IRP_MJ_WRITE] = HvDispatch; dispatch[IRP_MJ_DEVICE_CONTROL] = HvDispatch;
    attributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    attributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    attributes.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    attributes.DeviceName = &device; attributes.SymbolicName = &link;
    attributes.MajorFunctions = dispatch; attributes.DefaultSDDLString = &sddl;
    status = NdisRegisterDeviceEx(DriverHandle, &attributes, &ControlDevice, &DeviceHandle);
    if (status != NDIS_STATUS_SUCCESS) {NdisFDeregisterFilterDriver(DriverHandle); DriverHandle = NULL; return status;}
    ReadWorkItem = IoAllocateWorkItem(ControlDevice);
    CacheWorkItem = IoAllocateWorkItem(ControlDevice);
    if (ReadWorkItem == NULL || CacheWorkItem == NULL) [[unlikely]] {
        if (ReadWorkItem != NULL) {IoFreeWorkItem(ReadWorkItem); ReadWorkItem = NULL;}
        if (CacheWorkItem != NULL) {IoFreeWorkItem(CacheWorkItem); CacheWorkItem = NULL;}
        NdisDeregisterDeviceEx(DeviceHandle); NdisFDeregisterFilterDriver(DriverHandle);
        DriverHandle = NULL; return STATUS_INSUFFICIENT_RESOURCES;
    }
    ScheduleRead();
    ControlDevice->Flags |= DO_BUFFERED_IO;
    ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    SignalDriverReady(); // Publish only after the control device and timer are ready.
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
void HvUnload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);
    if (ReadyEvent != NULL) KeClearEvent(ReadyEvent);
    ExAcquireFastMutex(&IoMutex); InterlockedExchange(&Stopping, TRUE);
    SetReadClient(NULL); CloseClassificationSession(); Client = NULL; ExReleaseFastMutex(&IoMutex);
    CancelReads(NULL);
    KeCancelTimer(&PendingTimer); KeCancelTimer(&CacheTimer); KeFlushQueuedDpcs();
    ExWaitForRundownProtectionRelease(&ReadRundown);
    ExWaitForRundownProtectionRelease(&CacheRundown);
    IoFreeWorkItem(ReadWorkItem); ReadWorkItem = NULL;
    IoFreeWorkItem(CacheWorkItem); CacheWorkItem = NULL;
    NdisFDeregisterFilterDriver(DriverHandle);
    NdisDeregisterDeviceEx(DeviceHandle);
    if (ReadyEvent != NULL) {ObDereferenceObject(ReadyEvent); ReadyEvent = NULL;}
    if (ReadyEventHandle != NULL) {ZwClose(ReadyEventHandle); ReadyEventHandle = NULL;}
}

} // extern "C"
