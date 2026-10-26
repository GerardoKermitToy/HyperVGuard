// WDK ABI shim. Rust owns parsing, bounded policy queues, wire API and verdicts.
#include <ntifs.h>
#include <ndis.h>
#include <netioapi.h>
#include "lwf_contract.h"
#include "driver_ready.h"

#define TAG 'gVHH'
#define MAX_TOKENS 2048
#define MAX_EVENT_POOL_BYTES (16u * 1024u * 1024u)
#define VERSION_IOCTL CTL_CODE(40000, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define SHUTDOWN_IOCTL CTL_CODE(40000, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define FILTERED_DEVICE_COUNT_IOCTL CTL_CODE(40000, 0x802, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

typedef struct _HV_ADAPTER HV_ADAPTER;
typedef struct _HV_TOKEN {
    LIST_ENTRY Link;
    HV_ADAPTER* Adapter;
    PNET_BUFFER_LIST Nbl;
    NDIS_PORT_NUMBER Port;
    ULONG Flags, Direction, CopyBytes;
    UINT64 Epoch;
    BOOLEAN Copied, Forwarded;
} HV_TOKEN;
struct _HV_ADAPTER {
    NDIS_HANDLE Filter, NblPool, NbPool;
    NDIS_SPIN_LOCK Lock;
    PNDIS_RW_LOCK_EX ClassificationLock;
    EX_RUNDOWN_REF OidRundown;
    LIST_ENTRY Tokens;
    UINT64 Id, Epoch;
    LONG Active, TokenCount;
    ULONG CopyBytes;
    BOOLEAN Running, PausePending;
};

extern void HvConfigure(ULONG, ULONG, ULONG);
extern ULONG HvAttach(UINT64);
extern ULONG HvRestart(UINT64);
extern void HvInvalidate(UINT64, ULONG);
extern void HvDetach(UINT64);
extern void HvDrain(void);
extern void HvTick(void);
extern void HvConnect(void);
extern void HvDisconnect(void);
extern void HvCancel(UINT64, ULONG_PTR);
extern int HvClassify(ULONG_PTR, UINT64, UINT64, ULONG, ULONG, ULONG_PTR);
extern void HvResourceDrop(void);
extern ULONG HvRead(UCHAR*, ULONG);
extern NTSTATUS HvWrite(const UCHAR*, ULONG);

static NDIS_HANDLE DriverHandle, DeviceHandle;
static PDEVICE_OBJECT ControlDevice;
static HANDLE ReadyEventHandle;
static PKEVENT ReadyEvent;
static KSPIN_LOCK PolicyLock;
static FAST_MUTEX IoMutex;
static PFILE_OBJECT Client;
static volatile LONG Stopping;
static KTIMER Timer;
static KDPC TimerDpc;
static volatile LONG64 NextAdapter;
static volatile LONG64 EventPoolBytes;
static volatile LONG FilteredDeviceCount;
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
static BOOLEAN TargetAdapter(PNDIS_FILTER_ATTACH_PARAMETERS p);

// A bounded cancel-safe queue. NDIS only schedules the reader; buffered copies
// and IRP completions run outside the policy/NDIS locks on a system work item.
#define MAX_PENDING_READS 16
static IO_CSQ ReadCsq;
static LIST_ENTRY ReadIrps;
static KSPIN_LOCK ReadLock;
static PFILE_OBJECT ReadClient;
static EX_RUNDOWN_REF ReadRundown;
static PIO_WORKITEM ReadWorkItem;
static volatile LONG ReadPending, ReadReady, ReadOnline, ReadScheduled;
static IO_CSQ_INSERT_IRP_EX ReadInsert;
static IO_CSQ_REMOVE_IRP ReadRemove;
static IO_CSQ_PEEK_NEXT_IRP ReadPeek;
static IO_CSQ_ACQUIRE_LOCK HvReadQueueAcquire;
static IO_CSQ_RELEASE_LOCK HvReadQueueRelease;
static IO_CSQ_COMPLETE_CANCELED_IRP ReadCancelled;
static IO_WORKITEM_ROUTINE ReadWorker;

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
    if (ReadPending >= MAX_PENDING_READS) return STATUS_DEVICE_BUSY;
    InsertTailList(&ReadIrps, &irp->Tail.Overlay.ListEntry);
    InterlockedIncrement(&ReadPending);
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
static void ReadRemove(PIO_CSQ csq, PIRP irp) {
    UNREFERENCED_PARAMETER(csq);
    RemoveEntryList(&irp->Tail.Overlay.ListEntry);
    InterlockedDecrement(&ReadPending);
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
// Called only with PolicyLock held. No copying, completion, or NDIS calls here.
void hv_read_state(ULONG ready, ULONG online) {
    if (ReadReady != (LONG)ready) InterlockedExchange(&ReadReady, (LONG)ready);
    if (ReadOnline != (LONG)online) InterlockedExchange(&ReadOnline, (LONG)online);
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
        else bytes = HvRead(irp->AssociatedIrp.SystemBuffer,
            min(IoGetCurrentIrpStackLocation(irp)->Parameters.Read.Length, 65536));
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
void* hv_allocate(SIZE_T size) {
    LONG64 used;
    void* data;
    if (size == 0 || size > MAX_EVENT_POOL_BYTES) return NULL;
    used = InterlockedCompareExchange64(&EventPoolBytes, 0, 0);
    for (;;) {
        LONG64 previous;
        if (used > MAX_EVENT_POOL_BYTES - (LONG64)size) return NULL;
        previous = InterlockedCompareExchange64(&EventPoolBytes, used + (LONG64)size, used);
        if (previous == used) break;
        used = previous;
    }
    data = ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, size, TAG);
    if (data == NULL) InterlockedAdd64(&EventPoolBytes, -(LONG64)size);
    return data;
}
void hv_free(void* data, SIZE_T size) {
    LONG64 remaining;
    ExFreePoolWithTag(data, TAG);
    remaining = InterlockedAdd64(&EventPoolBytes, -(LONG64)size);
    NT_ASSERT(remaining >= 0);
    UNREFERENCED_PARAMETER(remaining);
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
static void ReleaseActive(HV_ADAPTER* a, LONG count) {
    BOOLEAN complete = FALSE;
    NDIS_HANDLE filter = a->Filter;
    NdisAcquireSpinLock(&a->Lock);
    NT_ASSERT(a->Active >= count);
    a->Active -= count;
    if (a->Active == 0 && a->PausePending) { a->PausePending = FALSE; complete = TRUE; }
    NdisReleaseSpinLock(&a->Lock);
    // Last access to a: PauseComplete may synchronously cause detach/free.
    if (complete) NdisFPauseComplete(filter);
}
static void SetFilterRunning(HV_ADAPTER* a, BOOLEAN running) {
    LONG count;
    NdisAcquireSpinLock(&a->Lock);
    count = InterlockedAdd(&FilteredDeviceCount, HvSetFilterRunning(&a->Running, running));
    NT_ASSERT(count >= 0);
    UNREFERENCED_PARAMETER(count);
    NdisReleaseSpinLock(&a->Lock);
}
static BOOLEAN BeginIo(HV_ADAPTER* a) {
    BOOLEAN running;
    NdisAcquireSpinLock(&a->Lock);
    running = a->Running;
    ++a->Active; // callback guard also protects rejects while pausing
    NdisReleaseSpinLock(&a->Lock);
    return running;
}
static void FreeReceiveCopy(HV_ADAPTER* a, PNET_BUFFER_LIST nbl, ULONG bytes) {
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
    NdisAcquireSpinLock(&a->Lock);
    NT_ASSERT(a->CopyBytes >= bytes);
    a->CopyBytes -= bytes;
    NdisReleaseSpinLock(&a->Lock);
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
static PNET_BUFFER_LIST CopyReceive(HV_ADAPTER* a, PNET_BUFFER_LIST source, ULONG* copyBytes) {
    PNET_BUFFER nb, tail = NULL;
    PNET_BUFFER_LIST copy;
    ULONG bytes = 0, count = 0;
    if (!CopyMetadataSupported(source)) return NULL;
    for (nb = NET_BUFFER_LIST_FIRST_NB(source); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
        ULONG length = NET_BUFFER_DATA_LENGTH(nb);
        if (!HvCopyFits(count, bytes, length)) return NULL;
        bytes += length; ++count;
    }
    if (count == 0) return NULL;
    NdisAcquireSpinLock(&a->Lock);
    if (!HvCopyPoolFits(a->CopyBytes, bytes)) { NdisReleaseSpinLock(&a->Lock); return NULL; }
    a->CopyBytes += bytes;
    NdisReleaseSpinLock(&a->Lock);
    copy = NdisAllocateNetBufferList(a->NblPool, 0, 0);
    if (copy == NULL) {
        NdisAcquireSpinLock(&a->Lock); a->CopyBytes -= bytes; NdisReleaseSpinLock(&a->Lock);
        return NULL;
    }
    NET_BUFFER_LIST_FIRST_NB(copy) = NULL;
    NET_BUFFER_LIST_NEXT_NBL(copy) = NULL;
    for (nb = NET_BUFFER_LIST_FIRST_NB(source); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
        ULONG length = NET_BUFFER_DATA_LENGTH(nb);
        void* storage = ExAllocatePool2(POOL_FLAG_NON_PAGED, length, TAG);
        void* data;
        PMDL mdl;
        PNET_BUFFER created;
        if (storage == NULL) goto Fail;
        data = NdisGetDataBuffer(nb, length, storage, 1, 0);
        if (data == NULL) { ExFreePoolWithTag(storage, TAG); goto Fail; }
        if (data != storage) RtlCopyMemory(storage, data, length);
        mdl = IoAllocateMdl(storage, length, FALSE, FALSE, NULL);
        if (mdl == NULL) { ExFreePoolWithTag(storage, TAG); goto Fail; }
        MmBuildMdlForNonPagedPool(mdl);
        created = NdisAllocateNetBuffer(a->NbPool, mdl, 0, length);
        if (created == NULL) { IoFreeMdl(mdl); ExFreePoolWithTag(storage, TAG); goto Fail; }
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
    *copyBytes = bytes;
    return copy;
Fail:
    FreeReceiveCopy(a, copy, bytes);
    return NULL;
}
static void ReleaseToken(HV_TOKEN* t) {
    HV_ADAPTER* a = t->Adapter;
    NdisAcquireSpinLock(&a->Lock); --a->TokenCount; NdisReleaseSpinLock(&a->Lock);
    ExFreePoolWithTag(t, TAG);
    ReleaseActive(a, 1);
}
static HV_TOKEN* CreateToken(HV_ADAPTER* a, PNET_BUFFER_LIST nbl, NDIS_PORT_NUMBER port,
    ULONG flags, ULONG direction, BOOLEAN resources) {
    HV_TOKEN* t;
    NdisAcquireSpinLock(&a->Lock);
    if (!a->Running || a->TokenCount >= MAX_TOKENS) { NdisReleaseSpinLock(&a->Lock); return NULL; }
    ++a->TokenCount; ++a->Active;
    NdisReleaseSpinLock(&a->Lock);
    t = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*t), TAG);
    if (t == NULL) {
        NdisAcquireSpinLock(&a->Lock); --a->TokenCount; NdisReleaseSpinLock(&a->Lock);
        ReleaseActive(a, 1); return NULL;
    }
    t->Adapter = a; t->Nbl = nbl; t->Port = port; t->Flags = flags;
    t->Direction = direction; t->Epoch = a->Epoch;
    if (resources) {
        t->Nbl = CopyReceive(a, nbl, &t->CopyBytes);
        if (t->Nbl == NULL) { ReleaseToken(t); return NULL; }
        t->Copied = TRUE;
        // The new storage has no shared-memory/header-split/queue assertions.
        t->Flags = 0;
    }
    NdisAcquireSpinLock(&a->Lock); InsertTailList(&a->Tokens, &t->Link); NdisReleaseSpinLock(&a->Lock);
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
    allow = finish == 0 && a->Running && t->Epoch == a->Epoch;
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
        FreeReceiveCopy(a, nbl, t->CopyBytes);
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
    if (n == 0) return 0;
    data = NdisGetDataBuffer(nb, n, out, 1, 0);
    if (data == NULL) return 0;
    if (data != out) RtlCopyMemory(out, data, n);
    *copied = n; *trusted = n; return 1;
}
static HV_TOKEN* TakeForwarded(HV_ADAPTER* a, PNET_BUFFER_LIST nbl, ULONG direction) {
    HV_TOKEN* t = NULL;
    LIST_ENTRY* entry;
    NdisAcquireSpinLock(&a->Lock);
    for (entry = a->Tokens.Flink; entry != &a->Tokens; entry = entry->Flink) {
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
    ULONG flags, ULONG direction, BOOLEAN resources, BOOLEAN admitted) {
    while (chain != NULL) {
        PNET_BUFFER_LIST nbl = chain;
        HV_TOKEN* t = NULL;
        LOCK_STATE_EX state;
        int result = 1;
        chain = NET_BUFFER_LIST_NEXT_NBL(nbl);
        // RESOURCES originals and their chain must be unchanged at callback exit.
        if (!resources) NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        if (admitted) {
            NdisAcquireRWLockRead(a->ClassificationLock, &state, 0);
            t = CreateToken(a, nbl, port, flags, direction, resources);
            if (t != NULL) {
                ULONG vlan = (ULONG)(ULONG_PTR)NET_BUFFER_LIST_INFO(t->Nbl, Ieee8021QNetBufferListInfo);
                ULONG_PTR cancel = direction == HV_DIRECTION_SEND ?
                    (ULONG_PTR)NDIS_GET_NET_BUFFER_LIST_CANCEL_ID(nbl) : 0;
                result = HvClassify((ULONG_PTR)t, a->Id, t->Epoch, direction, vlan, cancel);
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
    HV_ADAPTER* a = context;
    BOOLEAN admitted = BeginIo(a);
    ClassifyChain(a, chain, port, flags, HV_DIRECTION_SEND, FALSE, admitted);
    ReleaseActive(a, 1);
}
_Use_decl_annotations_
void HvSendComplete(NDIS_HANDLE context, PNET_BUFFER_LIST chain, ULONG flags) {
    HV_ADAPTER* a = context;
    NdisAcquireSpinLock(&a->Lock); ++a->Active; NdisReleaseSpinLock(&a->Lock);
    while (chain != NULL) {
        PNET_BUFFER_LIST nbl = chain;
        HV_TOKEN* t;
        chain = NET_BUFFER_LIST_NEXT_NBL(nbl); NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        t = TakeForwarded(a, nbl, HV_DIRECTION_SEND);
        NdisFSendNetBufferListsComplete(a->Filter, nbl, flags);
        if (t != NULL) ReleaseToken(t);
    }
    ReleaseActive(a, 1);
}
_Use_decl_annotations_
void HvCancelSend(NDIS_HANDLE context, PVOID cancel) {
    HV_ADAPTER* a = context;
    NdisAcquireSpinLock(&a->Lock); ++a->Active; NdisReleaseSpinLock(&a->Lock);
    HvCancel(a->Id, (ULONG_PTR)cancel);
    NdisFCancelSendNetBufferLists(a->Filter, cancel);
    ReleaseActive(a, 1);
}
_Use_decl_annotations_
void HvReceive(NDIS_HANDLE context, PNET_BUFFER_LIST chain, NDIS_PORT_NUMBER port, ULONG count, ULONG flags) {
    HV_ADAPTER* a = context;
    BOOLEAN admitted = BeginIo(a);
    UNREFERENCED_PARAMETER(count);
    ClassifyChain(a, chain, port, flags, HV_DIRECTION_RECEIVE,
        (flags & NDIS_RECEIVE_FLAGS_RESOURCES) != 0, admitted);
    ReleaseActive(a, 1);
}
_Use_decl_annotations_
void HvReturn(NDIS_HANDLE context, PNET_BUFFER_LIST chain, ULONG flags) {
    HV_ADAPTER* a = context;
    NdisAcquireSpinLock(&a->Lock); ++a->Active; NdisReleaseSpinLock(&a->Lock);
    while (chain != NULL) {
        PNET_BUFFER_LIST nbl = chain;
        HV_TOKEN* t;
        chain = NET_BUFFER_LIST_NEXT_NBL(nbl); NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        t = TakeForwarded(a, nbl, HV_DIRECTION_RECEIVE);
        if (t != NULL && t->Copied) FreeReceiveCopy(a, nbl, t->CopyBytes);
        else NdisFReturnNetBufferLists(a->Filter, nbl, flags);
        if (t != NULL) ReleaseToken(t);
    }
    ReleaseActive(a, 1);
}
static void Invalidate(HV_ADAPTER* a) {
    LOCK_STATE_EX state;
    NdisAcquireRWLockWrite(a->ClassificationLock, &state, 0);
    NdisAcquireSpinLock(&a->Lock); ++a->Epoch; NdisReleaseSpinLock(&a->Lock);
    HvInvalidate(a->Id, TRUE);
    NdisReleaseRWLock(a->ClassificationLock, &state);
    HvDrain(); // No NDIS call under the classification/policy locks.
}
_Use_decl_annotations_
NDIS_STATUS HvOid(NDIS_HANDLE context, PNDIS_OID_REQUEST r) {
    HV_ADAPTER* a = context;
    PNDIS_OID_REQUEST clone;
    NDIS_STATUS status;
    if (!ExAcquireRundownProtection(&a->OidRundown)) return NDIS_STATUS_CLOSING;
    status = NdisAllocateCloneOidRequest(a->Filter, r, TAG, &clone);
    if (status != NDIS_STATUS_SUCCESS) {ExReleaseRundownProtection(&a->OidRundown); return status;}
    *(PVOID*)&clone->SourceReserved[0] = r;
    status = NdisFOidRequest(a->Filter, clone);
    if (status != NDIS_STATUS_PENDING) HvOidComplete(a, clone, status);
    return NDIS_STATUS_PENDING;
}
_Use_decl_annotations_
void HvOidComplete(NDIS_HANDLE context, PNDIS_OID_REQUEST clone, NDIS_STATUS status) {
    HV_ADAPTER* a = context;
    PNDIS_OID_REQUEST original = *(PVOID*)&clone->SourceReserved[0];
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
    NdisFreeCloneOidRequest(a->Filter, clone);
    NdisFOidRequestComplete(a->Filter, original, status);
    ExReleaseRundownProtection(&a->OidRundown);
}
_Use_decl_annotations_
void HvCancelOid(NDIS_HANDLE context, PVOID id) {NdisFCancelOidRequest(((HV_ADAPTER*)context)->Filter, id);}
_Use_decl_annotations_
NDIS_STATUS HvPnp(NDIS_HANDLE context, PNET_PNP_EVENT_NOTIFICATION event) {
    return NdisFNetPnPEvent(((HV_ADAPTER*)context)->Filter, event);
}
_Use_decl_annotations_
void HvStatus(NDIS_HANDLE context, PNDIS_STATUS_INDICATION status) {
    NdisFIndicateStatus(((HV_ADAPTER*)context)->Filter, status);
}
_Use_decl_annotations_
NDIS_STATUS HvFilterAttach(NDIS_HANDLE filter, NDIS_HANDLE context, PNDIS_FILTER_ATTACH_PARAMETERS p) {
    HV_ADAPTER* a;
    NDIS_FILTER_ATTRIBUTES attributes = {0};
    NET_BUFFER_LIST_POOL_PARAMETERS nblPool = {0};
    NET_BUFFER_POOL_PARAMETERS nbPool = {0};
    NDIS_STATUS status = NDIS_STATUS_RESOURCES;
    UNREFERENCED_PARAMETER(context);
    // No fallback by friendly name, media type or wildcard. Missing/stale target
    // configuration means no adapter attaches; optional LWFs are bypassed by NDIS.
    if (p->MiniportMediaType != NdisMedium802_3 ||
        !TargetAdapter(p)) return NDIS_STATUS_NOT_SUPPORTED;
    a = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*a), TAG);
    if (a == NULL) return NDIS_STATUS_RESOURCES;
    a->Filter = filter; a->Epoch = 1;
    a->Id = (UINT64)InterlockedIncrement64(&NextAdapter);
    NdisAllocateSpinLock(&a->Lock); InitializeListHead(&a->Tokens); ExInitializeRundownProtection(&a->OidRundown);
    a->ClassificationLock = NdisAllocateRWLock(filter);
    if (a->ClassificationLock == NULL) goto FreeLock;
    nblPool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nblPool.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPool.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nblPool.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    nblPool.PoolTag = TAG;
    a->NblPool = NdisAllocateNetBufferListPool(filter, &nblPool);
    if (a->NblPool == NULL) goto FreeRw;
    nbPool.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbPool.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPool.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nbPool.PoolTag = TAG;
    a->NbPool = NdisAllocateNetBufferPool(filter, &nbPool);
    if (a->NbPool == NULL) goto FreeNblPool;
    if (!HvAttach(a->Id)) goto FreeNbPool;
    attributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    attributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    attributes.Header.Size = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
    status = NdisFSetAttributes(filter, a, &attributes);
    if (status == NDIS_STATUS_SUCCESS) return status;
    HvDetach(a->Id);
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
    HV_ADAPTER* a = context;
    UNREFERENCED_PARAMETER(parameters);
    if (!HvRestart(a->Id)) return NDIS_STATUS_FAILURE;
    SetFilterRunning(a, TRUE);
    return NDIS_STATUS_SUCCESS;
}
_Use_decl_annotations_
NDIS_STATUS HvFilterPause(NDIS_HANDLE context, PNDIS_FILTER_PAUSE_PARAMETERS parameters) {
    HV_ADAPTER* a = context;
    NDIS_STATUS status;
    UNREFERENCED_PARAMETER(parameters);
    SetFilterRunning(a, FALSE);
    Invalidate(a);
    NdisAcquireSpinLock(&a->Lock);
    status = a->Active == 0 ? NDIS_STATUS_SUCCESS : NDIS_STATUS_PENDING;
    if (status == NDIS_STATUS_PENDING) a->PausePending = TRUE;
    NdisReleaseSpinLock(&a->Lock);
    return status;
}
_Use_decl_annotations_
void HvFilterDetach(NDIS_HANDLE context) {
    HV_ADAPTER* a = context;
    NT_ASSERT(!a->Running && a->Active == 0 && IsListEmpty(&a->Tokens) && a->CopyBytes == 0);
    ExWaitForRundownProtectionRelease(&a->OidRundown);
    HvDetach(a->Id);
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
        else {Client = stack->FileObject; SetReadClient(Client); HvConnect();}
        break;
    case IRP_MJ_CLEANUP:
        if (Client == stack->FileObject) {SetReadClient(NULL); HvDisconnect(); Client = NULL;}
        cancelReads = TRUE;
        break;
    case IRP_MJ_CLOSE: break;
    default:
        if (Stopping || Client != stack->FileObject) {status = STATUS_DEVICE_NOT_CONNECTED; break;}
        if (stack->MajorFunction == IRP_MJ_READ) {
            ULONG n = min(stack->Parameters.Read.Length, 65536);
            if (n && irp->AssociatedIrp.SystemBuffer == NULL) status = STATUS_INVALID_PARAMETER;
            else if (n != 0) {
                if (!ExAcquireRundownProtection(&ReadRundown)) status = STATUS_DEVICE_NOT_CONNECTED;
                else queueRead = TRUE;
            }
        } else if (stack->MajorFunction == IRP_MJ_WRITE) {
            status = HvWrite(irp->AssociatedIrp.SystemBuffer, stack->Parameters.Write.Length);
            if (NT_SUCCESS(status)) transferred = stack->Parameters.Write.Length;
            if (!ReadOnline) cancelReads = TRUE;
        } else if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
            ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
            if (code == VERSION_IOCTL) {
                static const UCHAR version[4] = {0,3,1,0};
                if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(version)) status = STATUS_BUFFER_TOO_SMALL;
                else {RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, version, sizeof(version)); transferred = sizeof(version);}
            } else if (code == SHUTDOWN_IOCTL) {HvDisconnect(); cancelReads = TRUE;}
            else if (code == FILTERED_DEVICE_COUNT_IOCTL) {
                if (stack->Parameters.DeviceIoControl.InputBufferLength != 0) status = STATUS_INVALID_PARAMETER;
                else if (stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) status = STATUS_BUFFER_TOO_SMALL;
                else if (irp->AssociatedIrp.SystemBuffer == NULL) status = STATUS_INVALID_PARAMETER;
                else {
                    ULONG count = (ULONG)InterlockedCompareExchange(&FilteredDeviceCount, 0, 0);
                    UCHAR* out = irp->AssociatedIrp.SystemBuffer;
                    out[0] = (UCHAR)count; out[1] = (UCHAR)(count >> 8);
                    out[2] = (UCHAR)(count >> 16); out[3] = (UCHAR)(count >> 24);
                    transferred = sizeof(ULONG);
                }
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
        if (!NT_SUCCESS(status)) CompleteRead(irp, status, 0);
        else ScheduleRead();
        return STATUS_PENDING;
    }
    irp->IoStatus.Status = status; irp->IoStatus.Information = transferred;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return status;
}
static VOID TickDpc(PKDPC dpc, PVOID context, PVOID arg1, PVOID arg2) {
    UNREFERENCED_PARAMETER(dpc); UNREFERENCED_PARAMETER(context);
    UNREFERENCED_PARAMETER(arg1); UNREFERENCED_PARAMETER(arg2); HvTick();
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
static BOOLEAN TargetAdapter(PNDIS_FILTER_ATTACH_PARAMETERS p) {
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
        HvConfigure(ReadDword(parameters,L"DecisionTimeoutMs",2000),
            ReadDword(parameters,L"CacheTtlMs",60000), ReadDword(parameters,L"FailClosed",0));
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
    LARGE_INTEGER due;
    KeInitializeSpinLock(&PolicyLock); ExInitializeFastMutex(&IoMutex);
    KeInitializeSpinLock(&ReadLock); InitializeListHead(&ReadIrps);
    ExInitializeRundownProtection(&ReadRundown);
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
    if (ReadWorkItem == NULL) {
        NdisDeregisterDeviceEx(DeviceHandle); NdisFDeregisterFilterDriver(DriverHandle);
        DriverHandle = NULL; return STATUS_INSUFFICIENT_RESOURCES;
    }
    ScheduleRead();
    ControlDevice->Flags |= DO_BUFFERED_IO;
    ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;
    KeInitializeTimer(&Timer); KeInitializeDpc(&TimerDpc, TickDpc, NULL);
    due.QuadPart = -500000; KeSetTimerEx(&Timer, due, 50, &TimerDpc);
    SignalDriverReady(); // Publish only after the control device and timer are ready.
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
void HvUnload(PDRIVER_OBJECT driver) {
    UNREFERENCED_PARAMETER(driver);
    if (ReadyEvent != NULL) KeClearEvent(ReadyEvent);
    ExAcquireFastMutex(&IoMutex); InterlockedExchange(&Stopping, TRUE);
    SetReadClient(NULL); HvDisconnect(); Client = NULL; ExReleaseFastMutex(&IoMutex);
    CancelReads(NULL);
    ExWaitForRundownProtectionRelease(&ReadRundown);
    IoFreeWorkItem(ReadWorkItem); ReadWorkItem = NULL;
    KeCancelTimer(&Timer); KeFlushQueuedDpcs();
    NdisFDeregisterFilterDriver(DriverHandle);
    NdisDeregisterDeviceEx(DeviceHandle);
    if (ReadyEvent != NULL) {ObDereferenceObject(ReadyEvent); ReadyEvent = NULL;}
    if (ReadyEventHandle != NULL) {ZwClose(ReadyEventHandle); ReadyEventHandle = NULL;}
}
