// Bounded diagnostic IOCTL codec, shared with offline tests. Never copy native
// structure layout to userspace; every integer and UTF-16 code unit is LE.
#ifndef HYPERV_XNDIS_FILTER_ADAPTER_INFO_H
#define HYPERV_XNDIS_FILTER_ADAPTER_INFO_H

#include <stdint.h>

#define HV_ADAPTER_INFO_VERSION 1u
#define HV_ADAPTER_INFO_HEADER_SIZE 16u
#define HV_ADAPTER_INFO_ENTRY_SIZE 1760u
#define HV_ADAPTER_INFO_MAX_ADAPTERS 32u
#define HV_ADAPTER_INFO_NAME_CAPACITY 256u
#define HV_ADAPTER_INFO_MAC_CAPACITY 32u
#define HV_ADAPTER_INFO_MAX_SIZE (HV_ADAPTER_INFO_HEADER_SIZE + \
    HV_ADAPTER_INFO_MAX_ADAPTERS * HV_ADAPTER_INFO_ENTRY_SIZE)

#define HV_ADAPTER_RUNNING 0x01u
#define HV_ADAPTER_GENERAL_VALID 0x02u
#define HV_ADAPTER_CONNECTOR_VALID 0x04u
#define HV_ADAPTER_INSTANCE_NAME_TRUNCATED 0x08u
#define HV_ADAPTER_BASE_NAME_TRUNCATED 0x10u
#define HV_ADAPTER_FILTER_NAME_TRUNCATED 0x20u
#define HV_ADAPTER_LINK_STATE_VALID 0x40u
#define HV_ADAPTER_PAUSE_VALID 0x80u
#define HV_ADAPTER_INFO_KNOWN_FLAGS 0xffu

// Storage only, not a wire structure. GUID bytes use Windows GUID field order:
// Data1:u32 LE, Data2:u16 LE, Data3:u16 LE, Data4:8 bytes.
typedef struct _HV_ADAPTER_INFO {
    uint64_t ModuleId;
    uint32_t InterfaceIndex, FilterInterfaceIndex, LowerInterfaceIndex, Flags;
    uint64_t InterfaceLuid, FilterInterfaceLuid, LowerInterfaceLuid;
    uint8_t InterfaceGuid[16];
    uint32_t MediaType, PhysicalMedium, MediaConnectState, MediaDuplexState;
    uint64_t XmitLinkSpeed, RcvLinkSpeed;
    uint32_t Mtu, MacOptions, SupportedPacketFilters, MaxMulticastListSize;
    uint64_t MaxXmitLinkSpeed, MaxRcvLinkSpeed;
    uint32_t LookaheadSize, AccessType, ConnectionType, SupportedStatistics;
    uint32_t DataBackFillSize, ContextBackFillSize, RestartFlags, AttachFlags;
    uint32_t ConnectorPresent, MacAddressLength;
    uint8_t MacAddress[HV_ADAPTER_INFO_MAC_CAPACITY];
    uint32_t InstanceNameLength, BaseNameLength, FilterModuleNameLength;
    uint32_t AutoNegotiationFlags, PauseReason, PauseFlags;
    uint16_t InstanceName[HV_ADAPTER_INFO_NAME_CAPACITY];
    uint16_t BaseName[HV_ADAPTER_INFO_NAME_CAPACITY];
    uint16_t FilterModuleName[HV_ADAPTER_INFO_NAME_CAPACITY];
} HV_ADAPTER_INFO;

// Counted UTF-16 input; always terminate/zero the bounded destination and never
// cut a surrogate pair at the truncation boundary. Returns the stored length.
static inline uint32_t HvCopyAdapterName(uint16_t* out, const uint16_t* source,
    uint32_t length, uint32_t* flags, uint32_t truncatedFlag) {
    uint32_t i, copied = 0;
    for (i = 0; i < HV_ADAPTER_INFO_NAME_CAPACITY; ++i) out[i] = 0;
    if (source == 0) return 0;
    while (copied < length && copied < HV_ADAPTER_INFO_NAME_CAPACITY - 1 && source[copied] != 0) {
        out[copied] = source[copied];
        ++copied;
    }
    if (copied < length && source[copied] != 0) {
        *flags |= truncatedFlag;
        if (copied != 0 && out[copied - 1] >= 0xd800 && out[copied - 1] <= 0xdbff) out[--copied] = 0;
    }
    return copied;
}
static inline void HvInfoWrite32(uint8_t* out, uint32_t value) {
    unsigned int i;
    for (i = 0; i < 4; ++i) out[i] = (uint8_t)(value >> (8 * i));
}
static inline void HvInfoWrite64(uint8_t* out, uint64_t value) {
    unsigned int i;
    for (i = 0; i < 8; ++i) out[i] = (uint8_t)(value >> (8 * i));
}
static inline uint32_t HvAdapterInfoSize(uint32_t count) {
    return count <= HV_ADAPTER_INFO_MAX_ADAPTERS ?
        HV_ADAPTER_INFO_HEADER_SIZE + count * HV_ADAPTER_INFO_ENTRY_SIZE : 0;
}
static inline void HvEncodeAdapterInfoHeader(uint8_t* out, uint32_t count, uint32_t running) {
    HvInfoWrite32(out, HV_ADAPTER_INFO_VERSION);
    HvInfoWrite32(out + 4, HV_ADAPTER_INFO_ENTRY_SIZE);
    HvInfoWrite32(out + 8, count);
    HvInfoWrite32(out + 12, running);
}
static inline void HvEncodeAdapterInfo(uint8_t* out, const HV_ADAPTER_INFO* a) {
    unsigned int i;
    HvInfoWrite64(out, a->ModuleId);
    HvInfoWrite32(out + 8, a->InterfaceIndex);
    HvInfoWrite32(out + 12, a->FilterInterfaceIndex);
    HvInfoWrite32(out + 16, a->LowerInterfaceIndex);
    HvInfoWrite32(out + 20, a->Flags);
    HvInfoWrite64(out + 24, a->InterfaceLuid);
    HvInfoWrite64(out + 32, a->FilterInterfaceLuid);
    HvInfoWrite64(out + 40, a->LowerInterfaceLuid);
    for (i = 0; i < 16; ++i) out[48 + i] = a->InterfaceGuid[i];
    HvInfoWrite32(out + 64, a->MediaType);
    HvInfoWrite32(out + 68, a->PhysicalMedium);
    HvInfoWrite32(out + 72, a->MediaConnectState);
    HvInfoWrite32(out + 76, a->MediaDuplexState);
    HvInfoWrite64(out + 80, a->XmitLinkSpeed);
    HvInfoWrite64(out + 88, a->RcvLinkSpeed);
    HvInfoWrite32(out + 96, a->Mtu);
    HvInfoWrite32(out + 100, a->MacOptions);
    HvInfoWrite32(out + 104, a->SupportedPacketFilters);
    HvInfoWrite32(out + 108, a->MaxMulticastListSize);
    HvInfoWrite64(out + 112, a->MaxXmitLinkSpeed);
    HvInfoWrite64(out + 120, a->MaxRcvLinkSpeed);
    HvInfoWrite32(out + 128, a->LookaheadSize);
    HvInfoWrite32(out + 132, a->AccessType);
    HvInfoWrite32(out + 136, a->ConnectionType);
    HvInfoWrite32(out + 140, a->SupportedStatistics);
    HvInfoWrite32(out + 144, a->DataBackFillSize);
    HvInfoWrite32(out + 148, a->ContextBackFillSize);
    HvInfoWrite32(out + 152, a->RestartFlags);
    HvInfoWrite32(out + 156, a->AttachFlags);
    HvInfoWrite32(out + 160, a->ConnectorPresent);
    HvInfoWrite32(out + 164, a->MacAddressLength);
    for (i = 0; i < HV_ADAPTER_INFO_MAC_CAPACITY; ++i) out[168 + i] = a->MacAddress[i];
    HvInfoWrite32(out + 200, a->InstanceNameLength);
    HvInfoWrite32(out + 204, a->BaseNameLength);
    HvInfoWrite32(out + 208, a->FilterModuleNameLength);
    HvInfoWrite32(out + 212, a->AutoNegotiationFlags);
    HvInfoWrite32(out + 216, a->PauseReason);
    HvInfoWrite32(out + 220, a->PauseFlags);
    for (i = 0; i < HV_ADAPTER_INFO_NAME_CAPACITY; ++i) {
        out[224 + 2 * i] = (uint8_t)a->InstanceName[i];
        out[225 + 2 * i] = (uint8_t)(a->InstanceName[i] >> 8);
        out[736 + 2 * i] = (uint8_t)a->BaseName[i];
        out[737 + 2 * i] = (uint8_t)(a->BaseName[i] >> 8);
        out[1248 + 2 * i] = (uint8_t)a->FilterModuleName[i];
        out[1249 + 2 * i] = (uint8_t)(a->FilterModuleName[i] >> 8);
    }
}
#endif
