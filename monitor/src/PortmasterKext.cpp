// HyperVXNdisFilter adaptation of kext_client, 2026-10-25; see README.md and LICENSE.
#include "PortmasterKext.h"
#include "DriverProtocol.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <exception>
#include <new>
#include <string>
#include <thread>
#include <utility>

namespace pmkext {
namespace {

std::string LastErrorText(DWORD error) {
    return "error " + std::to_string(error);
}

// Every concurrent operation owns its event and OVERLAPPED storage until reaped.
class Overlap {
public:
    Overlap() { ov_.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr); }
    ~Overlap() { if (ov_.hEvent != nullptr) CloseHandle(ov_.hEvent); }
    Overlap(const Overlap&) = delete;
    Overlap& operator=(const Overlap&) = delete;
    bool valid() const { return ov_.hEvent != nullptr; }
    OVERLAPPED* get() { return &ov_; }
    void Reset() {
        const HANDLE event = ov_.hEvent;
        ov_ = {};
        ov_.hEvent = event;
        ResetEvent(event);
    }
private:
    OVERLAPPED ov_{};
};

bool FinishOverlapped(HANDLE device, OVERLAPPED* ov, BOOL started,
                      const char* what, DWORD& transferred, std::string& error) {
    if (started == FALSE) {
        const DWORD status = GetLastError();
        if (status != ERROR_IO_PENDING) {
            error = std::string(what) + " failed: " + LastErrorText(status);
            return false;
        }
    }
    if (GetOverlappedResult(device, ov, &transferred, TRUE) == FALSE) {
        error = std::string(what) + " failed: " + LastErrorText(GetLastError());
        return false;
    }
    error.clear();
    return true;
}

} // namespace

const char* ToString(Verdict v) {
    switch (v) {
        case Verdict::Undecided:           return "Undecided";
        case Verdict::Undeterminable:      return "Undeterminable";
        case Verdict::Accept:              return "Accept";
        case Verdict::PermanentAccept:     return "PermanentAccept";
        case Verdict::Block:               return "Block";
        case Verdict::PermanentBlock:      return "PermanentBlock";
        case Verdict::Drop:                return "Drop";
        case Verdict::PermanentDrop:       return "PermanentDrop";
        case Verdict::RedirectNameServer:  return "RedirectNameServer";
        case Verdict::RedirectTunnel:      return "RedirectTunnel";
        case Verdict::Failed:              return "Failed";
        case Verdict::RedirectSplitTunnel: return "RedirectSplitTunnel";
    }
    return "Unknown";
}

const char* ToString(Severity s) {
    switch (s) {
        case Severity::Trace:    return "TRACE";
        case Severity::Debug:    return "DEBUG";
        case Severity::Info:     return "INFO";
        case Severity::Warning:  return "WARN";
        case Severity::Error:    return "ERROR";
        case Severity::Critical: return "CRIT";
        case Severity::Disabled: return "OFF";
    }
    return "?";
}

const char* ToString(InfoType t) {
    switch (t) {
        case InfoType::LogLine:              return "LogLine";
        case InfoType::ConnectionIpv4:       return "ConnectionIpv4";
        case InfoType::ConnectionIpv6:       return "ConnectionIpv6";
        case InfoType::ConnectionEndEventV4: return "ConnectionEndV4";
        case InfoType::ConnectionEndEventV6: return "ConnectionEndV6";
        case InfoType::BandwidthStatsV4:     return "BandwidthStatsV4";
        case InfoType::BandwidthStatsV6:     return "BandwidthStatsV6";
    }
    return "Unknown";
}

const char* PayloadLayerToString(uint8_t layer) {
    switch (layer) {
        case 3: return "network";
        case 4: return "transport"; // Retained for source compatibility.
        default: return "unknown";
    }
}

const char* ProtocolToString(uint8_t proto) {
    switch (proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 58: return "ICMPv6";
        default: return "other";
    }
}

const char* DirectionToString(uint8_t dir) {
    return dir == 0 ? "outbound" : dir == 1 ? "inbound" : "unknown";
}

std::string FormatIpv4(const uint8_t ip[4]) {
    char buffer[16]{};
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buffer;
}

std::string FormatIpv6(const uint8_t ip[16]) {
    char buffer[64]{};
    std::snprintf(buffer, sizeof(buffer),
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                  ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    return buffer;
}

bool NormalizeIpAddress(const std::wstring& literal, std::string& normalized) {
    uint8_t ip[16]{};
    if (InetPtonW(AF_INET, literal.c_str(), ip) == 1) {
        normalized = FormatIpv4(ip);
        return true;
    }
    if (InetPtonW(AF_INET6, literal.c_str(), ip) == 1) {
        normalized = FormatIpv6(ip);
        return true;
    }
    return false;
}

std::string Connection::LocalIpString() const {
    return ipv6 ? FormatIpv6(local_ip) : FormatIpv4(local_ip);
}
std::string Connection::RemoteIpString() const {
    return ipv6 ? FormatIpv6(remote_ip) : FormatIpv4(remote_ip);
}
std::string Connection::PayloadHexString() const {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(payload.size() * 2);
    for (const uint8_t b : payload) {
        result.push_back(digits[b >> 4]);
        result.push_back(digits[b & 15]);
    }
    return result;
}
std::string ConnectionEnd::LocalIpString() const {
    return ipv6 ? FormatIpv6(local_ip) : FormatIpv4(local_ip);
}
std::string ConnectionEnd::RemoteIpString() const {
    return ipv6 ? FormatIpv6(remote_ip) : FormatIpv4(remote_ip);
}
std::string BandwidthEntry::LocalIpString() const {
    return ipv6 ? FormatIpv6(local_ip) : FormatIpv4(local_ip);
}
std::string BandwidthEntry::RemoteIpString() const {
    return ipv6 ? FormatIpv6(remote_ip) : FormatIpv4(remote_ip);
}

Driver::Driver(std::wstring service_name)
    : service_name_(std::move(service_name)),
      records_(std::make_unique<wire::RecordStream>()) {}

Driver::~Driver() {
    try { Cleanup(); } catch (...) { /* Destructors must not propagate shutdown failures. */ }
}

bool Driver::Install(const std::wstring&, std::string& error, bool) {
    error = "automatic installation is not supported for an NDIS LWF; "
            "install explicitly with dist/Install.exe for vEthernet (Default Switch)";
    return false;
}

bool Driver::Open(std::string& error) {
    if (device_ != nullptr || stop_event_ != nullptr) {
        error = "device session is already open";
        return false;
    }
    const std::wstring path = L"\\\\.\\" + service_name_;
    HANDLE device = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                                nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        error = "CreateFile on installed device failed: " + LastErrorText(GetLastError()) +
                "; install/bind the LWF explicitly and run elevated";
        return false;
    }
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stop == nullptr) {
        const DWORD status = GetLastError();
        CloseHandle(device);
        error = "CreateEvent failed: " + LastErrorText(status);
        return false;
    }
    device_ = device;
    stop_event_ = stop;
    shutdown_requested_.store(false, std::memory_order_release);
    records_->Reset();
    error.clear();
    return true;
}

void Driver::Cleanup() {
    Stop();
    if (device_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(device_));
        device_ = nullptr;
    }
    if (stop_event_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
    records_->Reset();
}

bool Driver::DeviceControl(uint32_t code, uint8_t* out, uint32_t out_len,
                           std::string& error, uint32_t* returned) {
    if (device_ == nullptr) {
        error = "device not open";
        return false;
    }
    Overlap overlap;
    if (!overlap.valid()) {
        error = "CreateEvent failed: " + LastErrorText(GetLastError());
        return false;
    }
    DWORD transferred = 0;
    const HANDLE device = static_cast<HANDLE>(device_);
    const BOOL ok = DeviceIoControl(device, code, nullptr, 0, out, out_len,
                                    &transferred, overlap.get());
    if (!FinishOverlapped(device, overlap.get(), ok, "DeviceIoControl", transferred, error)) {
        return false;
    }
    if (returned != nullptr) *returned = transferred;
    return true;
}

bool Driver::GetVersion(uint8_t out[4], std::string& error) {
    if (out == nullptr) {
        error = "null version output";
        return false;
    }
    uint32_t returned = 0;
    if (!DeviceControl(wire::kIoctlVersion, out, 4, error, &returned)) return false;
    if (returned != 4) {
        error = "IOCTL_VERSION did not return exactly four bytes";
        return false;
    }
    return true;
}

bool Driver::GetFilteredDeviceCount(uint32_t& out, std::string& error) {
    uint8_t bytes[4]{};
    uint32_t returned = 0;
    if (!DeviceControl(wire::kIoctlFilteredDeviceCount, bytes, sizeof(bytes), error, &returned)) return false;
    return wire::DecodeFilteredDeviceCount(bytes, returned, out, error);
}

bool Driver::GetAdapterInfo(AdapterSnapshot& out, std::string& error) {
    if (device_ == nullptr) {
        error = "device not open";
        return false;
    }
    std::unique_ptr<uint8_t[]> bytes(new (std::nothrow) uint8_t[wire::kMaxAdapterInfoSize]);
    if (!bytes) {
        error = "cannot allocate adapter information buffer";
        return false;
    }
    uint32_t returned = 0;
    if (!DeviceControl(wire::kIoctlAdapterInfo, bytes.get(),
                       static_cast<uint32_t>(wire::kMaxAdapterInfoSize), error, &returned)) return false;
    return wire::DecodeAdapterInfo(bytes.get(), returned, out, error);
}

bool Driver::RequestShutdown(std::string& error) {
    return DeviceControl(wire::kIoctlShutdown, nullptr, 0, error);
}

bool Driver::SendCommand(const uint8_t* data, size_t length, std::string& error) {
    // Do not allow a valid prefix to run before rejecting an invalid suffix.
    if (!wire::ValidateCommands(data, length, error)) return false;
    std::lock_guard<std::mutex> guard(write_mutex_);
    if (device_ == nullptr) {
        error = "device not open";
        return false;
    }
    if (shutdown_requested_.load(std::memory_order_acquire)) {
        error = "device session is stopping";
        return false;
    }
    Overlap overlap;
    if (!overlap.valid()) {
        error = "CreateEvent failed: " + LastErrorText(GetLastError());
        return false;
    }
    const HANDLE device = static_cast<HANDLE>(device_);
    DWORD written = 0;
    const BOOL ok = WriteFile(device, data, static_cast<DWORD>(length), &written, overlap.get());
    if (!FinishOverlapped(device, overlap.get(), ok, "WriteFile", written, error)) return false;
    if (written != length) {
        error = "WriteFile completed a short command batch";
        return false;
    }
    return true;
}

bool Driver::SendVerdict(uint64_t id, Verdict verdict, std::string& error) {
    std::array<uint8_t, wire::kVerdictCommandSize> command{};
    if (!wire::EncodeVerdict(id, verdict, command, error)) return false;
    return SendCommand(command.data(), command.size(), error);
}

bool Driver::RequestLogs(std::string& error) {
    const uint8_t command = static_cast<uint8_t>(CommandType::GetLogs);
    return SendCommand(&command, 1, error);
}
bool Driver::RequestBandwidthStats(std::string& error) {
    const uint8_t command = static_cast<uint8_t>(CommandType::GetBandwidthStats);
    return SendCommand(&command, 1, error);
}
bool Driver::RequestMemoryStats(std::string& error) {
    const uint8_t command = static_cast<uint8_t>(CommandType::PrintMemoryStats);
    return SendCommand(&command, 1, error);
}
bool Driver::RequestCleanEndedConnections(std::string& error) {
    const uint8_t command = static_cast<uint8_t>(CommandType::CleanEndedConnections);
    return SendCommand(&command, 1, error);
}
bool Driver::RequestClearCache(std::string& error) {
    const uint8_t command = static_cast<uint8_t>(CommandType::ClearCache);
    return SendCommand(&command, 1, error);
}

void Driver::Stop() {
    if (stop_event_ != nullptr) SetEvent(static_cast<HANDLE>(stop_event_));
    if (device_ == nullptr) return;
    bool expected = false;
    if (!shutdown_requested_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }
    // Wait out any already submitted command so no write follows shutdown.
    std::lock_guard<std::mutex> guard(write_mutex_);
    std::string ignored;
    RequestShutdown(ignored);
}

void Driver::Dispatch(const uint8_t* record, size_t length, const Handlers& handlers) {
    std::string error;
    if (!wire::DispatchRecord(record, length, handlers, error) && handlers.on_warning) {
        handlers.on_warning(error);
    }
}

void Driver::ReaderLoop(const Handlers& handlers) {
    std::array<uint8_t, 64 * 1024> chunk{};
    const HANDLE device = static_cast<HANDLE>(device_);
    const HANDLE stop = static_cast<HANDLE>(stop_event_);
    Overlap overlap;
    if (!overlap.valid()) {
        if (handlers.on_warning) handlers.on_warning("CreateEvent failed: " + LastErrorText(GetLastError()));
        return;
    }
    while (WaitForSingleObject(stop, 0) != WAIT_OBJECT_0) {
        overlap.Reset();
        DWORD read = 0;
        const BOOL ok = ReadFile(device, chunk.data(), static_cast<DWORD>(chunk.size()),
                                  &read, overlap.get());
        if (ok == FALSE) {
            const DWORD status = GetLastError();
            if (status == ERROR_OPERATION_ABORTED || status == ERROR_INVALID_HANDLE ||
                status == ERROR_HANDLE_EOF) break;
            if (status != ERROR_IO_PENDING) {
                if (WaitForSingleObject(stop, 0) != WAIT_OBJECT_0 && handlers.on_warning) handlers.on_warning("ReadFile failed: " + LastErrorText(status));
                break;
            }
            const HANDLE waits[] = {stop, overlap.get()->hEvent};
            const DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (result != WAIT_OBJECT_0 + 1) {
                // Always cancel/reap before OVERLAPPED or chunk storage is freed.
                const DWORD wait_error = result == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
                CancelIoEx(device, overlap.get());
                DWORD ignored = 0;
                GetOverlappedResult(device, overlap.get(), &ignored, TRUE);
                if (wait_error != ERROR_SUCCESS && handlers.on_warning) {
                    handlers.on_warning("read wait failed: " + LastErrorText(wait_error));
                }
                break;
            }
        }
        // Query completion even on synchronous success: overlapped transfer
        // counts come from the completed request, not from an assumed length.
        if (GetOverlappedResult(device, overlap.get(), &read, TRUE) == FALSE) {
            const DWORD status = GetLastError();
            if (status != ERROR_OPERATION_ABORTED && status != ERROR_INVALID_HANDLE &&
                status != ERROR_HANDLE_EOF && WaitForSingleObject(stop, 0) != WAIT_OBJECT_0 && handlers.on_warning) {
                handlers.on_warning("GetOverlappedResult failed: " + LastErrorText(status));
            }
            break;
        }
        if (read == 0) {
            if (handlers.on_warning) handlers.on_warning("unexpected empty read; install the blocking-read SYS");
            break;
        }
        if (read > chunk.size()) {
            if (handlers.on_warning) handlers.on_warning("driver returned an invalid read length");
            break;
        }
        std::string error;
        if (!records_->Feed(chunk.data(), read,
                [&](const uint8_t* record, size_t length) { Dispatch(record, length, handlers); }, error)) {
            if (handlers.on_warning) handlers.on_warning(error);
            break;
        }
    }
    if (records_->PendingBytes() != 0 && handlers.on_warning) {
        handlers.on_warning("incomplete final driver record discarded");
    }
}

void Driver::Run(const Handlers& handlers, unsigned poll_interval_ms) {
    if (device_ == nullptr || stop_event_ == nullptr) {
        if (handlers.on_warning) handlers.on_warning("Run called without an open device");
        return;
    }
    const HANDLE stop = static_cast<HANDLE>(stop_event_);
    auto fail = [&](const char* message) noexcept {
        try { if (handlers.on_warning) handlers.on_warning(message); } catch (...) {}
        try { Stop(); } catch (...) {}
    };
    std::thread reader([&]() {
        try {
            ReaderLoop(handlers);
            Stop(); // Also wake Run after a read/protocol error, not just on Ctrl+C.
        } catch (const std::exception& error) {
            fail(error.what());
        } catch (...) {
            fail("reader failed with an unknown exception");
        }
    });
    try {
        while (WaitForSingleObject(stop, 0) != WAIT_OBJECT_0) {
            if (handlers.on_poll) handlers.on_poll();
            const DWORD result = WaitForSingleObject(stop, std::max(1u, poll_interval_ms));
            if (result == WAIT_OBJECT_0) break;
            if (result == WAIT_FAILED) {
                fail("poll wait failed");
                break;
            }
        }
    } catch (...) {
        try { Stop(); } catch (...) {}
        reader.join();
        throw;
    }
    reader.join();
}

} // namespace pmkext
