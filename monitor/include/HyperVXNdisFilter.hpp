// Header-only Windows x64 / C++20 client. No pmkext library dependency.
#pragma once

#include <windows.h>
#include <sddl.h>
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif
#include <array>
#include <atomic>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <string_view>

namespace hypervxndisfilter {

// One caller-owned Run() thread, no polling thread or per-packet allocations.
// Callbacks run inline. Views expire on callback return; copy only what you keep.
// Stop is safe during Open/Run; commands may run concurrently after Open succeeds.
// Join all callers before Close/destruction; callbacks may Stop but not Close.
class Client final {
public:
    static_assert(std::endian::native == std::endian::little, "The device wire API is little-endian");
    using Bytes = std::span<const uint8_t>;
    static constexpr size_t MaxPayloadSize = 1'048'576;
    static constexpr size_t MaxRecordSize = MaxPayloadSize + 60;
    static constexpr DWORD ReadSize = 65'536;
    static constexpr std::array<uint8_t, 4> RequiredVersion{0, 3, 2, 0};
    enum class Verdict : uint8_t { Accept = 2, PermanentAccept, Block, PermanentBlock, Drop, PermanentDrop };
    enum class Command : uint8_t { ClearCache = 4, GetLogs, GetBandwidthStats, PrintMemoryStats, CleanEndedConnections };

    // Borrowed wire views, not normalized copies. Packing applies only to these
    // fixed layouts; never take an aligned scalar pointer/reference to a field.
#pragma pack(push, 1)
    template <size_t AddressSize> struct ConnectionFixed {
        uint64_t id;
        uint32_t interface_index; // Индекс хостового адаптера точки перехвата, не интерфейса гостя.
        uint8_t direction, protocol; // 0=guest outbound, 1=guest inbound; never host PID.
        uint8_t local_ip[AddressSize], remote_ip[AddressSize];
        uint16_t local_port, remote_port;
        uint8_t payload_layer; // Always 3. The following u32 is the payload size.
    };
    template <size_t AddressSize> struct BandwidthValue {
        uint8_t local_ip[AddressSize];
        uint16_t local_port;
        uint8_t remote_ip[AddressSize];
        uint16_t remote_port;
        uint64_t transmitted_bytes, received_bytes;
    };
#pragma pack(pop)
    using ConnectionV4 = ConnectionFixed<4>;
    using ConnectionV6 = ConnectionFixed<16>;
    using BandwidthV4 = BandwidthValue<4>;
    using BandwidthV6 = BandwidthValue<16>;
    static_assert(sizeof(ConnectionV4) == 27 && sizeof(ConnectionV6) == 51);
    static_assert(alignof(ConnectionV4) == 1 && alignof(ConnectionV6) == 1);
    static_assert(offsetof(ConnectionV4, id) == 0 && offsetof(ConnectionV6, id) == 0);
    static_assert(offsetof(ConnectionV4, interface_index) == 8 && offsetof(ConnectionV6, interface_index) == 8);
    static_assert(offsetof(ConnectionV4, direction) == 12 && offsetof(ConnectionV6, direction) == 12);
    static_assert(offsetof(ConnectionV4, protocol) == 13 && offsetof(ConnectionV6, protocol) == 13);
    static_assert(offsetof(ConnectionV4, local_ip) == 14 && offsetof(ConnectionV6, local_ip) == 14);
    static_assert(offsetof(ConnectionV4, remote_ip) == 18 && offsetof(ConnectionV6, remote_ip) == 30);
    static_assert(offsetof(ConnectionV4, local_port) == 22 && offsetof(ConnectionV6, local_port) == 46);
    static_assert(offsetof(ConnectionV4, remote_port) == 24 && offsetof(ConnectionV6, remote_port) == 48);
    static_assert(offsetof(ConnectionV4, payload_layer) == 26 && offsetof(ConnectionV6, payload_layer) == 50);
    static_assert(sizeof(BandwidthV4) == 28 && sizeof(BandwidthV6) == 52);
    static_assert(alignof(BandwidthV4) == 1 && alignof(BandwidthV6) == 1);
    static_assert(offsetof(BandwidthV4, local_ip) == 0 && offsetof(BandwidthV6, local_ip) == 0);
    static_assert(offsetof(BandwidthV4, local_port) == 4 && offsetof(BandwidthV6, local_port) == 16);
    static_assert(offsetof(BandwidthV4, remote_ip) == 6 && offsetof(BandwidthV6, remote_ip) == 18);
    static_assert(offsetof(BandwidthV4, remote_port) == 10 && offsetof(BandwidthV6, remote_port) == 34);
    static_assert(offsetof(BandwidthV4, transmitted_bytes) == 12 && offsetof(BandwidthV6, transmitted_bytes) == 36);
    static_assert(offsetof(BandwidthV4, received_bytes) == 20 && offsetof(BandwidthV6, received_bytes) == 44);

    template <class T> using ConnectionCallback = void (*)(void*, const T*, const uint8_t* payload, uint32_t size);
    template <class T> using BandwidthCallback = void (*)(void*, uint8_t protocol, const T*, uint32_t count);
    struct Callbacks {
        void* context = nullptr;
        ConnectionCallback<ConnectionV4> on_connection_v4 = nullptr;
        ConnectionCallback<ConnectionV6> on_connection_v6 = nullptr;
        void (*on_log)(void*, uint8_t severity, std::string_view message) = nullptr;
        BandwidthCallback<BandwidthV4> on_bandwidth_v4 = nullptr; // One call per record, not per tuple.
        BandwidthCallback<BandwidthV6> on_bandwidth_v6 = nullptr;
    };

    Client() = default;
    ~Client() { assert(!running_.load()); Close(); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Не устанавливает драйвер. DriverReady ожидается без тайм-аута при запуске.
    // Занятое эксклюзивное устройство возвращает ERROR_SHARING_VIOLATION сразу:
    // освобождение чужого handle не сигнализирует DriverReady повторно.
    DWORD Open() {
        if (device_ != INVALID_HANDLE_VALUE || stop_event_) return ERROR_ALREADY_EXISTS;
        AcquireSRWLockExclusive(&stop_lock_);
        stopping_.store(false);
        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const DWORD stop_error = stop_event_ ? ERROR_SUCCESS : GetLastError();
        ReleaseSRWLockExclusive(&stop_lock_);
        if (stop_error) { Close(); return stop_error; }
        control_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!control_event_) { const DWORD e = GetLastError(); Close(); return e; }
        DWORD error = OpenDevice();
        if (!error && stopping_.load()) error = ERROR_OPERATION_ABORTED;
        std::array<uint8_t, 4> version{};
        if (!error) error = GetVersion(version);
        if (!error && version != RequiredVersion) error = ERROR_REVISION_MISMATCH;
        if (error) Close();
        return error;
    }
    void Stop() noexcept {
        AcquireSRWLockShared(&stop_lock_);
        stopping_.store(true);
        if (stop_event_) SetEvent(stop_event_);
        ReleaseSRWLockShared(&stop_lock_);
    }
    DWORD Close() {
        if (running_.load()) return ERROR_BUSY; // Stop, then join Run first.
        Stop();
        std::lock_guard lock(control_mutex_);
        if (device_ != INVALID_HANDLE_VALUE) CloseHandle(device_);
        if (control_event_) CloseHandle(control_event_);
        AcquireSRWLockExclusive(&stop_lock_);
        if (stop_event_) CloseHandle(stop_event_);
        stop_event_ = nullptr;
        ReleaseSRWLockExclusive(&stop_lock_);
        device_ = INVALID_HANDLE_VALUE;
        control_event_ = nullptr;
        return ERROR_SUCCESS;
    }
    DWORD GetVersion(std::array<uint8_t, 4>& out) {
        std::array<uint8_t, 4> bytes{};
        DWORD size = 0, error = Control(0x800, bytes.data(), 4, size);
        if (!error && size != 4) error = ERROR_BAD_LENGTH;
        if (!error) out = bytes;
        return error;
    }
    DWORD GetFilteredDeviceCount(uint32_t& out) {
        uint8_t bytes[4]{};
        DWORD size = 0, error = Control(0x802, bytes, 4, size);
        if (!error && size != 4) error = ERROR_BAD_LENGTH;
        if (!error) out = ReadLe<uint32_t>(bytes);
        return error;
    }
    DWORD Shutdown() {
        Stop();
        DWORD size = 0;
        return Control(0x801, nullptr, 0, size);
    }
    DWORD SendVerdict(uint64_t id, Verdict verdict) {
        const auto v = static_cast<uint8_t>(verdict);
        if (v < 2 || v > 7) return ERROR_INVALID_PARAMETER;
        uint8_t bytes[10]{1};
        std::memcpy(bytes + 1, &id, sizeof(id));
        bytes[9] = v;
        return Write(bytes, sizeof(bytes));
    }
    DWORD Send(Command command) {
        const auto value = static_cast<uint8_t>(command);
        if (value < 4 || value > 8) return ERROR_INVALID_PARAMETER;
        return Write(&value, 1);
    }

    // Blocks on overlapped read completion, Stop, or this optional deadline.
    // No automatic verdicts/statistics. Use a positive duration for automated runs.
    // Stop/timeout returns SUCCESS; callback exceptions propagate after I/O is reaped.
    DWORD Run(const Callbacks& callbacks, DWORD duration_ms = INFINITE) {
        if (device_ == INVALID_HANDLE_VALUE) return ERROR_INVALID_HANDLE;
        if (duration_ms == 0) return ERROR_INVALID_PARAMETER;
        if (running_.exchange(true)) return ERROR_BUSY;
        struct Guard { std::atomic<bool>& flag; ~Guard() { flag.store(false); } } guard{running_};
        struct Event { HANDLE h = CreateEventW(nullptr, TRUE, FALSE, nullptr);
                       ~Event() { if (h) CloseHandle(h); } } done;
        if (!done.h) return GetLastError();
        Stream stream;
        if (stream.Buffer().empty()) return ERROR_NOT_ENOUGH_MEMORY;
        const ULONGLONG deadline = duration_ms == INFINITE ? 0 : GetTickCount64() + duration_ms;
        while (!stopping_.load()) {
            if (deadline && GetTickCount64() >= deadline) break;
            auto buffer = stream.Buffer();
            OVERLAPPED ov{};
            ov.hEvent = done.h;
            ResetEvent(done.h);
            DWORD bytes = 0;
            const BOOL started = ReadFile(device_, buffer.data(), static_cast<DWORD>(buffer.size()), &bytes, &ov);
            DWORD error = Finish(device_, ov, started, bytes, stop_event_, deadline);
            if (stopping_.load() || error == ERROR_TIMEOUT) break;
            if (error) return error;
            if (bytes == 0) return ERROR_INVALID_DATA; // Never spin on an old/nonblocking SYS.
            error = stream.Commit(bytes, callbacks, &stopping_);
            if (error) return error;
        }
        return ERROR_SUCCESS;
    }

    // Device-independent, borrowed packed views. Exactly one complete bounded record.
    static DWORD DispatchRecord(Bytes record, const Callbacks& cb) {
        if (record.size() < 5 || record.size() > MaxRecordSize || ReadLe<uint32_t>(record.data() + 1) != record.size() - 5)
            return ERROR_INVALID_DATA;
        return DispatchBody(record[0], record.subspan(5), cb);
    }

    // Read directly into reusable storage; retain [head_, tail_) in place until
    // the writable tail is short. No compaction on every partial-record read.
    class Stream {
    public:
        std::span<uint8_t> Buffer() noexcept {
            if (!data_ || failed_) return {};
            if (MaxRecordSize - tail_ < ReadSize && head_) {
                const size_t pending = PendingBytes();
                std::memmove(data_.get(), data_.get() + head_, pending);
                head_ = 0;
                tail_ = pending;
            }
            const size_t available = MaxRecordSize - tail_;
            return {data_.get() + tail_, available < ReadSize ? available : ReadSize};
        }
        DWORD Commit(size_t count, const Callbacks& cb, const std::atomic<bool>* stop = nullptr) {
            if (!data_) return ERROR_NOT_ENOUGH_MEMORY;
            if (failed_ || count > ReadSize || count > MaxRecordSize - tail_) {
                failed_ = true; return ERROR_INVALID_DATA;
            }
            tail_ += count;
            while (PendingBytes() >= 5 && (!stop || !stop->load())) {
                const uint8_t* p = data_.get() + head_;
                const uint32_t body = ReadLe<uint32_t>(p + 1);
                if (body > MaxRecordSize - 5) { failed_ = true; return ERROR_INVALID_DATA; }
                const size_t length = 5 + static_cast<size_t>(body);
                if (PendingBytes() < length) break;
                const DWORD error = DispatchBody(p[0], {p + 5, body}, cb);
                if (error) { failed_ = true; return error; }
                head_ += length;
            }
            if (head_ == tail_) head_ = tail_ = 0;
            return ERROR_SUCCESS;
        }
        void Reset() noexcept { head_ = tail_ = 0; failed_ = false; }
        size_t PendingBytes() const noexcept { return tail_ - head_; }
    private:
        std::unique_ptr<uint8_t[]> data_{new (std::nothrow) uint8_t[MaxRecordSize]};
        size_t head_ = 0, tail_ = 0;
        bool failed_ = false;
    };

private:
    template <class T> static DWORD DispatchConnection(Bytes body, void* context, ConnectionCallback<T> callback) {
        constexpr size_t prefix = sizeof(T) + sizeof(uint32_t);
        if (body.size() < prefix) return ERROR_INVALID_DATA;
        const auto* connection = reinterpret_cast<const T*>(body.data());
        const uint32_t size = ReadLe<uint32_t>(body.data() + sizeof(T));
        if (connection->direction > 1 || connection->payload_layer != 3 || size > MaxPayloadSize ||
            size != body.size() - prefix) return ERROR_INVALID_DATA;
        if (callback) callback(context, connection, body.data() + prefix, size);
        return ERROR_SUCCESS;
    }
    template <class T> static DWORD DispatchBandwidth(Bytes body, void* context, BandwidthCallback<T> callback) {
        if (body.size() < 5) return ERROR_INVALID_DATA;
        const uint32_t count = ReadLe<uint32_t>(body.data() + 1);
        if ((body.size() - 5) % sizeof(T) || count != (body.size() - 5) / sizeof(T)) return ERROR_INVALID_DATA;
        if (callback && count) callback(context, body[0], reinterpret_cast<const T*>(body.data() + 5), count);
        return ERROR_SUCCESS;
    }
    static DWORD DispatchBody(uint8_t type, Bytes body, const Callbacks& cb) {
        switch (type) {
        case 0:
            if (body.empty() || body.size() > 507 || body[0] < 1 || body[0] > 7) return ERROR_INVALID_DATA;
            if (cb.on_log) cb.on_log(cb.context, body[0], {reinterpret_cast<const char*>(body.data() + 1), body.size() - 1});
            return ERROR_SUCCESS;
        case 1: return DispatchConnection(body, cb.context, cb.on_connection_v4);
        case 2: return DispatchConnection(body, cb.context, cb.on_connection_v6);
        case 5: return DispatchBandwidth(body, cb.context, cb.on_bandwidth_v4);
        case 6: return DispatchBandwidth(body, cb.context, cb.on_bandwidth_v6);
        default: return ERROR_NOT_SUPPORTED; // No synthetic/legacy connection-END events.
        }
    }
    DWORD OpenDevice() {
        auto try_open = [&]() {
            device_ = CreateFileW(L"\\\\.\\HyperVXNdisFilter", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
            return device_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        };
        const DWORD first = try_open();
        if (!first || first == ERROR_SHARING_VIOLATION) return first;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) return GetLastError();
        SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
        struct Event { HANDLE h; ~Event() { if (h) CloseHandle(h); } } ready{
            CreateEventW(&sa, TRUE, FALSE, L"Global\\HyperVXNdisFilter.DriverReady")};
        const DWORD create_error = ready.h ? ERROR_SUCCESS : GetLastError();
        LocalFree(sd);
        if (create_error) return create_error;
        for (;;) {
            // Reset BEFORE retrying: no lost startup signal or stale-signal loop.
            if (!ResetEvent(ready.h)) return GetLastError();
            if (stopping_.load()) return ERROR_OPERATION_ABORTED;
            const DWORD error = try_open();
            if (!error || error == ERROR_SHARING_VIOLATION) return error;
            const HANDLE events[]{stop_event_, ready.h};
            const DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) return ERROR_OPERATION_ABORTED;
            if (wait != WAIT_OBJECT_0 + 1) return wait == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        }
    }
    template <class T> static T ReadLe(const uint8_t* bytes) noexcept {
        T value;
        std::memcpy(&value, bytes, sizeof(value)); // Unaligned scalar load, not a record copy.
        return value;
    }
    static DWORD Finish(HANDLE device, OVERLAPPED& ov, BOOL started, DWORD& bytes,
                        HANDLE stop = nullptr, ULONGLONG deadline = 0) {
        if (!started) {
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) return error;
            if (stop) {
                const HANDLE events[]{stop, ov.hEvent};
                const ULONGLONG now = GetTickCount64();
                const DWORD timeout = !deadline ? INFINITE : now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
                const DWORD wait = WaitForMultipleObjects(2, events, FALSE, timeout);
                if (wait != WAIT_OBJECT_0 + 1) {
                    const DWORD result = wait == WAIT_FAILED ? GetLastError() :
                                         wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED;
                    CancelIoEx(device, &ov);
                    DWORD ignored = 0;
                    GetOverlappedResult(device, &ov, &ignored, TRUE); // Reap before any storage dies.
                    return result;
                }
            }
        }
        return GetOverlappedResult(device, &ov, &bytes, TRUE) ? ERROR_SUCCESS : GetLastError();
    }
    DWORD Control(uint32_t function, void* output, DWORD length, DWORD& actual) {
        std::lock_guard lock(control_mutex_);
        if (device_ == INVALID_HANDLE_VALUE) return ERROR_INVALID_HANDLE;
        OVERLAPPED ov{};
        ov.hEvent = control_event_;
        ResetEvent(control_event_);
        const DWORD code = (40000u << 16) | (3u << 14) | (function << 2);
        const BOOL started = DeviceIoControl(device_, code, nullptr, 0, output, length, &actual, &ov);
        return Finish(device_, ov, started, actual);
    }
    DWORD Write(const uint8_t* bytes, DWORD length) {
        std::lock_guard lock(control_mutex_);
        if (device_ == INVALID_HANDLE_VALUE) return ERROR_INVALID_HANDLE;
        OVERLAPPED ov{};
        ov.hEvent = control_event_;
        ResetEvent(control_event_);
        DWORD actual = 0;
        const BOOL started = WriteFile(device_, bytes, length, &actual, &ov);
        const DWORD error = Finish(device_, ov, started, actual);
        return error ? error : actual == length ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
    }
    HANDLE device_ = INVALID_HANDLE_VALUE, stop_event_ = nullptr, control_event_ = nullptr;
    SRWLOCK stop_lock_ = SRWLOCK_INIT;
    std::mutex control_mutex_;
    std::atomic<bool> stopping_{false}, running_{false};
};

} // namespace hypervxndisfilter
