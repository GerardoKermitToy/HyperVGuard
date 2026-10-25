// Header-only Windows x64 / C++20 client. No pmkext library dependency.
#pragma once

#include <windows.h>
#include <sddl.h>
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif
#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <string_view>

namespace hypervguard {

// One caller-owned Run() thread, no polling thread or per-packet allocations.
// Callbacks run inline. Views expire on callback return; copy only what you keep.
// Stop is safe during Open/Run; commands may run concurrently after Open succeeds.
// Join all callers before Close/destruction; callbacks may Stop but not Close.
class Client final {
public:
    using Bytes = std::span<const uint8_t>;
    static constexpr size_t MaxRecordSize = 1'048'632;
    static constexpr DWORD ReadSize = 65'536;
    static constexpr std::array<uint8_t, 4> RequiredVersion{0, 3, 1, 0};
    enum class Verdict : uint8_t { Accept = 2, PermanentAccept, Block, PermanentBlock, Drop, PermanentDrop };
    enum class Command : uint8_t { ClearCache = 4, GetLogs, GetBandwidthStats, PrintMemoryStats, CleanEndedConnections };
    struct Connection {
        uint64_t id;
        bool ipv6;
        uint8_t direction, protocol; // 0=guest outbound, 1=guest inbound; never host PID.
        Bytes local_ip, remote_ip;
        uint16_t local_port, remote_port;
        Bytes payload; // Complete L3 packet, not Ethernet; may be a logical offload packet.
    };
    struct Bandwidth {
        bool ipv6;
        uint8_t protocol;
        Bytes local_ip, remote_ip;
        uint16_t local_port, remote_port;
        uint64_t transmitted_bytes, received_bytes;
    };
    struct Callbacks {
        void* context = nullptr;
        void (*on_connection)(void*, const Connection&) = nullptr;
        void (*on_log)(void*, uint8_t severity, std::string_view message) = nullptr;
        void (*on_bandwidth)(void*, const Bandwidth&) = nullptr; // Once per tuple, not per batch.
    };

    Client() = default;
    ~Client() { assert(!running_.load()); Close(); }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    // Never installs a driver. Waits indefinitely on DriverReady after an open
    // failure; only a successful open or Stop() ends this startup wait.
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
        if (!error) out = static_cast<uint32_t>(ReadLe(bytes, 4));
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
        for (unsigned i = 0; i < 8; ++i) bytes[i + 1] = static_cast<uint8_t>(id >> (i * 8));
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

    // Device-independent, zero-copy decode. Exactly one complete bounded record.
    static DWORD DispatchRecord(Bytes record, const Callbacks& cb) {
        if (record.size() < 5 || record.size() > MaxRecordSize || ReadLe(record.data() + 1, 4) != record.size() - 5)
            return ERROR_INVALID_DATA;
        const auto body = record.subspan(5);
        const uint8_t* p = body.data();
        if (record[0] == 0) {
            if (body.empty() || record.size() > 512 || p[0] < 1 || p[0] > 7) return ERROR_INVALID_DATA;
            if (cb.on_log) cb.on_log(cb.context, p[0], {reinterpret_cast<const char*>(p + 1), body.size() - 1});
        } else if (record[0] == 1 || record[0] == 2) {
            const bool v6 = record[0] == 2;
            const size_t addr = v6 ? 16 : 4, prefix = v6 ? 51 : 27;
            if (body.size() < prefix || p[8] > 1 || p[prefix - 5] != 3 ||
                ReadLe(p + prefix - 4, 4) != body.size() - prefix || body.size() - prefix > 1'048'576)
                return ERROR_INVALID_DATA;
            const Connection connection{ReadLe(p, 8), v6, p[8], p[9], body.subspan(10, addr),
                body.subspan(10 + addr, addr), static_cast<uint16_t>(ReadLe(p + 10 + addr * 2, 2)),
                static_cast<uint16_t>(ReadLe(p + 12 + addr * 2, 2)), body.subspan(prefix)};
            if (cb.on_connection) cb.on_connection(cb.context, connection);
        } else if (record[0] == 5 || record[0] == 6) {
            const bool v6 = record[0] == 6;
            const size_t addr = v6 ? 16 : 4, entry = addr * 2 + 20;
            if (body.size() < 5 || (body.size() - 5) % entry || ReadLe(p + 1, 4) != (body.size() - 5) / entry)
                return ERROR_INVALID_DATA;
            if (cb.on_bandwidth) for (size_t offset = 5; offset < body.size(); offset += entry) {
                const uint8_t* b = p + offset;
                const Bandwidth bandwidth{v6, p[0], body.subspan(offset, addr), body.subspan(offset + addr + 2, addr),
                    static_cast<uint16_t>(ReadLe(b + addr, 2)), static_cast<uint16_t>(ReadLe(b + addr * 2 + 2, 2)),
                    ReadLe(b + addr * 2 + 4, 8), ReadLe(b + addr * 2 + 12, 8)};
                cb.on_bandwidth(cb.context, bandwidth);
            }
        } else return ERROR_NOT_SUPPORTED; // No synthetic/legacy connection-END events.
        return ERROR_SUCCESS;
    }

    // Read directly into this reusable heap buffer. Only an incomplete tail moves;
    // complete packets and callback views are never copied into separate objects.
    class Stream {
    public:
        std::span<uint8_t> Buffer() noexcept {
            if (!data_ || failed_) return {};
            const size_t available = MaxRecordSize - used_;
            return {data_.get() + used_, available < ReadSize ? available : ReadSize};
        }
        DWORD Commit(size_t count, const Callbacks& cb, const std::atomic<bool>* stop = nullptr) {
            if (!data_) return ERROR_NOT_ENOUGH_MEMORY;
            if (failed_ || count > Buffer().size()) { failed_ = true; return ERROR_INVALID_DATA; }
            used_ += count;
            size_t consumed = 0;
            while (used_ - consumed >= 5 && (!stop || !stop->load())) {
                const uint8_t* p = data_.get() + consumed;
                const uint64_t body = ReadLe(p + 1, 4);
                if (body > MaxRecordSize - 5) { failed_ = true; return ERROR_INVALID_DATA; }
                const size_t length = 5 + static_cast<size_t>(body);
                if (used_ - consumed < length) break;
                const DWORD error = DispatchRecord({p, length}, cb);
                if (error) { failed_ = true; return error; }
                consumed += length;
            }
            used_ -= consumed;
            if (used_ && consumed) std::memmove(data_.get(), data_.get() + consumed, used_);
            return ERROR_SUCCESS;
        }
        void Reset() noexcept { used_ = 0; failed_ = false; }
        size_t PendingBytes() const noexcept { return used_; }
    private:
        std::unique_ptr<uint8_t[]> data_{new (std::nothrow) uint8_t[MaxRecordSize]};
        size_t used_ = 0;
        bool failed_ = false;
    };

private:
    DWORD OpenDevice() {
        auto try_open = [&]() {
            device_ = CreateFileW(L"\\\\.\\HyperVGuard", GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
            return device_ == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        };
        const DWORD first = try_open();
        if (!first) return first;
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, nullptr)) return GetLastError();
        SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
        struct Event { HANDLE h; ~Event() { if (h) CloseHandle(h); } } ready{
            CreateEventW(&sa, TRUE, FALSE, L"Global\\HyperVGuard.DriverReady")};
        const DWORD create_error = ready.h ? ERROR_SUCCESS : GetLastError();
        LocalFree(sd);
        if (create_error) return create_error;
        for (;;) {
            // Reset BEFORE retrying: no lost startup signal or stale-signal loop.
            if (!ResetEvent(ready.h)) return GetLastError();
            if (stopping_.load()) return ERROR_OPERATION_ABORTED;
            if (!try_open()) return ERROR_SUCCESS;
            const HANDLE events[]{stop_event_, ready.h};
            const DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0) return ERROR_OPERATION_ABORTED;
            if (wait != WAIT_OBJECT_0 + 1) return wait == WAIT_FAILED ? GetLastError() : ERROR_GEN_FAILURE;
        }
    }
    static uint64_t ReadLe(const uint8_t* bytes, unsigned length) noexcept {
        uint64_t result = 0;
        for (unsigned i = 0; i < length; ++i) result |= static_cast<uint64_t>(bytes[i]) << (i * 8);
        return result;
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

} // namespace hypervguard
