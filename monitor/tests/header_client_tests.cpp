// All device entry points are faked; only private unnamed Win32 events are real.
#include <windows.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <future>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <vector>

namespace testio {
HANDLE CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
BOOL CloseHandle(HANDLE);
BOOL DeviceIoControl(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
BOOL CancelIoEx(HANDLE, LPOVERLAPPED);
}
#define CreateEventW testio::CreateEventW
#define CreateFileW testio::CreateFileW
#define CloseHandle testio::CloseHandle
#define DeviceIoControl testio::DeviceIoControl
#define ReadFile testio::ReadFile
#define WriteFile testio::WriteFile
#define GetOverlappedResult testio::GetOverlappedResult
#define CancelIoEx testio::CancelIoEx
#include "HyperVXNdisFilter.hpp"
#undef CreateEventW
#undef CreateFileW
#undef CloseHandle
#undef DeviceIoControl
#undef ReadFile
#undef WriteFile
#undef GetOverlappedResult
#undef CancelIoEx

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); return false; } } while (false)
using Client = hypervxndisfilter::Client;
using Bytes = std::vector<uint8_t>;

namespace testio {
struct Operation {
    bool complete = false;
    DWORD bytes = 0, error = ERROR_SUCCESS;
    uint8_t* buffer = nullptr;
    DWORD capacity = 0;
};
struct State {
    std::mutex mutex;
    std::unordered_map<OVERLAPPED*, Operation> operations;
    OVERLAPPED* pending = nullptr;
    HANDLE submitted = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE startup_seen = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE driver_ready = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    Bytes queued, written;
    std::vector<DWORD> open_errors;
    size_t offset = 0;
    unsigned reads = 0, cancels = 0, opens = 0, closes = 0;
    bool empty_read = false, short_control = false, wrong_version = false, fail_open = false, secure_ready = false;
    const uint8_t* first_buffer = nullptr;
    Client* stop_on_read = nullptr;
    ~State() { ::CloseHandle(submitted); ::CloseHandle(startup_seen); ::CloseHandle(driver_ready); }
} state;
HANDLE Device() { return reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x1234)); }
void Reset() {
    std::lock_guard lock(state.mutex);
    if (!state.operations.empty()) throw std::runtime_error("unreaped fake I/O");
    state.pending = nullptr;
    state.queued.clear(); state.written.clear(); state.open_errors.clear(); state.offset = 0;
    state.reads = state.cancels = state.opens = state.closes = 0;
    state.empty_read = state.short_control = state.wrong_version = state.fail_open = state.secure_ready = false;
    state.first_buffer = nullptr; state.stop_on_read = nullptr;
    ::ResetEvent(state.submitted); ::ResetEvent(state.startup_seen); ::ResetEvent(state.driver_ready);
}
void Complete(OVERLAPPED* ov, DWORD bytes, DWORD error = ERROR_SUCCESS) {
    auto& op = state.operations.at(ov);
    op.complete = true; op.bytes = bytes; op.error = error;
    if (state.pending == ov) state.pending = nullptr;
    ::SetEvent(ov->hEvent);
}
void Fill(OVERLAPPED* ov) {
    const auto& op = state.operations.at(ov);
    const size_t n = (std::min)(static_cast<size_t>(op.capacity), state.queued.size() - state.offset);
    std::memcpy(op.buffer, state.queued.data() + state.offset, n);
    state.offset += n;
    Complete(ov, static_cast<DWORD>(n));
}
void Inject(Bytes bytes) {
    std::lock_guard lock(state.mutex);
    state.queued = std::move(bytes); state.offset = 0;
    if (state.pending) Fill(state.pending);
}
HANDLE CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL initial, LPCWSTR name) {
    if (!name) return ::CreateEventW(sa, manual, initial, nullptr);
    std::lock_guard lock(state.mutex);
    if (std::wcscmp(name, L"Global\\HyperVXNdisFilter.DriverReady")) {
        ::SetLastError(ERROR_INVALID_NAME); return nullptr;
    }
    SECURITY_DESCRIPTOR_CONTROL control = 0;
    DWORD revision = 0;
    state.secure_ready = sa && !sa->bInheritHandle && sa->lpSecurityDescriptor &&
        ::GetSecurityDescriptorControl(sa->lpSecurityDescriptor, &control, &revision) &&
        (control & SE_DACL_PROTECTED) && manual && !initial;
    HANDLE duplicate = nullptr;
    if (!::DuplicateHandle(::GetCurrentProcess(), state.driver_ready, ::GetCurrentProcess(),
                           &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS)) return nullptr;
    ::SetEvent(state.startup_seen);
    return duplicate;
}
HANDLE CreateFileW(LPCWSTR path, DWORD access, DWORD sharing, LPSECURITY_ATTRIBUTES, DWORD mode, DWORD flags, HANDLE) {
    std::lock_guard lock(state.mutex);
    if (std::wcscmp(path, L"\\\\.\\HyperVXNdisFilter") || access != (GENERIC_READ | GENERIC_WRITE) ||
        sharing || mode != OPEN_EXISTING || !(flags & FILE_FLAG_OVERLAPPED)) {
        ::SetLastError(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
    }
    ++state.opens;
    if (state.opens <= state.open_errors.size()) {
        const DWORD error = state.open_errors[state.opens - 1];
        if (state.opens == 2) ::SetEvent(state.submitted);
        if (error) { ::SetLastError(error); return INVALID_HANDLE_VALUE; }
    }
    if (state.fail_open) { ::SetLastError(ERROR_FILE_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    return Device();
}
BOOL CloseHandle(HANDLE handle) {
    if (handle != Device()) return ::CloseHandle(handle);
    std::lock_guard lock(state.mutex);
    ++state.closes;
    return TRUE;
}
BOOL DeviceIoControl(HANDLE, DWORD code, LPVOID input, DWORD input_size, LPVOID output,
                     DWORD capacity, LPDWORD actual, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    if (input || input_size) { ::SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    uint8_t bytes[4]{};
    DWORD size = 4;
    if (code == 0x9c40e000u) {
        const auto version = Client::RequiredVersion;
        std::memcpy(bytes, version.data(), 4);
        if (state.wrong_version) bytes[2] = 0;
    } else if (code == 0x9c40e008u) bytes[0] = 1;
    else if (code == 0x9c40e004u) {
        size = 0;
        if (state.pending) Complete(state.pending, 0, ERROR_OPERATION_ABORTED);
    } else { ::SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
    if (size && state.short_control) size = 3;
    if (capacity < size) { ::SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    if (size) std::memcpy(output, bytes, size);
    state.operations[ov] = {};
    Complete(ov, size);
    *actual = size;
    return TRUE;
}
BOOL ReadFile(HANDLE, LPVOID buffer, DWORD capacity, LPDWORD actual, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    ++state.reads;
    if (state.stop_on_read) {
        state.stop_on_read->Stop();
        ::SetLastError(ERROR_DEVICE_NOT_CONNECTED); return FALSE;
    }
    if (!state.first_buffer) state.first_buffer = static_cast<uint8_t*>(buffer);
    state.operations[ov] = {false, 0, 0, static_cast<uint8_t*>(buffer), capacity};
    if (state.empty_read) { Complete(ov, 0); *actual = 0; return TRUE; }
    if (state.offset < state.queued.size()) { Fill(ov); *actual = state.operations.at(ov).bytes; return TRUE; }
    state.pending = ov;
    ::SetEvent(state.submitted);
    ::SetLastError(ERROR_IO_PENDING);
    return FALSE;
}
BOOL WriteFile(HANDLE, LPCVOID buffer, DWORD size, LPDWORD actual, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    const auto* p = static_cast<const uint8_t*>(buffer);
    state.written.insert(state.written.end(), p, p + size);
    state.operations[ov] = {};
    Complete(ov, size);
    *actual = size;
    return TRUE;
}
BOOL GetOverlappedResult(HANDLE, LPOVERLAPPED ov, LPDWORD actual, BOOL wait) {
    for (;;) {
        {
            std::lock_guard lock(state.mutex);
            const auto it = state.operations.find(ov);
            if (it == state.operations.end()) { ::SetLastError(ERROR_NOT_FOUND); return FALSE; }
            if (it->second.complete) {
                const auto op = it->second;
                state.operations.erase(it);
                *actual = op.bytes;
                if (op.error) { ::SetLastError(op.error); return FALSE; }
                return TRUE;
            }
        }
        if (!wait) { ::SetLastError(ERROR_IO_INCOMPLETE); return FALSE; }
        ::WaitForSingleObject(ov->hEvent, INFINITE);
    }
}
BOOL CancelIoEx(HANDLE, LPOVERLAPPED ov) {
    std::lock_guard lock(state.mutex);
    ++state.cancels;
    const auto it = state.operations.find(ov);
    if (it == state.operations.end() || it->second.complete) { ::SetLastError(ERROR_NOT_FOUND); return FALSE; }
    Complete(ov, 0, ERROR_OPERATION_ABORTED);
    return TRUE;
}
} // namespace testio

namespace {
void Put(Bytes& bytes, size_t offset, uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i) bytes[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}
Bytes Connection(bool ipv6, size_t payload) {
    const size_t prefix = ipv6 ? 56 : 32, addr = ipv6 ? 16 : 4;
    Bytes bytes(prefix + payload);
    bytes[0] = ipv6 ? 2 : 1;
    Put(bytes, 1, bytes.size() - 5, 4);
    Put(bytes, 5, 0x0102030405060708ull, 8);
    bytes[13] = ipv6 ? 1 : 0; bytes[14] = 17;
    bytes[15] = 0x20; bytes[15 + addr] = 0x30;
    Put(bytes, 15 + addr * 2, 12345, 2); Put(bytes, 17 + addr * 2, 443, 2);
    bytes[prefix - 5] = 3;
    Put(bytes, prefix - 4, payload, 4);
    for (size_t i = 0; i < payload; ++i) bytes[prefix + i] = static_cast<uint8_t>(i % 251);
    return bytes;
}
struct Observed {
    bool good = true, ipv6 = false;
    unsigned calls = 0;
    size_t payload = 0;
    const uint8_t* pointer = nullptr;
    const void* header = nullptr;
    Client* client = nullptr;
    bool throw_callback = false;
};
template <class T> void Observe(void* context, const T* packet, const uint8_t* payload, uint32_t size) {
    auto& s = *static_cast<Observed*>(context);
    ++s.calls;
    s.good &= packet->id == 0x0102030405060708ull && (sizeof(packet->local_ip) == 16) == s.ipv6 &&
        packet->direction == (s.ipv6 ? 1 : 0) && packet->protocol == 17 && packet->payload_layer == 3 &&
        packet->local_ip[0] == 0x20 && packet->remote_ip[0] == 0x30 &&
        packet->local_port == 12345 && packet->remote_port == 443 && size == s.payload &&
        (!s.pointer || payload == s.pointer) && (!s.header || packet == s.header);
    for (size_t i = 0; i < size; ++i) s.good &= payload[i] == static_cast<uint8_t>(i % 251);
    if (s.throw_callback) throw std::runtime_error("callback");
    if (s.client) {
        s.good &= s.client->SendVerdict(packet->id, Client::Verdict::PermanentAccept) == ERROR_SUCCESS;
        s.client->Stop();
    }
}
Client::Callbacks ConnectionCallbacks(Observed& observed) {
    Client::Callbacks cb;
    cb.context = &observed;
    cb.on_connection_v4 = Observe<Client::ConnectionV4>;
    cb.on_connection_v6 = Observe<Client::ConnectionV6>;
    return cb;
}
bool Feed(Client::Stream& stream, const Bytes& bytes, size_t chunk, const Client::Callbacks& cb) {
    for (size_t offset = 0; offset < bytes.size();) {
        auto buffer = stream.Buffer();
        const size_t n = (std::min)({chunk, buffer.size(), bytes.size() - offset});
        CHECK(n != 0);
        std::memcpy(buffer.data(), bytes.data() + offset, n);
        CHECK(stream.Commit(n, cb) == ERROR_SUCCESS);
        offset += n;
    }
    return true;
}
bool TestCodecAndStream() {
    static_assert(sizeof(Client) < 1024 && sizeof(Client::Stream) < 1024);
    static_assert(Client::RequiredVersion == std::array<uint8_t, 4>{0, 3, 1, 0});
    for (bool v6 : {false, true}) for (size_t size : {size_t{0}, size_t{28}, size_t{65537}, size_t{1048576}}) {
        auto record = Connection(v6, size);
        Observed observed;
        observed.ipv6 = v6; observed.payload = size;
        observed.header = record.data() + 5; observed.pointer = record.data() + (v6 ? 56 : 32);
        auto cb = ConnectionCallbacks(observed);
        CHECK(Client::DispatchRecord(record, cb) == ERROR_SUCCESS);
        CHECK(observed.calls == 1 && observed.good);
        for (size_t chunk : {size_t{1}, size_t{31}, size_t{65536}}) {
            Client::Stream stream;
            observed.calls = 0; observed.header = stream.Buffer().data() + 5;
            observed.pointer = stream.Buffer().data() + (v6 ? 56 : 32);
            CHECK(Feed(stream, record, chunk, cb));
            CHECK(stream.PendingBytes() == 0 && observed.calls == 1 && observed.good);
        }
    }
    auto record = Connection(false, 32);
    Bytes pair = record; pair.insert(pair.end(), record.begin(), record.end());
    Observed observed; observed.payload = 32;
    auto cb = ConnectionCallbacks(observed);
    Client::Stream stream;
    CHECK(Feed(stream, pair, 79, cb));
    CHECK(observed.good && observed.calls == 2 && stream.PendingBytes() == 0);
    for (size_t n = 0; n < record.size(); ++n)
        CHECK(Client::DispatchRecord(Client::Bytes(record).first(n), cb) != ERROR_SUCCESS);
    for (size_t offset : {size_t{13}, size_t{27}, size_t{28}}) {
        auto invalid = record; invalid[offset] = 9;
        CHECK(Client::DispatchRecord(invalid, cb) != ERROR_SUCCESS);
    }
    const unsigned calls = observed.calls;
    auto invalid = record; Put(invalid, 1, 0xffffffff, 4);
    std::memcpy(stream.Buffer().data(), invalid.data(), 5);
    CHECK(stream.Commit(5, cb) == ERROR_INVALID_DATA);
    CHECK(observed.calls == calls && stream.Buffer().empty());
    CHECK(stream.Commit(0, cb) == ERROR_INVALID_DATA);
    stream.Reset();
    CHECK(Feed(stream, record, 31, cb));
    CHECK(observed.calls == calls + 1);
    return true;
}
bool TestUnalignedViewsAndDeferredCompaction() {
    struct Natural { uint8_t byte; uint64_t value; };
    static_assert(alignof(Natural) == alignof(uint64_t) && offsetof(Natural, value) == 8); // pack was restored.
    for (bool v6 : {false, true}) {
        auto record = Connection(v6, 28);
        Observed observed; observed.ipv6 = v6; observed.payload = 28;
        auto cb = ConnectionCallbacks(observed);
        for (size_t shift = 0; shift < 8; ++shift) {
            Bytes storage(shift + record.size());
            std::memcpy(storage.data() + shift, record.data(), record.size());
            observed.header = storage.data() + shift + 5;
            observed.pointer = storage.data() + shift + (v6 ? 56 : 32);
            CHECK(Client::DispatchRecord(Client::Bytes(storage).subspan(shift), cb) == ERROR_SUCCESS);
            CHECK(observed.good && observed.calls == shift + 1);
        }
        const unsigned calls = observed.calls;
        for (size_t offset : {size_t{13}, record.size() - 28 - 5, record.size() - 28 - 4}) {
            auto invalid = record; invalid[offset] = 9;
            CHECK(Client::DispatchRecord(invalid, cb) == ERROR_INVALID_DATA);
            CHECK(Client::DispatchRecord(invalid, {}) == ERROR_INVALID_DATA);
        }
        CHECK(observed.calls == calls);
    }
    Client::Stream stream;
    uint8_t* base = stream.Buffer().data();
    auto first = Connection(false, 0);
    auto second = Connection(true, Client::MaxPayloadSize);
    const size_t partial = 17, written = first.size() + partial;
    std::memcpy(base, first.data(), first.size());
    std::memcpy(base + first.size(), second.data(), partial);
    Observed observed; observed.header = base + 5; observed.pointer = base + 32;
    auto cb = ConnectionCallbacks(observed);
    CHECK(stream.Commit(written, cb) == ERROR_SUCCESS);
    CHECK(observed.good && observed.calls == 1 && stream.PendingBytes() == partial);
    CHECK(stream.Buffer().data() == base + written); // The partial frame was not moved after dispatch.
    observed.ipv6 = true; observed.payload = Client::MaxPayloadSize;
    observed.header = base + 5; observed.pointer = base + 56; // Compaction is eventually necessary at capacity.
    Bytes remainder(second.begin() + partial, second.end());
    CHECK(Feed(stream, remainder, Client::ReadSize, cb));
    CHECK(observed.good && observed.calls == 2 && stream.PendingBytes() == 0);
    CHECK(stream.Buffer().data() == base);
    CHECK(stream.Commit(Client::ReadSize + 1, cb) == ERROR_INVALID_DATA);
    CHECK(stream.Buffer().empty());
    stream.Reset();
    CHECK(!stream.Buffer().empty());
    return true;
}
bool TestLogAndBandwidth() {
    struct State {
        unsigned logs = 0, batches = 0, entries = 0;
        bool good = true, ipv6 = false;
        const void* pointer = nullptr;
    } state;
    Client::Callbacks cb;
    cb.context = &state;
    cb.on_log = [](void* context, uint8_t level, std::string_view text) {
        auto& s = *static_cast<State*>(context); ++s.logs;
        s.good &= level == 3 && text == "abc" && text.data() == s.pointer;
    };
    const auto bandwidth = []<class T>(void* context, uint8_t protocol, const T* entries, uint32_t count) {
        auto& s = *static_cast<State*>(context); ++s.batches; s.entries += count;
        s.good &= protocol == 6 && (sizeof(entries->local_ip) == 16) == s.ipv6 &&
            entries == s.pointer && count == 2;
        for (uint32_t i = 0; i < count; ++i) {
            const auto& b = entries[i];
            s.good &= b.local_ip[0] == 1 && b.remote_ip[0] == 2 &&
                b.local_port == 12345 && b.remote_port == 443 &&
                b.transmitted_bytes == 0x0123456789abcdefull + i && b.received_bytes == 0xfedcba9876543210ull - i;
        }
    };
    cb.on_bandwidth_v4 = bandwidth;
    cb.on_bandwidth_v6 = bandwidth;
    Bytes log{0, 4, 0, 0, 0, 3, 'a', 'b', 'c'};
    state.pointer = log.data() + 6;
    CHECK(Client::DispatchRecord(log, cb) == ERROR_SUCCESS);
    for (uint8_t severity : {uint8_t{0}, uint8_t{8}}) {
        log[5] = severity; CHECK(Client::DispatchRecord(log, cb) == ERROR_INVALID_DATA);
    }
    for (bool v6 : {false, true}) {
        const size_t addr = v6 ? 16 : 4, entry = addr * 2 + 20;
        Bytes stats(10 + 2 * entry);
        stats[0] = v6 ? 6 : 5; Put(stats, 1, stats.size() - 5, 4); stats[5] = 6; Put(stats, 6, 2, 4);
        for (size_t i = 0; i < 2; ++i) {
            const size_t offset = 10 + i * entry;
            stats[offset] = 1; Put(stats, offset + addr, 12345, 2);
            stats[offset + addr + 2] = 2; Put(stats, offset + addr * 2 + 2, 443, 2);
            Put(stats, offset + addr * 2 + 4, 0x0123456789abcdefull + i, 8);
            Put(stats, offset + addr * 2 + 12, 0xfedcba9876543210ull - i, 8);
        }
        state.ipv6 = v6;
        for (size_t shift = 0; shift < 8; ++shift) {
            Bytes storage(shift + stats.size());
            std::memcpy(storage.data() + shift, stats.data(), stats.size());
            state.pointer = storage.data() + shift + 10;
            const unsigned batches = state.batches;
            CHECK(Client::DispatchRecord(Client::Bytes(storage).subspan(shift), cb) == ERROR_SUCCESS);
            CHECK(state.good && state.batches == batches + 1); // One borrowed array, not two temporary entries.
        }
        const unsigned batches = state.batches;
        auto invalid = stats;
        Put(invalid, 6, 0xffffffff, 4);
        CHECK(Client::DispatchRecord(invalid, cb) == ERROR_INVALID_DATA);
        CHECK(Client::DispatchRecord(invalid, {}) == ERROR_INVALID_DATA);
        invalid = stats; invalid.pop_back(); Put(invalid, 1, invalid.size() - 5, 4);
        CHECK(Client::DispatchRecord(invalid, cb) == ERROR_INVALID_DATA);
        for (size_t n = 0; n < stats.size(); ++n)
            CHECK(Client::DispatchRecord(Client::Bytes(stats).first(n), cb) != ERROR_SUCCESS);
        Bytes empty{static_cast<uint8_t>(v6 ? 6 : 5), 5, 0, 0, 0, 6, 0, 0, 0, 0};
        CHECK(Client::DispatchRecord(empty, cb) == ERROR_SUCCESS);
        CHECK(state.batches == batches);
    }
    CHECK(state.good && state.logs == 1 && state.batches == 16 && state.entries == 32);
    return true;
}
bool TestIdleAndStop() {
    testio::Reset();
    Client client;
    CHECK(client.Open() == ERROR_SUCCESS);
    auto run = std::async(std::launch::async, [&] { return client.Run({}, 1000); });
    CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
    CHECK(client.Close() == ERROR_BUSY);
    uint32_t count = 0;
    CHECK(client.GetFilteredDeviceCount(count) == ERROR_SUCCESS && count == 1); // While read is pending.
    HANDLE quiet = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    const DWORD waited = ::WaitForSingleObject(quiet, 80);
    ::CloseHandle(quiet);
    CHECK(waited == WAIT_TIMEOUT);
    { std::lock_guard lock(testio::state.mutex); CHECK(testio::state.reads == 1 && testio::state.pending); }
    client.Stop();
    CHECK(run.get() == ERROR_SUCCESS);
    CHECK(client.Close() == ERROR_SUCCESS);
    CHECK(testio::state.operations.empty() && testio::state.cancels == 1 && testio::state.closes == 1);
    testio::Reset();
    CHECK(client.Open() == ERROR_SUCCESS);
    auto shutdown = std::async(std::launch::async, [&] { return client.Run({}, 1000); });
    CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
    CHECK(client.Shutdown() == ERROR_SUCCESS);
    CHECK(shutdown.get() == ERROR_SUCCESS && testio::state.operations.empty());
    CHECK(client.Close() == ERROR_SUCCESS);
    return true;
}
bool TestStartupWait() {
    for (bool cancel : {false, true}) {
        testio::Reset();
        testio::state.fail_open = true;
        ::SetEvent(testio::state.driver_ready); // Stale signal must not cause retry spinning.
        Client client;
        auto open = std::async(std::launch::async, [&] { return client.Open(); });
        struct Guard {
            Client& client; std::future<DWORD>& open;
            ~Guard() { client.Stop(); if (open.valid()) open.wait(); }
        } guard{client, open};
        CHECK(::WaitForSingleObject(testio::state.startup_seen, 2000) == WAIT_OBJECT_0);
        HANDLE quiet = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        const DWORD waited = ::WaitForSingleObject(quiet, 80);
        ::CloseHandle(quiet);
        CHECK(waited == WAIT_TIMEOUT);
        { std::lock_guard lock(testio::state.mutex);
          CHECK(testio::state.opens == 2 && testio::state.secure_ready); }
        if (cancel) client.Stop();
        else {
            std::lock_guard lock(testio::state.mutex);
            testio::state.fail_open = false;
            ::SetEvent(testio::state.driver_ready);
        }
        CHECK(open.get() == static_cast<DWORD>(cancel ? ERROR_OPERATION_ABORTED : ERROR_SUCCESS));
        CHECK(testio::state.operations.empty());
        client.Close();
    }
    return true;
}
bool TestBusyStartup() {
    for (const auto& errors : std::vector<std::vector<DWORD>>{
            {ERROR_SHARING_VIOLATION},
            {ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION},
            {ERROR_FILE_NOT_FOUND, ERROR_FILE_NOT_FOUND, ERROR_SHARING_VIOLATION}}) {
        testio::Reset();
        testio::state.open_errors = errors;
        Client client;
        auto open = std::async(std::launch::async, [&] { return client.Open(); });
        struct Guard {
            Client& client; std::future<DWORD>& open;
            ~Guard() { client.Stop(); if (open.valid()) open.wait(); }
        } guard{client, open};
        if (errors.size() == 3) {
            CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
            ::SetEvent(testio::state.driver_ready);
        }
        const bool completed = open.wait_for(std::chrono::seconds(2)) == std::future_status::ready;
        if (!completed) client.Stop();
        CHECK(open.get() == ERROR_SHARING_VIOLATION && completed);
        CHECK(testio::state.opens == errors.size() && testio::state.operations.empty());
        if (errors.size() == 1) CHECK(::WaitForSingleObject(testio::state.startup_seen, 0) == WAIT_TIMEOUT);
        testio::state.open_errors.clear();
        CHECK(client.Open() == ERROR_SUCCESS);
        CHECK(client.Close() == ERROR_SUCCESS && testio::state.operations.empty());
    }
    return true;
}

bool TestTimeoutAndLegacy() {
    testio::Reset();
    Client client;
    CHECK(client.Open() == ERROR_SUCCESS);
    const auto started = GetTickCount64();
    CHECK(client.Run({}, 30) == ERROR_SUCCESS);
    CHECK(GetTickCount64() - started >= 20);
    CHECK(testio::state.reads == 1 && testio::state.cancels == 1 && testio::state.operations.empty());
    client.Close();
    testio::Reset();
    CHECK(client.Open() == ERROR_SUCCESS);
    testio::state.empty_read = true;
    CHECK(client.Run({}, 1000) == ERROR_INVALID_DATA);
    CHECK(testio::state.reads == 1 && testio::state.operations.empty());
    client.Close();
    testio::Reset();
    CHECK(client.Open() == ERROR_SUCCESS);
    testio::state.stop_on_read = &client;
    CHECK(client.Run({}, 1000) == ERROR_SUCCESS);
    CHECK(testio::state.reads == 1 && testio::state.operations.empty());
    return true;
}
bool TestCallbacksAndLargeRead() {
    for (size_t size : {size_t{32}, size_t{1048576}}) {
        testio::Reset();
        Client client;
        CHECK(client.Open() == ERROR_SUCCESS);
        Observed observed; observed.ipv6 = true; observed.payload = size; observed.client = &client;
        auto cb = ConnectionCallbacks(observed);
        auto run = std::async(std::launch::async, [&] { return client.Run(cb, 2000); });
        CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
        { std::lock_guard lock(testio::state.mutex);
          observed.pointer = testio::state.first_buffer + 56; observed.header = testio::state.first_buffer + 5; }
        testio::Inject(Connection(true, size));
        CHECK(run.get() == ERROR_SUCCESS);
        CHECK(observed.good && observed.calls == 1 && testio::state.operations.empty());
        const Bytes expected{1, 8, 7, 6, 5, 4, 3, 2, 1, 3};
        CHECK(testio::state.written == expected);
        CHECK(client.Send(Client::Command::GetBandwidthStats) == ERROR_SUCCESS);
        CHECK(testio::state.written.back() == 6);
        client.Close();
    }
    return true;
}
bool TestErrorsAndException() {
    testio::Reset();
    Client client;
    uint32_t count = 99;
    std::array<uint8_t, 4> version{9, 9, 9, 9};
    CHECK(client.GetVersion(version) == ERROR_INVALID_HANDLE && version[0] == 9);
    CHECK(client.GetFilteredDeviceCount(count) == ERROR_INVALID_HANDLE && count == 99);
    CHECK(client.Run({}, 10) == ERROR_INVALID_HANDLE);
    CHECK(client.SendVerdict(1, static_cast<Client::Verdict>(9)) == ERROR_INVALID_PARAMETER);
    CHECK(client.Send(static_cast<Client::Command>(0)) == ERROR_INVALID_PARAMETER);
    testio::state.wrong_version = true;
    CHECK(client.Open() == ERROR_REVISION_MISMATCH && testio::state.closes == 1);
    testio::state.wrong_version = false;
    CHECK(client.Open() == ERROR_SUCCESS);
    testio::state.short_control = true;
    CHECK(client.GetFilteredDeviceCount(count) == ERROR_BAD_LENGTH && count == 99);
    testio::state.short_control = false;
    Observed observed; observed.payload = 32; observed.throw_callback = true;
    auto cb = ConnectionCallbacks(observed);
    auto run = std::async(std::launch::async, [&] { return client.Run(cb, 1000); });
    CHECK(::WaitForSingleObject(testio::state.submitted, 2000) == WAIT_OBJECT_0);
    testio::Inject(Connection(false, 32));
    bool threw = false;
    try { (void)run.get(); } catch (const std::runtime_error&) { threw = true; }
    CHECK(threw && testio::state.operations.empty());
    CHECK(client.Close() == ERROR_SUCCESS);
    CHECK(client.Close() == ERROR_SUCCESS);
    return true;
}
} // namespace

int main() {
    const struct { const char* name; bool (*run)(); } tests[]{
        {"borrowed packed connection headers/payloads, 1 MiB packets, chunked/coalesced reads and poisoned-stream reset", TestCodecAndStream},
        {"unaligned zero-copy views, restored packing and deferred stream compaction", TestUnalignedViewsAndDeferredCompaction},
        {"borrowed logs and batched bandwidth arrays, exact layouts and malformed records", TestLogAndBandwidth},
        {"idle read without polling, concurrent IOCTL, Stop/Shutdown cancellation and reaping", TestIdleAndStop},
        {"unlimited DriverReady startup wait, protected ACL, stale signal and Stop without device polling", TestStartupWait},
        {"exclusive-device sharing errors never wait for DriverReady and allow a later reopen", TestBusyStartup},
        {"deadline reaping, no legacy-read spin, and Stop during read admission", TestTimeoutAndLegacy},
        {"callback verdict bytes and full maximum packet read without payload allocation/copy", TestCallbacksAndLargeRead},
        {"unopened/short/version errors and callback exception cleanup", TestErrorsAndException},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
