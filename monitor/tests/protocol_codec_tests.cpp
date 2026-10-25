#include "DriverProtocol.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return false; } } while (false)

namespace {

using Bytes = std::vector<uint8_t>;
void U16(Bytes& b, uint16_t value) {
    b.push_back(static_cast<uint8_t>(value));
    b.push_back(static_cast<uint8_t>(value >> 8));
}
void U32(Bytes& b, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(value >> (i * 8)));
}
void U64(Bytes& b, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>(value >> (i * 8)));
}
Bytes Record(uint8_t type, const Bytes& payload) {
    Bytes b{type};
    U32(b, static_cast<uint32_t>(payload.size()));
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}
Bytes ConnectionRecord(bool v6) {
    Bytes p;
    U64(p, 0x0102030405060708ULL);
    U64(p, 0); // PID, with no extra thread/switch/port/NIC metadata.
    p.push_back(0);
    p.push_back(17);
    if (v6) {
        const uint8_t local[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        const uint8_t remote[16] = {0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
        p.insert(p.end(), local, local + 16);
        p.insert(p.end(), remote, remote + 16);
    } else {
        const uint8_t ips[] = {10, 0, 0, 1, 10, 0, 0, 2};
        p.insert(p.end(), ips, ips + sizeof(ips));
    }
    U16(p, 0x1234);
    U16(p, 53);
    p.push_back(3);
    U32(p, 2);
    p.push_back(v6 ? 0x60 : 0x45);
    p.push_back(0);
    return Record(v6 ? 2 : 1, p);
}

bool TestConnectionAbi() {
    std::string error;
    unsigned calls = 0;
    unsigned ends = 0;
    pmkext::Connection observed;
    pmkext::Handlers handlers;
    handlers.on_connection = [&](const pmkext::Connection& c) { observed = c; ++calls; };
    handlers.on_connection_end = [&](const pmkext::ConnectionEnd&) { ++ends; };
    for (bool v6 : {false, true}) {
        const auto bytes = ConnectionRecord(v6);
        CHECK(bytes.size() == (v6 ? 66u : 42u));
        CHECK(bytes[0] == (v6 ? 2 : 1));
        CHECK(bytes[1] == (v6 ? 61 : 37));
        const uint8_t id[] = {8, 7, 6, 5, 4, 3, 2, 1};
        CHECK(std::memcmp(bytes.data() + 5, id, 8) == 0);
        CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        CHECK(observed.id == 0x0102030405060708ULL && observed.process_id == 0);
        CHECK(observed.ipv6 == v6 && observed.direction == 0 && observed.protocol == 17);
        CHECK(observed.local_port == 0x1234 && observed.remote_port == 53);
        CHECK(observed.payload_layer == 3 && observed.payload_size == 2 && observed.payload.size() == 2);
        CHECK(observed.PayloadHexString() == (v6 ? "6000" : "4500"));
        CHECK(observed.LocalIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0001" : "10.0.0.1"));
        CHECK(observed.RemoteIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0002" : "10.0.0.2"));
    }
    for (bool v6 : {false, true}) {
        auto bytes = ConnectionRecord(v6);
        bytes[21] = 1;
        CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        CHECK(observed.direction == 1 && observed.process_id == 0 && observed.ipv6 == v6);
        CHECK(observed.local_port == 0x1234 && observed.remote_port == 53);
    }
    CHECK(calls == 4 && ends == 0);
    CHECK(std::string(pmkext::DirectionToString(0)) == "outbound");
    CHECK(std::string(pmkext::DirectionToString(1)) == "inbound");
    CHECK(std::string(pmkext::DirectionToString(2)) == "unknown");
    CHECK(pmkext::wire::kIoctlVersion == 0x9c40e000u);
    CHECK(pmkext::wire::kIoctlShutdown == 0x9c40e004u);
    return true;
}

bool TestInvalidRecords() {
    std::string error;
    unsigned callbacks = 0;
    pmkext::Handlers handlers;
    handlers.on_connection = [&](const auto&) { ++callbacks; };
    handlers.on_log = [&](const auto&) { ++callbacks; };
    handlers.on_bandwidth = [&](const auto&) { ++callbacks; };
    for (size_t modified : {size_t{13}, size_t{21}, size_t{35}}) {
        auto bytes = ConnectionRecord(false);
        bytes[modified] = modified == 35 ? 4 : modified == 21 ? 2 : 1; // PID, direction, payload layer.
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
    }
    auto bytes = ConnectionRecord(false);
    bytes[36] = 3; // Payload is only two bytes.
    CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
    bytes = ConnectionRecord(false);
    bytes[36] = 1; // Extra bytes are not a hidden second packet or extension.
    CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
    bytes[1] = 200;
    CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
    CHECK(!pmkext::wire::DispatchRecord(nullptr, 5, handlers, error));
    for (const Bytes& malformed : {Record(1, {}), Record(0, {}), Record(0, {0, 'x'}),
                                   Record(0, {8, 'x'}), Record(255, {}),
                                   Record(5, {17, 255, 255, 255, 255})}) {
        CHECK(!pmkext::wire::DispatchRecord(malformed.data(), malformed.size(), handlers, error));
    }
    CHECK(callbacks == 0);
    return true;
}

bool TestLogsAndCompatibilityTypes() {
    std::string error;
    unsigned logs = 0, ends = 0, bandwidth = 0;
    pmkext::Handlers handlers;
    handlers.on_log = [&](const pmkext::LogLine& line) {
        if (line.severity == pmkext::Severity::Info && line.message == "hello") ++logs;
    };
    handlers.on_connection_end = [&](const auto&) { ++ends; };
    handlers.on_bandwidth = [&](const pmkext::BandwidthStats& stats) {
        if (stats.protocol == 17 && stats.entries.size() == 1 &&
            stats.entries[0].transmitted_bytes == 123 && stats.entries[0].received_bytes == 456)
            ++bandwidth;
    };
    const auto log = Record(0, {3, 'h', 'e', 'l', 'l', 'o'});
    CHECK(pmkext::wire::DispatchRecord(log.data(), log.size(), handlers, error));
    CHECK(logs == 1 && ends == 0 && bandwidth == 0);
    for (bool v6 : {false, true}) {
        const size_t addr_size = v6 ? 16 : 4;
        Bytes end;
        U64(end, 0); end.push_back(0); end.push_back(17);
        end.resize(end.size() + addr_size * 2, 0);
        U16(end, 123); U16(end, 456);
        const auto actual_end = Record(v6 ? 4 : 3, end);
        CHECK(pmkext::wire::DispatchRecord(actual_end.data(), actual_end.size(), handlers, error));
        Bytes stats{17}; U32(stats, 1);
        stats.resize(stats.size() + addr_size, 0); U16(stats, 123);
        stats.resize(stats.size() + addr_size, 0); U16(stats, 456);
        U64(stats, 123); U64(stats, 456);
        const auto actual_stats = Record(v6 ? 6 : 5, stats);
        CHECK(pmkext::wire::DispatchRecord(actual_stats.data(), actual_stats.size(), handlers, error));
    }
    CHECK(ends == 2 && bandwidth == 2); // Only actual input records produce these.
    return true;
}

bool TestStreaming() {
    const auto v4 = ConnectionRecord(false);
    const auto v6 = ConnectionRecord(true);
    const auto log = Record(0, {3, 'o', 'k'});
    Bytes combined = v4;
    combined.insert(combined.end(), log.begin(), log.end());
    combined.insert(combined.end(), v6.begin(), v6.end());
    for (size_t chunk = 1; chunk <= combined.size(); ++chunk) {
        pmkext::wire::RecordStream stream;
        std::string error;
        std::vector<Bytes> observed;
        auto collect = [&](const uint8_t* p, size_t n) { observed.emplace_back(p, p + n); };
        for (size_t offset = 0; offset < combined.size(); offset += chunk) {
            const size_t size = std::min(chunk, combined.size() - offset);
            CHECK(stream.Feed(combined.data() + offset, size, collect, error));
            // Empty successful reads are ordinary idle observations. They must
            // not drain partial records, fabricate EOF, or produce any event.
            const auto before = stream.PendingBytes();
            CHECK(stream.Feed(nullptr, 0, collect, error));
            CHECK(stream.PendingBytes() == before);
        }
        CHECK(stream.PendingBytes() == 0 && observed.size() == 3);
        CHECK(observed[0] == v4 && observed[1] == log && observed[2] == v6);
    }
    pmkext::wire::RecordStream stream;
    std::string error;
    unsigned calls = 0;
    auto callback = [&](const auto*, auto) { ++calls; };
    const uint8_t oversized[] = {0, 255, 255, 255, 255};
    CHECK(!stream.Feed(oversized, sizeof(oversized), callback, error));
    CHECK(!stream.Feed(log.data(), log.size(), callback, error));
    CHECK(calls == 0 && stream.PendingBytes() == 5);
    stream.Reset();
    CHECK(stream.Feed(log.data(), log.size(), callback, error));
    CHECK(calls == 1);
    Bytes maximum(pmkext::wire::kMaxRecordSize - 5, 'x'); maximum[0] = 3;
    maximum = Record(0, maximum);
    CHECK(stream.Feed(maximum.data(), maximum.size(), callback, error));
    CHECK(calls == 2 && stream.PendingBytes() == 0);
    CHECK(!stream.Feed(nullptr, 1, callback, error));
    return true;
}

bool TestCommands() {
    std::string error;
    std::array<uint8_t, 10> command{};
    for (uint8_t value = 2; value <= 7; ++value) {
        CHECK(pmkext::wire::EncodeVerdict(0x0102030405060708ULL,
              static_cast<pmkext::Verdict>(value), command, error));
        const std::array<uint8_t, 10> expected = {1, 8, 7, 6, 5, 4, 3, 2, 1, value};
        CHECK(command == expected);
        CHECK(pmkext::wire::ValidateCommands(command.data(), command.size(), error));
    }
    for (const uint8_t value : std::array<uint8_t, 7>{0, 1, 8, 9, 10, 11, 255}) {
        CHECK(!pmkext::wire::EncodeVerdict(1, static_cast<pmkext::Verdict>(value), command, error));
        command[9] = value;
        CHECK(!pmkext::wire::ValidateCommands(command.data(), command.size(), error));
    }
    Bytes batch{0, 4, 5, 6, 7, 8};
    for (const auto kind : {uint8_t{2}, uint8_t{3}}) {
        const size_t size = kind == 2 ? 15 : 39;
        Bytes update(size, 0); update[0] = kind; update.back() = 3;
        CHECK(!pmkext::wire::ValidateCommands(update.data(), update.size(), error));
        CHECK(error.find("not supported") != std::string::npos);
        update.back() = 9;
        CHECK(!pmkext::wire::ValidateCommands(update.data(), update.size(), error));
        CHECK(!pmkext::wire::ValidateCommands(update.data(), update.size() - 1, error));
    }
    CHECK(pmkext::wire::ValidateCommands(batch.data(), batch.size(), error));
    batch.push_back(255); // A valid prefix does not make a malformed batch valid.
    CHECK(!pmkext::wire::ValidateCommands(batch.data(), batch.size(), error));
    CHECK(!pmkext::wire::ValidateCommands(nullptr, 0, error));
    CHECK(!pmkext::wire::ValidateCommands(command.data(), 9, error));
    Bytes maximum(pmkext::wire::kMaxCommandBatchSize, 4);
    CHECK(pmkext::wire::ValidateCommands(maximum.data(), maximum.size(), error));
    maximum.push_back(4);
    CHECK(!pmkext::wire::ValidateCommands(maximum.data(), maximum.size(), error));
    return true;
}

bool TestDeviceOnlySession() {
    pmkext::Driver driver;
    std::string error;
    uint8_t version[4]{};
    CHECK(!driver.GetVersion(version, error) && error == "device not open");
    CHECK(!driver.SendVerdict(1, pmkext::Verdict::Accept, error) && error == "device not open");
    CHECK(!driver.RequestLogs(error) && error == "device not open");
    CHECK(!driver.Install(L"unused.sys", error));
    CHECK(error.find("automatic installation is not supported") != std::string::npos);
    unsigned warnings = 0;
    unsigned connections = 0;
    pmkext::Handlers handlers;
    handlers.on_warning = [&](const std::string& warning) {
        if (warning == "Run called without an open device") ++warnings;
    };
    handlers.on_connection = [&](const auto&) { ++connections; };
    driver.Run(handlers, 1);
    CHECK(warnings == 1 && connections == 0);
    driver.Stop();
    driver.Cleanup();
    driver.Cleanup();
    CHECK(!driver.GetVersion(version, error) && error == "device not open");
    return true;
}

} // namespace

int main() {
    const struct { const char* name; bool (*run)(); } tests[] = {
        {"IPv4/IPv6 exact Portmaster ABI and LWF directions", TestConnectionAbi},
        {"malformed records and metadata rejected before callbacks", TestInvalidRecords},
        {"logs and real compatibility records (no synthesized ends)", TestLogsAndCompatibilityTypes},
        {"fragmented/coalesced records, idle reads and bounded headers", TestStreaming},
        {"unframed commands, verdict bytes 2..7, updates rejected, bounded batches", TestCommands},
        {"device-only lifecycle without installation or device access", TestDeviceOnlySession},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
