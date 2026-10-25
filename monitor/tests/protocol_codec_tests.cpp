#include "DriverProtocol.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#define CHECK(expression) do { if (!(expression)) { \
    std::fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #expression); return false; } } while (false)

namespace {

using Bytes = std::vector<uint8_t>;

template<class T>
concept HasProcessId = requires(T value) { value.process_id; };
static_assert(!HasProcessId<pmkext::Connection>);
static_assert(HasProcessId<pmkext::ConnectionEnd>);
static_assert(sizeof(pmkext::wire::RecordStream) < 1024, "record storage must live on the heap");
static_assert(sizeof(pmkext::Driver) < 1024, "Driver must not embed a large record buffer");
static_assert(pmkext::wire::kConnectionIpv4PrefixSize == 32);
static_assert(pmkext::wire::kConnectionIpv6PrefixSize == 56);
static_assert(pmkext::wire::kMaxPayloadSize == 1'048'576);
static_assert(pmkext::wire::kMaxRecordSize == 1'048'632);
static_assert(pmkext::wire::kMaxLogRecordSize == 512);

// Complete UDP/IP packets. Wire metadata uses LE ports, while these unmodified
// packet bytes retain network byte order. Neither Connection fixture has a PID.
constexpr uint8_t kIpv4Packet[] = {
    0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11,
    0x54, 0x9b, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
    0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
};
constexpr uint8_t kIpv6Packet[] = {
    0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x92, 0x00,
};
constexpr uint8_t kConnectionIpv4[] = {
    1, 0x37, 0, 0, 0,                         // Type 1, body = 27 + 28.
    8, 7, 6, 5, 4, 3, 2, 1,                 // ID, immediately followed by direction.
    0, 17,
    10, 0, 0, 1, 10, 0, 0, 2,
    0x34, 0x12, 0x35, 0x00,
    3, 0x1c, 0, 0, 0,
    0x45, 0x00, 0x00, 0x1c, 0x12, 0x34, 0x00, 0x00, 0x40, 0x11,
    0x54, 0x9b, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
    0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
};
constexpr uint8_t kConnectionIpv6[] = {
    2, 0x63, 0, 0, 0,                         // Type 2, body = 51 + 48.
    8, 7, 6, 5, 4, 3, 2, 1,
    0, 17,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    0x34, 0x12, 0x35, 0x00,
    3, 0x30, 0, 0, 0,
    0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x11, 0x40,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    0x12, 0x34, 0x00, 0x35, 0x00, 0x08, 0x92, 0x00,
};
static_assert(sizeof(kConnectionIpv4) == 32 + sizeof(kIpv4Packet));
static_assert(sizeof(kConnectionIpv6) == 56 + sizeof(kIpv6Packet));

// Legacy END records retain their original eight-byte PID=0 field and layout.
constexpr uint8_t kConnectionEndIpv4[] = {
    3, 0x16, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 17,
    10, 0, 0, 1, 10, 0, 0, 2,
    0x34, 0x12, 0x35, 0x00,
};
constexpr uint8_t kConnectionEndIpv6[] = {
    4, 0x2e, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 17,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    0x34, 0x12, 0x35, 0x00,
};
static_assert(sizeof(kConnectionEndIpv4) == 27);
static_assert(sizeof(kConnectionEndIpv6) == 51);

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
void StoreU32(Bytes& b, size_t offset, uint32_t value) {
    for (unsigned i = 0; i < 4; ++i) b[offset + i] = static_cast<uint8_t>(value >> (i * 8));
}
void FixBodySize(Bytes& b) {
    StoreU32(b, 1, static_cast<uint32_t>(b.size() - 5));
}
Bytes Record(uint8_t type, const Bytes& payload) {
    Bytes b{type};
    U32(b, static_cast<uint32_t>(payload.size()));
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}
Bytes PacketFixture(bool v6) {
    return v6 ? Bytes(kIpv6Packet, kIpv6Packet + sizeof(kIpv6Packet))
              : Bytes(kIpv4Packet, kIpv4Packet + sizeof(kIpv4Packet));
}
Bytes ConnectionFixture(bool v6) {
    return v6 ? Bytes(kConnectionIpv6, kConnectionIpv6 + sizeof(kConnectionIpv6))
              : Bytes(kConnectionIpv4, kConnectionIpv4 + sizeof(kConnectionIpv4));
}
Bytes EndFixture(bool v6) {
    return v6 ? Bytes(kConnectionEndIpv6, kConnectionEndIpv6 + sizeof(kConnectionEndIpv6))
              : Bytes(kConnectionEndIpv4, kConnectionEndIpv4 + sizeof(kConnectionEndIpv4));
}
Bytes LogicalPacket(bool v6, size_t size) {
    const auto prefix = PacketFixture(v6);
    Bytes packet(size);
    std::copy(prefix.begin(), prefix.end(), packet.begin());
    for (size_t i = prefix.size(); i < size; ++i) {
        packet[i] = static_cast<uint8_t>(i * 37 + 11);
    }
    // Logical offload packets may exceed the IP header's 16-bit length fields.
    // The codec must preserve every supplied byte, not shorten to those fields.
    const size_t ip_size = v6 ? size - 40 : size;
    const uint16_t length = ip_size <= 65535 ? static_cast<uint16_t>(ip_size) : 0;
    const size_t offset = v6 ? 4 : 2;
    packet[offset] = static_cast<uint8_t>(length >> 8);
    packet[offset + 1] = static_cast<uint8_t>(length);
    return packet;
}
Bytes ConnectionRecord(bool v6, const Bytes& packet) {
    const auto fixture = ConnectionFixture(v6);
    const size_t prefix = v6 ? 56 : 32;
    Bytes b(fixture.begin(), fixture.begin() + prefix);
    StoreU32(b, prefix - 4, static_cast<uint32_t>(packet.size()));
    b.insert(b.end(), packet.begin(), packet.end());
    FixBodySize(b);
    return b;
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
        const auto bytes = ConnectionFixture(v6);
        const auto packet = PacketFixture(v6);
        CHECK(bytes.size() == (v6 ? 104u : 60u));
        CHECK(bytes[0] == (v6 ? 2 : 1));
        CHECK(bytes[1] == (v6 ? 99 : 55));
        const uint8_t id[] = {8, 7, 6, 5, 4, 3, 2, 1};
        CHECK(std::memcmp(bytes.data() + 5, id, 8) == 0);
        CHECK(bytes[13] == 0 && bytes[14] == 17); // No intervening PID.
        CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        CHECK(observed.id == 0x0102030405060708ULL);
        CHECK(observed.ipv6 == v6 && observed.direction == 0 && observed.protocol == 17);
        CHECK(observed.local_port == 0x1234 && observed.remote_port == 53);
        CHECK(observed.payload_layer == 3 && observed.payload_size == packet.size());
        CHECK(observed.payload == packet);
        CHECK(observed.PayloadHexString() == (v6
            ? "6000000000081140"
              "20010db8000000000000000000000001"
              "20010db8000000000000000000000002"
              "1234003500089200"
            : "4500001c123400004011549b0a0000010a000002"
              "1234003500080000"));
        CHECK(observed.LocalIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0001" : "10.0.0.1"));
        CHECK(observed.RemoteIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0002" : "10.0.0.2"));
    }
    for (bool v6 : {false, true}) {
        auto bytes = ConnectionFixture(v6);
        bytes[13] = 1;
        CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        CHECK(observed.direction == 1 && observed.ipv6 == v6);
        CHECK(observed.local_port == 0x1234 && observed.remote_port == 53);
        CHECK(observed.payload == PacketFixture(v6)); // Direction never rewrites IP bytes.
    }
    CHECK(calls == 4 && ends == 0);
    CHECK(std::string(pmkext::DirectionToString(0)) == "outbound");
    CHECK(std::string(pmkext::DirectionToString(1)) == "inbound");
    CHECK(std::string(pmkext::DirectionToString(2)) == "unknown");
    CHECK(pmkext::wire::kIoctlVersion == 0x9c40e000u);
    CHECK(pmkext::wire::kIoctlShutdown == 0x9c40e004u);
    return true;
}

bool TestRequiredVersion() {
    const std::array<uint8_t, 4> expected = {0, 3, 0, 0};
    CHECK(pmkext::wire::kRequiredDeviceVersion == expected);
    CHECK(pmkext::wire::IsCompatibleVersion(expected.data()));
    CHECK(!pmkext::wire::IsCompatibleVersion(nullptr));
    for (const auto version : std::array<std::array<uint8_t, 4>, 7>{{
            {0, 2, 1, 0}, {0, 2, 0, 0}, {0, 0, 0, 0}, {0, 3, 0, 1},
            {0, 3, 1, 0}, {0, 4, 0, 0}, {1, 3, 0, 0}}}) {
        CHECK(!pmkext::wire::IsCompatibleVersion(version.data()));
    }
    return true;
}

bool TestLargeConnections() {
    std::string error;
    pmkext::Connection observed;
    unsigned calls = 0;
    pmkext::Handlers handlers;
    handlers.on_connection = [&](const auto& c) { observed = c; ++calls; };
    for (bool v6 : {false, true}) {
        for (const size_t size : {size_t{257}, size_t{65536}, size_t{65537}, pmkext::wire::kMaxPayloadSize}) {
            const auto packet = LogicalPacket(v6, size);
            const auto bytes = ConnectionRecord(v6, packet);
            CHECK(bytes.size() == (v6 ? 56 : 32) + size);
            CHECK(bytes.size() <= pmkext::wire::kMaxRecordSize);
            CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
            CHECK(observed.ipv6 == v6 && observed.id == 0x0102030405060708ULL);
            CHECK(observed.payload_size == size && observed.payload == packet);
            CHECK(observed.payload_layer == 3 && observed.local_port == 0x1234 && observed.remote_port == 53);
            const auto hex = observed.PayloadHexString();
            CHECK(hex.size() == size * 2);
            CHECK(hex.substr(0, 2) == (v6 ? "60" : "45"));
            constexpr char digits[] = "0123456789abcdef";
            CHECK(hex[hex.size() - 2] == digits[packet.back() >> 4]);
            CHECK(hex.back() == digits[packet.back() & 15]);
        }
    }
    CHECK(calls == 8);
    return true;
}

bool TestInvalidRecords() {
    std::string error;
    unsigned callbacks = 0;
    pmkext::Handlers handlers;
    handlers.on_connection = [&](const auto&) { ++callbacks; };
    handlers.on_connection_end = [&](const auto&) { ++callbacks; };
    handlers.on_log = [&](const auto&) { ++callbacks; };
    handlers.on_bandwidth = [&](const auto&) { ++callbacks; };
    for (bool v6 : {false, true}) {
        const size_t prefix = v6 ? 56 : 32;
        const auto fixture = ConnectionFixture(v6);
        for (size_t length = 0; length < 5; ++length) {
            CHECK(!pmkext::wire::DispatchRecord(fixture.data(), length, handlers, error));
        }
        for (const size_t modified : {size_t{13}, prefix - 5}) {
            auto bytes = fixture;
            bytes[modified] = modified == 13 ? 2 : 4; // Direction or payload layer.
            CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        }
        for (const uint32_t length : {uint32_t{0}, uint32_t{1},
                static_cast<uint32_t>(PacketFixture(v6).size() - 1),
                static_cast<uint32_t>(PacketFixture(v6).size() + 1),
                static_cast<uint32_t>(pmkext::wire::kMaxPayloadSize + 1),
                std::numeric_limits<uint32_t>::max()}) {
            auto bytes = fixture;
            StoreU32(bytes, prefix - 4, length);
            CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        }
        auto bytes = fixture;
        bytes.resize(prefix - 1);
        FixBodySize(bytes);
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        bytes.pop_back();
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        FixBodySize(bytes);
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        bytes.push_back(0); // No hidden extension or trailing packet bytes.
        FixBodySize(bytes);
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        StoreU32(bytes, 1, std::numeric_limits<uint32_t>::max());
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        bytes.insert(bytes.begin() + 13, 8, 0); // Old Connection PID field is not an extension.
        FixBodySize(bytes);
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
    }
    // IPv4 has 24 fewer prefix bytes: a payload above 1 MiB can fit under the
    // global IPv6 frame bound, so payload_size needs its own explicit check.
    auto oversized = ConnectionRecord(false, LogicalPacket(false, pmkext::wire::kMaxPayloadSize + 1));
    CHECK(oversized.size() <= pmkext::wire::kMaxRecordSize);
    CHECK(!pmkext::wire::DispatchRecord(oversized.data(), oversized.size(), handlers, error));
    CHECK(error.find("1 MiB") != std::string::npos);
    oversized = ConnectionRecord(true, LogicalPacket(true, pmkext::wire::kMaxPayloadSize + 1));
    CHECK(oversized.size() == pmkext::wire::kMaxRecordSize + 1);
    CHECK(!pmkext::wire::DispatchRecord(oversized.data(), oversized.size(), handlers, error));
    CHECK(!pmkext::wire::DispatchRecord(nullptr, 5, handlers, error));
    for (const Bytes& malformed : {Record(1, {}), Record(2, {}), Record(0, {}), Record(0, {0, 'x'}),
                                   Record(0, {8, 'x'}), Record(255, {}),
                                   Record(5, {17, 255, 255, 255, 255}), Record(6, {17, 1, 0, 0, 0})}) {
        CHECK(!pmkext::wire::DispatchRecord(malformed.data(), malformed.size(), handlers, error));
    }
    CHECK(callbacks == 0);
    return true;
}

bool TestConnectionEndAbi() {
    std::string error;
    unsigned ends = 0, connections = 0;
    pmkext::ConnectionEnd observed;
    pmkext::Handlers handlers;
    handlers.on_connection = [&](const auto&) { ++connections; };
    handlers.on_connection_end = [&](const auto& end) { observed = end; ++ends; };
    for (bool v6 : {false, true}) {
        const auto fixture = EndFixture(v6);
        CHECK(fixture.size() == (v6 ? 51u : 27u));
        for (uint8_t direction : {uint8_t{0}, uint8_t{1}}) {
            auto bytes = fixture;
            bytes[13] = direction;
            CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
            CHECK(observed.ipv6 == v6 && observed.process_id == 0);
            CHECK(observed.direction == direction && observed.protocol == 17);
            CHECK(observed.local_port == 0x1234 && observed.remote_port == 53);
            CHECK(observed.LocalIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0001" : "10.0.0.1"));
            CHECK(observed.RemoteIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0002" : "10.0.0.2"));
        }
        auto bytes = fixture;
        bytes[5] = 1; // Legacy PID must still be zero.
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        bytes[13] = 2;
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        bytes.push_back(0);
        FixBodySize(bytes);
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        bytes = fixture;
        bytes.pop_back();
        FixBodySize(bytes);
        CHECK(!pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
    }
    CHECK(ends == 4 && connections == 0);
    return true;
}

bool TestLogsAndBandwidth() {
    std::string error;
    unsigned logs = 0, ends = 0, bandwidth = 0;
    pmkext::LogLine observed_log;
    pmkext::BandwidthStats observed_stats;
    pmkext::Handlers handlers;
    handlers.on_log = [&](const auto& line) { observed_log = line; ++logs; };
    handlers.on_connection_end = [&](const auto&) { ++ends; };
    handlers.on_bandwidth = [&](const auto& stats) { observed_stats = stats; ++bandwidth; };
    const auto log = Record(0, {3, 'h', 'e', 'l', 'l', 'o'});
    CHECK(pmkext::wire::DispatchRecord(log.data(), log.size(), handlers, error));
    CHECK(logs == 1 && observed_log.severity == pmkext::Severity::Info && observed_log.message == "hello");
    Bytes message(pmkext::wire::kMaxLogRecordSize - 5, 'x');
    message[0] = 3;
    auto maximum_log = Record(0, message);
    CHECK(maximum_log.size() == 512);
    CHECK(pmkext::wire::DispatchRecord(maximum_log.data(), maximum_log.size(), handlers, error));
    CHECK(logs == 2 && observed_log.message.size() == 506);
    message.push_back('x');
    maximum_log = Record(0, message);
    CHECK(!pmkext::wire::DispatchRecord(maximum_log.data(), maximum_log.size(), handlers, error));
    CHECK(logs == 2);
    for (bool v6 : {false, true}) {
        const auto fixture = ConnectionFixture(v6);
        const size_t addr_size = v6 ? 16 : 4;
        Bytes stats{17}; U32(stats, 1);
        stats.insert(stats.end(), fixture.begin() + 15, fixture.begin() + 15 + addr_size);
        U16(stats, 0x1234);
        stats.insert(stats.end(), fixture.begin() + 15 + addr_size, fixture.begin() + 15 + addr_size * 2);
        U16(stats, 53);
        U64(stats, 123); U64(stats, 456);
        const auto bytes = Record(v6 ? 6 : 5, stats);
        CHECK(pmkext::wire::DispatchRecord(bytes.data(), bytes.size(), handlers, error));
        CHECK(observed_stats.protocol == 17 && observed_stats.entries.size() == 1);
        const auto& entry = observed_stats.entries.front();
        CHECK(entry.ipv6 == v6 && entry.local_port == 0x1234 && entry.remote_port == 53);
        CHECK(entry.transmitted_bytes == 123 && entry.received_bytes == 456);
        CHECK(entry.LocalIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0001" : "10.0.0.1"));
        CHECK(entry.RemoteIpString() == (v6 ? "2001:0db8:0000:0000:0000:0000:0000:0002" : "10.0.0.2"));
    }
    CHECK(ends == 0 && bandwidth == 2); // No END is fabricated from other records.
    return true;
}

bool TestStreaming() {
    const auto v4 = ConnectionFixture(false);
    const auto v6 = ConnectionFixture(true);
    const auto end = EndFixture(false);
    const auto log = Record(0, {3, 'o', 'k'});
    Bytes combined = v4;
    combined.insert(combined.end(), log.begin(), log.end());
    combined.insert(combined.end(), v6.begin(), v6.end());
    combined.insert(combined.end(), end.begin(), end.end());
    for (size_t chunk = 1; chunk <= combined.size(); ++chunk) {
        pmkext::wire::RecordStream stream;
        std::string error;
        std::vector<Bytes> observed;
        auto collect = [&](const uint8_t* p, size_t n) { observed.emplace_back(p, p + n); };
        for (size_t offset = 0; offset < combined.size(); offset += chunk) {
            const size_t size = std::min(chunk, combined.size() - offset);
            CHECK(stream.Feed(combined.data() + offset, size, collect, error));
            // Empty successful reads are idle, not EOF or a partial-frame flush.
            const auto before = stream.PendingBytes();
            CHECK(stream.Feed(nullptr, 0, collect, error));
            CHECK(stream.PendingBytes() == before);
        }
        CHECK(stream.PendingBytes() == 0 && observed.size() == 4);
        CHECK(observed[0] == v4 && observed[1] == log && observed[2] == v6 && observed[3] == end);
    }
    return true;
}

bool TestStreamingMaximumRecords() {
    const auto packet4 = LogicalPacket(false, pmkext::wire::kMaxPayloadSize);
    const auto packet6 = LogicalPacket(true, pmkext::wire::kMaxPayloadSize);
    const auto v4 = ConnectionRecord(false, packet4);
    const auto v6 = ConnectionRecord(true, packet6);
    const auto log = Record(0, {3, 'o', 'k'});
    const auto end = EndFixture(true);
    CHECK(v4.size() == pmkext::wire::kMaxPayloadSize + 32);
    CHECK(v6.size() == pmkext::wire::kMaxRecordSize);
    const std::array<const Bytes*, 5> expected = {&log, &v4, &log, &v6, &end};
    Bytes combined;
    for (const auto* record : expected) combined.insert(combined.end(), record->begin(), record->end());
    for (const size_t chunk : {size_t{65536}, size_t{65535}, size_t{4093}}) {
        pmkext::wire::RecordStream stream;
        std::string error;
        size_t records = 0;
        unsigned connections = 0, logs = 0, ends = 0;
        bool valid = true;
        pmkext::Handlers handlers;
        handlers.on_connection = [&](const auto& c) {
            valid = valid && c.payload_size == pmkext::wire::kMaxPayloadSize &&
                    c.payload == (c.ipv6 ? packet6 : packet4);
            ++connections;
        };
        handlers.on_log = [&](const auto&) { ++logs; };
        handlers.on_connection_end = [&](const auto&) { ++ends; };
        auto collect = [&](const uint8_t* p, size_t n) {
            if (records >= expected.size() || n != expected[records]->size() ||
                std::memcmp(p, expected[records]->data(), n) != 0) valid = false;
            std::string decode_error;
            if (!pmkext::wire::DispatchRecord(p, n, handlers, decode_error)) valid = false;
            ++records;
        };
        CHECK(stream.Feed(combined.data(), 1, collect, error));
        CHECK(stream.Feed(combined.data() + 1, 2, collect, error));
        CHECK(records == 0 && stream.PendingBytes() == 3);
        for (size_t offset = 3; offset < combined.size(); offset += chunk) {
            const size_t size = std::min(chunk, combined.size() - offset);
            CHECK(size <= 65536);
            CHECK(stream.Feed(combined.data() + offset, size, collect, error));
            CHECK(stream.PendingBytes() <= pmkext::wire::kMaxRecordSize);
            const auto pending = stream.PendingBytes();
            CHECK(stream.Feed(nullptr, 0, collect, error));
            CHECK(stream.PendingBytes() == pending);
        }
        CHECK(valid && records == expected.size() && stream.PendingBytes() == 0);
        CHECK(connections == 2 && logs == 2 && ends == 1);
    }
    return true;
}

bool TestStreamFailureAndReset() {
    const auto v4 = ConnectionFixture(false);
    const auto log = Record(0, {3, 'o', 'k'});
    pmkext::wire::RecordStream stream;
    std::string error;
    unsigned calls = 0;
    auto callback = [&](const auto*, auto) { ++calls; };
    for (const size_t partial : {size_t{1}, size_t{4}, size_t{5}, size_t{6}, size_t{31}, v4.size() - 1}) {
        stream.Reset();
        calls = 0;
        CHECK(stream.Feed(v4.data(), partial, callback, error));
        CHECK(calls == 0 && stream.PendingBytes() == partial);
        stream.Reset();
        CHECK(stream.PendingBytes() == 0);
        CHECK(stream.Feed(log.data(), log.size(), callback, error));
        CHECK(calls == 1 && stream.PendingBytes() == 0);
    }
    const auto large = ConnectionRecord(true, LogicalPacket(true, 65537));
    stream.Reset();
    calls = 0;
    CHECK(stream.Feed(large.data(), 65536, callback, error));
    CHECK(calls == 0 && stream.PendingBytes() == 65536);
    stream.Reset();
    CHECK(stream.Feed(v4.data(), v4.size(), callback, error));
    CHECK(calls == 1 && stream.PendingBytes() == 0);
    for (const uint32_t length : {static_cast<uint32_t>(pmkext::wire::kMaxRecordSize - 5 + 1),
                                  std::numeric_limits<uint32_t>::max()}) {
        stream.Reset();
        calls = 0;
        Bytes oversized{2}; U32(oversized, length);
        Bytes combined = log;
        combined.insert(combined.end(), oversized.begin(), oversized.end());
        combined.insert(combined.end(), v4.begin(), v4.end());
        // A valid prefix is delivered, but no plausible frame in the suffix is
        // guessed as a new boundary after the fragmented oversized header.
        CHECK(stream.Feed(combined.data(), log.size() + 2, callback, error));
        CHECK(calls == 1 && stream.PendingBytes() == 2);
        CHECK(!stream.Feed(combined.data() + log.size() + 2,
                           combined.size() - log.size() - 2, callback, error));
        CHECK(calls == 1 && stream.PendingBytes() == 5);
        CHECK(!stream.Feed(v4.data(), v4.size(), callback, error));
        CHECK(!stream.Feed(nullptr, 0, callback, error));
        CHECK(calls == 1);
        stream.Reset();
        CHECK(stream.Feed(log.data(), log.size(), callback, error));
        CHECK(calls == 2 && stream.PendingBytes() == 0);
    }
    stream.Reset();
    calls = 0;
    CHECK(stream.Feed(v4.data(), 2, callback, error));
    CHECK(!stream.Feed(nullptr, 1, callback, error));
    CHECK(stream.PendingBytes() == 2 && calls == 0);
    CHECK(stream.Feed(v4.data() + 2, v4.size() - 2, callback, error));
    CHECK(calls == 1 && stream.PendingBytes() == 0);
    CHECK(stream.Feed(v4.data(), v4.size(), {}, error));
    CHECK(calls == 1 && stream.PendingBytes() == 0);
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
        {"IPv4/IPv6 exact PID-less wire fixtures and complete IP packets", TestConnectionAbi},
        {"only wire version 0.3.0.0 is compatible", TestRequiredVersion},
        {"full packets above 256/65536 bytes and at the 1 MiB maximum", TestLargeConnections},
        {"malformed records, metadata and oversized payloads rejected before callbacks", TestInvalidRecords},
        {"legacy ConnectionEnd IPv4/IPv6 layout and zero PID unchanged", TestConnectionEndAbi},
        {"512-byte log bound and unchanged bandwidth layouts", TestLogsAndBandwidth},
        {"fragmented/coalesced records and idle reads", TestStreaming},
        {"maximum IPv4/IPv6 records across many bounded reads", TestStreamingMaximumRecords},
        {"oversized headers poison the stream; partial/failed streams reset safely", TestStreamFailureAndReset},
        {"unframed commands, verdict bytes 2..7, updates rejected, bounded batches", TestCommands},
        {"device-only lifecycle without installation or device access", TestDeviceOnlySession},
    };
    for (const auto& test : tests) {
        if (!test.run()) return 1;
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
