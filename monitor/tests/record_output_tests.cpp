// HyperVXNdisFilter adaptation, 2026-10-25: keep test files in the build directory.
// Original source provenance/license: ../README.md and ../LICENSE.
#include "RecordOutput.h"

#include <chrono>
#include <cstdio>
#include <future>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using File = std::unique_ptr<FILE, decltype(&std::fclose)>;

std::string ReadOutput(FILE* file) {
    std::rewind(file);
    std::string text;
    char buffer[1024];
    while (const size_t count = std::fread(buffer, 1, sizeof(buffer), file)) {
        text.append(buffer, count);
    }
    return text;
}

void Emit(FILE* file, std::mutex& mutex, const char* format, ...) {
    pmkext::RecordOutput record(file, mutex);
    va_list args;
    va_start(args, format);
    record.WriteV(format, args);
    va_end(args);
}

bool CheckFormattingAndNullOutput() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    Emit(file.get(), mutex, "[VERDICT] id=%llu -> %s\n", 1234567890123ULL, "Accept");
    if (ReadOutput(file.get()) != "[VERDICT] id=1234567890123 -> Accept\n") return false;
    {
        pmkext::RecordOutput record(nullptr, mutex);
        record.Write("ignored %u\n", 1u);
    }
    std::unique_lock<std::mutex> lock(mutex, std::try_to_lock);
    return lock.owns_lock();
}

bool CheckConnectionInterfaceIndices() {
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    std::string expected;
    pmkext::Connection c;
    c.id = 1234567890123ULL;
    c.protocol = 17;
    c.local_port = 12345;
    c.remote_port = 53;
    for (bool ipv6 : {false, true}) {
        c.ipv6 = ipv6;
        c.direction = ipv6 ? 1 : 0;
        c.payload_size = ipv6 ? 48 : 28;
        c.local_ip[0] = c.remote_ip[0] = ipv6 ? 0x20 : 10;
        c.local_ip[1] = c.remote_ip[1] = ipv6 ? 1 : 0;
        c.local_ip[3] = c.remote_ip[3] = 0;
        c.local_ip[ipv6 ? 15 : 3] = 1;
        c.remote_ip[ipv6 ? 15 : 3] = 2;
        const char* prefix = ipv6 ? "[12:34:56] " : "";
        const char* local = ipv6 ? "2001:0000:0000:0000:0000:0000:0000:0001" : "10.0.0.1";
        const char* remote = ipv6 ? "2001:0000:0000:0000:0000:0000:0000:0002" : "10.0.0.2";
        for (const uint32_t index : {0u, 101u, 0x87654321u, 101u, 0xffffffffu}) {
            c.interface_index = index;
            {
                pmkext::RecordOutput record(file.get(), mutex);
                record.WriteConnection(c, prefix);
            }
            expected += std::string(prefix) + "[CONN " + (ipv6 ? "v6" : "v4") +
                "] id=1234567890123 interface_index=" + std::to_string(index) +
                (ipv6 ? " inbound" : " outbound") + " proto=17(UDP) layer=3(network)\n" +
                "          local(guest)=" + local + ":12345  remote(peer)=" + remote +
                ":53  payload=" + (ipv6 ? "48" : "28") + " bytes\n";
        }
    }
    return ReadOutput(file.get()) == expected;
}

bool CheckWholeRecordLock() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    std::promise<bool> attempted;
    auto attempt = attempted.get_future();
    std::thread contender;
    bool locked_for_record = false;
    {
        pmkext::RecordOutput record(file.get(), mutex);
        record.Write("[CONN] id=13\n");
        contender = std::thread([&]() {
            const bool acquired = mutex.try_lock();
            if (acquired) mutex.unlock();
            attempted.set_value(acquired);
            Emit(file.get(), mutex, "[VERDICT] id=12\n");
        });
        if (attempt.wait_for(2s) == std::future_status::ready) {
            locked_for_record = !attempt.get();
        }
        record.Write("  payload: 1234\n");
        record.Write("  -> verdict Accept scheduled\n");
    }
    contender.join();
    return locked_for_record && ReadOutput(file.get()) ==
        "[CONN] id=13\n  payload: 1234\n  -> verdict Accept scheduled\n[VERDICT] id=12\n";
}

bool CheckExceptionReleasesLock() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    try {
        pmkext::RecordOutput record(file.get(), mutex);
        record.Write("first\n");
        throw std::runtime_error("test unwind");
    } catch (const std::runtime_error&) {
    }
    std::unique_lock<std::mutex> lock(mutex, std::try_to_lock);
    if (!lock.owns_lock()) return false;
    lock.unlock();
    Emit(file.get(), mutex, "second\n");
    return ReadOutput(file.get()) == "first\nsecond\n";
}

bool CheckConcurrentRecords() {
    // CTest sets cwd to the monitor build tree; never write a global temp file.
    File file(std::fopen("record_output_tests.tmp", "w+b"), std::fclose);
    if (!file) return false;
    std::mutex mutex;
    constexpr unsigned kItems = 250;
    std::vector<std::thread> producers;
    for (unsigned producer = 0; producer < 4; ++producer) {
        producers.emplace_back([&, producer]() {
            for (unsigned item = 0; item < kItems; ++item) {
                if (producer < 2) {
                    pmkext::RecordOutput record(file.get(), mutex);
                    record.Write("[CONN] p=%u i=%u\n", producer, item);
                    std::this_thread::yield();
                    record.Write("  payload=%u/%u\n", producer, item);
                    std::this_thread::yield();
                    record.Write("  verdict=%u/%u\n", producer, item);
                } else if (producer == 2) {
                    pmkext::RecordOutput record(file.get(), mutex);
                    record.Write("[BANDWIDTH] p=%u i=%u entries=2\n", producer, item);
                    std::this_thread::yield();
                    record.Write("  row=0 value=%u\n", item);
                    std::this_thread::yield();
                    record.Write("  row=1 value=%u\n", item);
                } else {
                    Emit(file.get(), mutex, "[VERDICT] p=%u i=%u\n", producer, item);
                }
            }
        });
    }
    for (auto& producer : producers) producer.join();
    std::istringstream stream(ReadOutput(file.get()));
    bool seen[4][kItems] = {};
    unsigned records = 0;
    std::string line;
    while (std::getline(stream, line)) {
        unsigned producer = 0;
        unsigned item = 0;
        if (std::sscanf(line.c_str(), "[CONN] p=%u i=%u", &producer, &item) == 2) {
            if (producer >= 2 || item >= kItems || seen[producer][item]) return false;
            const std::string tag = std::to_string(producer) + "/" + std::to_string(item);
            if (!std::getline(stream, line) || line != "  payload=" + tag) return false;
            if (!std::getline(stream, line) || line != "  verdict=" + tag) return false;
        } else if (std::sscanf(line.c_str(), "[BANDWIDTH] p=%u i=%u entries=2", &producer, &item) == 2) {
            if (producer != 2 || item >= kItems || seen[producer][item]) return false;
            if (!std::getline(stream, line) || line != "  row=0 value=" + std::to_string(item)) return false;
            if (!std::getline(stream, line) || line != "  row=1 value=" + std::to_string(item)) return false;
        } else if (std::sscanf(line.c_str(), "[VERDICT] p=%u i=%u", &producer, &item) == 2) {
            if (producer != 3 || item >= kItems || seen[producer][item]) return false;
        } else {
            return false;
        }
        seen[producer][item] = true;
        ++records;
    }
    return records == 4 * kItems;
}

int main() {
    const struct {
        const char* name;
        bool (*run)();
    } tests[] = {
        {"formatting and null output", CheckFormattingAndNullOutput},
        {"IPv4/IPv6 connection output includes each unsigned interface index after id", CheckConnectionInterfaceIndices},
        {"whole-record lock against a concurrent verdict", CheckWholeRecordLock},
        {"exception releases lock", CheckExceptionReleasesLock},
        {"1000 concurrent CONN/BANDWIDTH/VERDICT records", CheckConcurrentRecords},
    };
    for (const auto& test : tests) {
        if (!test.run()) {
            std::fprintf(stderr, "FAIL: %s\n", test.name);
            return 1;
        }
        std::printf("PASS: %s\n", test.name);
    }
    return 0;
}
