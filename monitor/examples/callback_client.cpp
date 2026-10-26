#include "HyperVXNdisFilter.hpp"
#include <cstdio>

int main() {
    hypervxndisfilter::Client driver;
    DWORD error = driver.Open();
    if (error) { std::fprintf(stderr, "Open failed: %lu\n", error); return 1; }
    uint32_t devices = 0;
    error = driver.GetFilteredDeviceCount(devices);
    if (error) { std::fprintf(stderr, "Device count failed: %lu\n", error); return 1; }
    std::printf("Filtered network devices: %u\n", devices);

    struct State { hypervxndisfilter::Client& driver; DWORD error = 0; uint64_t packets = 0; } state{driver};
    hypervxndisfilter::Client::Callbacks callbacks;
    callbacks.context = &state;
    const auto accept = []<class T>(void* context, const T* packet, const uint8_t*, uint32_t) {
        auto& s = *static_cast<State*>(context);
        ++s.packets;
        // Header and payload point into the read buffer; valid only during this callback.
        s.error = s.driver.SendVerdict(packet->id, hypervxndisfilter::Client::Verdict::PermanentAccept);
        if (s.error) s.driver.Stop();
    };
    callbacks.on_connection_v4 = accept;
    callbacks.on_connection_v6 = accept;
    error = driver.Run(callbacks, 10'000); // Bounded example: 10 seconds, no driver lifecycle.
    driver.Close();
    if (!error) error = state.error;
    std::printf("NBL events: %llu; result: %lu\n", static_cast<unsigned long long>(state.packets), error);
    return error ? 1 : 0;
}
