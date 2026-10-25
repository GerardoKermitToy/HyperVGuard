#include "HyperVGuard.hpp"
#include <cstdio>

int main() {
    hypervguard::Client driver;
    DWORD error = driver.Open();
    if (error) { std::fprintf(stderr, "Open failed: %lu\n", error); return 1; }
    uint32_t devices = 0;
    error = driver.GetFilteredDeviceCount(devices);
    if (error) { std::fprintf(stderr, "Device count failed: %lu\n", error); return 1; }
    std::printf("Filtered network devices: %u\n", devices);

    struct State { hypervguard::Client& driver; DWORD error = 0; uint64_t packets = 0; } state{driver};
    hypervguard::Client::Callbacks callbacks;
    callbacks.context = &state;
    callbacks.on_connection = [](void* context, const hypervguard::Client::Connection& packet) {
        auto& s = *static_cast<State*>(context);
        ++s.packets;
        // Borrowed packet.payload is valid only inside this callback. No per-packet printing.
        s.error = s.driver.SendVerdict(packet.id, hypervguard::Client::Verdict::PermanentAccept);
        if (s.error) s.driver.Stop();
    };
    error = driver.Run(callbacks, 10'000); // Bounded example: 10 seconds, no driver lifecycle.
    driver.Close();
    if (!error) error = state.error;
    std::printf("NBL events: %llu; result: %lu\n", static_cast<unsigned long long>(state.packets), error);
    return error ? 1 : 0;
}
