#pragma once

#include "PortmasterKext.h"

#include <windows.h>

#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace pmkext {

// Keep every part of a record under one lock, including the final flush.
class RecordOutput {
public:
    RecordOutput(FILE* output, std::mutex& mutex)
        : guard_(mutex), output_(output) {}

    ~RecordOutput() {
        if (output_ != nullptr) {
            std::fflush(output_);
        }
    }

    RecordOutput(const RecordOutput&) = delete;
    RecordOutput& operator=(const RecordOutput&) = delete;

    void Write(const char* format, ...) {
        va_list args;
        va_start(args, format);
        WriteV(format, args);
        va_end(args);
    }

    void WriteV(const char* format, va_list args) {
        if (output_ != nullptr) {
            std::vfprintf(output_, format, args);
        }
    }

    void WriteConnection(const Connection& c, const char* prefix) {
        Write("%s[CONN %s] id=%llu interface_index=%u %s proto=%u(%s) layer=%u(%s)\n"
              "          local(guest)=%s:%u  remote(peer)=%s:%u  payload=%u bytes\n",
              prefix, c.ipv6 ? "v6" : "v4", static_cast<unsigned long long>(c.id),
              static_cast<unsigned>(c.interface_index), DirectionToString(c.direction),
              static_cast<unsigned>(c.protocol), ProtocolToString(c.protocol),
              static_cast<unsigned>(c.payload_layer), PayloadLayerToString(c.payload_layer),
              c.LocalIpString().c_str(), static_cast<unsigned>(c.local_port),
              c.RemoteIpString().c_str(), static_cast<unsigned>(c.remote_port),
              static_cast<unsigned>(c.payload_size));
    }

    void WriteAdapters(const AdapterSnapshot& snapshot, const char* prefix) {
        Write("%sAttached network adapters: %zu (running=%u; host NDIS modules)\n",
              prefix, snapshot.adapters.size(), snapshot.running_count);
        for (const auto& a : snapshot.adapters) {
            Write("%s[ADAPTER] module_id=%llu interface_index=%u state=%s flags=0x%02X\n",
                  prefix, static_cast<unsigned long long>(a.module_id), a.interface_index,
                  a.flags & AdapterInfo::Running ? "running" : "not-running", a.flags);
            Write("          instance_name=%s%s\n          base_name=%s%s\n          filter_module_name=%s%s\n",
                  DisplayName(a.instance_name).c_str(), a.flags & AdapterInfo::InstanceNameTruncated ? " [truncated]" : "",
                  DisplayName(a.base_name).c_str(), a.flags & AdapterInfo::BaseNameTruncated ? " [truncated]" : "",
                  DisplayName(a.filter_module_name).c_str(), a.flags & AdapterInfo::FilterModuleNameTruncated ? " [truncated]" : "");
            const auto& g = a.interface_guid;
            Write("          interface_guid={%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}\n",
                  g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
                  g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
            Write("          interface_luid=0x%016llX filter_interface_index=%u filter_interface_luid=0x%016llX\n"
                  "          lower_interface_index=%u lower_interface_luid=0x%016llX\n",
                  static_cast<unsigned long long>(a.interface_luid), a.filter_interface_index,
                  static_cast<unsigned long long>(a.filter_interface_luid), a.lower_interface_index,
                  static_cast<unsigned long long>(a.lower_interface_luid));
            Write("          mac=");
            if (a.mac_address_length == 0) Write("(unavailable)");
            for (uint32_t i = 0; i < a.mac_address_length && i < a.mac_address.size(); ++i)
                Write("%s%02X", i == 0 ? "" : ":", a.mac_address[i]);
            Write(" media_type=%u physical_medium=%u attach_flags=0x%08X connector=%s\n",
                  a.media_type, a.physical_medium, a.attach_flags,
                  !(a.flags & AdapterInfo::ConnectorPresentValid) ? "unknown" : a.connector_present ? "present" : "absent");
            const char* link = a.media_connect_state == 1 ? "connected" : a.media_connect_state == 2 ? "disconnected" : "unknown";
            const char* duplex = a.media_duplex_state == 2 ? "full" : a.media_duplex_state == 1 ? "half" : "unknown";
            Write("          link=%s(%u) duplex=%s(%u) tx_bps=%s rx_bps=%s\n",
                  link, a.media_connect_state, duplex, a.media_duplex_state,
                  SpeedText(a.xmit_link_speed).c_str(), SpeedText(a.rcv_link_speed).c_str());
            if (a.flags & AdapterInfo::LinkStateValid)
                Write("          auto_negotiation_flags=0x%08X (last link-state indication)\n", a.auto_negotiation_flags);
            else Write("          auto_negotiation_flags=unknown (no link-state indication)\n");
            if (a.flags & AdapterInfo::GeneralAttributesValid) {
                Write("          mtu=%u max_tx_bps=%s max_rx_bps=%s lookahead_size=%u\n"
                      "          mac_options=0x%08X supported_packet_filters=0x%08X max_multicast_list_size=%u\n"
                      "          access_type=%u connection_type=%u supported_statistics=0x%08X\n"
                      "          data_backfill_size=%u context_backfill_size=%u restart_flags=0x%08X\n",
                      a.mtu, SpeedText(a.max_xmit_link_speed).c_str(), SpeedText(a.max_rcv_link_speed).c_str(),
                      a.lookahead_size, a.mac_options, a.supported_packet_filters, a.max_multicast_list_size,
                      a.access_type, a.connection_type, a.supported_statistics,
                      a.data_backfill_size, a.context_backfill_size, a.restart_flags);
            } else Write("          mtu/general_attributes=unknown (not supplied by NDIS restart)\n");
            if (a.flags & AdapterInfo::PauseValid)
                Write("          last_pause_reason=0x%08X last_pause_flags=0x%08X\n", a.pause_reason, a.pause_flags);
            else Write("          last_pause=none observed\n");
        }
    }

private:
    static std::string SpeedText(uint64_t speed) {
        return speed == ~uint64_t{0} ? "unknown" : std::to_string(speed);
    }

    static std::string DisplayName(const std::wstring& name) {
        if (name.empty()) return "(unavailable)";
        const int size = WideCharToMultiByte(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), nullptr, 0, nullptr, nullptr);
        if (size == 0) return "(invalid UTF-16)";
        std::string utf8(static_cast<size_t>(size), '\0');
        if (WideCharToMultiByte(CP_UTF8, 0, name.data(), static_cast<int>(name.size()), utf8.data(), size, nullptr, nullptr) != size)
            return "(invalid UTF-16)";
        std::string escaped;
        for (unsigned char c : utf8) {
            if (c < 0x20 || c == 0x7f) {
                char buffer[5]{};
                std::snprintf(buffer, sizeof(buffer), "\\x%02X", c);
                escaped += buffer;
            } else escaped += static_cast<char>(c);
        }
        return escaped;
    }

    std::lock_guard<std::mutex> guard_;
    FILE* output_;
};

} // namespace pmkext
