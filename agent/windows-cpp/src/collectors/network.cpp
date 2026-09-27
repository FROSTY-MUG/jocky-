#include "collectors/network.hpp"
#include "errors.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tcpmib.h>
#include <iphlpapi.h>
#include <vector>

namespace jocky {

std::string format_ipv4(DWORD ip) {
    char buf[16];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return std::string(buf);
}

std::string state_to_string(DWORD state) {
    switch (state) {
        case MIB_TCP_STATE_CLOSED: return "CLOSED";
        case MIB_TCP_STATE_LISTEN: return "LISTEN";
        case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
        case MIB_TCP_STATE_SYN_RCVD: return "SYN_RCVD";
        case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
        case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT_1";
        case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT_2";
        case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
        case MIB_TCP_STATE_CLOSING: return "CLOSING";
        case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
        case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
        case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

nlohmann::json NetworkCollector::collect() {
    nlohmann::json result = nlohmann::json::array();

    ULONG size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::vector<uint8_t> tcp_buf(size);
    if (GetExtendedTcpTable(tcp_buf.data(), &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        auto table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tcp_buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            auto& row = table->table[i];
            result.push_back({
                {"proto", "TCP"},
                {"local_addr", format_ipv4(row.dwLocalAddr)},
                {"local_port", ntohs((u_short)row.dwLocalPort)},
                {"remote_addr", format_ipv4(row.dwRemoteAddr)},
                {"remote_port", ntohs((u_short)row.dwRemotePort)},
                {"state", state_to_string(row.dwState)},
                {"pid", row.dwOwningPid}
            });
        }
    }

    size = 0;
    GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    std::vector<uint8_t> udp_buf(size);
    if (GetExtendedUdpTable(udp_buf.data(), &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        auto table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(udp_buf.data());
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            auto& row = table->table[i];
            result.push_back({
                {"proto", "UDP"},
                {"local_addr", format_ipv4(row.dwLocalAddr)},
                {"local_port", ntohs((u_short)row.dwLocalPort)},
                {"remote_addr", ""},
                {"remote_port", 0},
                {"state", ""},
                {"pid", row.dwOwningPid}
            });
        }
    }

    return result;
}

} // namespace jocky
