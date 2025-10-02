#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <tins/tins.h>

#include <iostream>

using namespace Tins;

struct Stats {
    size_t packets = 0;
    size_t bytes = 0;
};

std::string resolve_hostname(const std::string& ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);

    char host[NI_MAXHOST];
    int res = getnameinfo((sockaddr*)&sa, sizeof(sa), host, sizeof(host),
                          nullptr, 0, NI_NAMEREQD);
    if (res == 0) {
        return std::string(host);
    } else {
        return ip;  // fallback if no hostname found
    }
}

int main() {
    try {
        // List available interfaces
        std::vector<NetworkInterface> interfaces = NetworkInterface::all();
        std::cout << "Available interfaces:\n";
        for (const auto& interface : interfaces) {
            std::cout << "\t" << interface.name();
            if (interface.info().ip_addr != IPv4Address())
                std::cout << "\t(IP: " << interface.info().ip_addr << ")";
            std::cout << "\n";
        }

        std::string interface_name;
        std::cout << "\nEnter interface to sniff: ";
        std::cin >> interface_name;

        if (auto it = std::find_if(
                interfaces.begin(), interfaces.end(),
                [&interface_name](const NetworkInterface& interface) {
                    return interface.name() == interface_name;
                });
            it == interfaces.end()) {
            throw std::runtime_error("Invalid interface");
            return 1;
        }

        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter("ip");

        std::unordered_map<std::string, Stats> traffic;
        std::unordered_map<std::string, std::string> ipToHostname;
        auto last_print = std::chrono::steady_clock::now();

        Sniffer sniffer(interface_name, config);

        sniffer.sniff_loop([&](PDU& pdu) {
            try {
                const IP& ip = pdu.rfind_pdu<IP>();
                std::string dst = ip.dst_addr().to_string();
                if (ipToHostname.find(dst) == ipToHostname.end()) {
                    ipToHostname[dst] = resolve_hostname(dst);
                } else {
                    dst = ipToHostname[dst];
                }

                auto& entry = traffic[dst];
                entry.packets++;
                entry.bytes += ip.size();
            } catch (std::exception&) {
            }

            auto now = std::chrono::steady_clock::now();
            if (now - last_print > std::chrono::seconds(1)) {
                system("clear");
                std::vector<std::pair<std::string, Stats>> sorted_traffic(
                    traffic.begin(), traffic.end());
                std::sort(sorted_traffic.begin(), sorted_traffic.end(),
                          [](const auto& a, const auto& b) {
                              return a.second.bytes > b.second.bytes;
                          });
                for (auto& [dst, stat] : sorted_traffic) {
                    std::cout << dst << "\t" << stat.packets << " packets\t"
                              << stat.bytes << " bytes\n";
                }
                last_print = now;
            }
            return true;
        });
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
}
