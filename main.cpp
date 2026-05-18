#include <iostream>
#include <tuple>
#include <cstdint>
#include <unordered_map>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pcap.h>

//define the 5-tuple
struct Flow5Tuple{
   uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol; 

    // Overload '==' and provide a hasher so it can be used in an unordered_map
    bool operator==(const Flow5Tuple& other) const //compare flows
    
     {
        return std::tie(src_ip, dst_ip, src_port, dst_port, protocol) ==
               std::tie(other.src_ip, other.dst_ip, other.src_port, other.dst_port, other.protocol);
    }
};

// Hash function for the 5-tuple to use in unordered_map [cite: 209]
//Μετατρέπει σε αριθμούς κάθε στειχείο ( όχι τυχαία) και μετά κάνει mixing XOR μεταξύ τους
//με το hash(port) << 1, hash(port) << 2 μετακινεί τα bits αριστερά Για να μην μοιάζουν πολύ μεταξύ τους και να μειωθούν collisions
//όλο αυτο καταλήγει σε ένα νούμερο
struct FlowHasher {
    std::size_t operator()(const Flow5Tuple& f) const {
        return std::hash<uint32_t>{}(f.src_ip) ^ std::hash<uint32_t>{}(f.dst_ip) ^ 
               (std::hash<uint16_t>{}(f.src_port) << 1) ^ (std::hash<uint16_t>{}(f.dst_port) << 2) ^ 
               f.protocol;
    }
};
struct FlowState {
    int packet_count = 0;
};

// Global flow table (similar to the Delay Register/Stateful memory in the paper) [cite: 178, 209]
//κρατάω πληροφορία για κάθε flow Που έχω δει
std::unordered_map<Flow5Tuple, FlowState, FlowHasher> flow_table;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Skip 14 bytes Ethernet header
    
    if (ip_header->ip_v != 4) return; // Only process IPv4 [cite: 118]

    Flow5Tuple id;
    id.src_ip = ip_header->ip_src.s_addr;
    id.dst_ip = ip_header->ip_dst.s_addr;
    id.protocol = ip_header->ip_p;

    // Extract ports for TCP/UDP
    if (id.protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        id.src_port = ntohs(tcp->th_sport);
        id.dst_port = ntohs(tcp->th_dport);
    } else if (id.protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        id.src_port = ntohs(udp->uh_sport);
        id.dst_port = ntohs(udp->uh_dport);
    } else {
        id.src_port = 0; id.dst_port = 0;
    }



    // PIAS Scheduling Logic 
    FlowState &state = flow_table[id];
    state.packet_count++;

    int assigned_queue;
    if (state.packet_count <= 3) {
        assigned_queue = 1; // Q1 limit 3 [cite: 110]
    } else if (state.packet_count <= 10) {
        assigned_queue = 2; // Q2 4-10 packets
    } else {
        assigned_queue = 3; // Q3 over 10 packets [cite: 109]
    }

    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(id.src_ip), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(id.dst_ip), dst_ip_str, INET_ADDRSTRLEN);

    std::cout << "Flow: " << src_ip_str << ":" << id.src_port << " -> " << dst_ip_str << ":" << id.dst_port 
              << " | Pkt: " << state.packet_count << " | Queue: Q" << assigned_queue << std::endl;
}


int main(int argc, char *argv[]) {
    // Check if the user provided a pcap file name
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap_file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // Open the pcap file for offline reading
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == nullptr) {
        std::cerr << "Could not open file: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Starting PIAS Scheduling Emulation..." << std::endl;
    // This starts the loop that processes every packet using packet_handler
    pcap_loop(handle, 0, packet_handler, nullptr);

    // Clean up
    pcap_close(handle);
    return 0;
}