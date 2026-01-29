#include <iostream>
#include <pcap.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <string>

pcap_t* handle;
pcap_dumper_t* pdumper;

void signal_handler(int sig) {
    std::cout << "\nstop capture and save file..." << std::endl;
    if (pdumper) pcap_dump_close(pdumper);
    if (handle) pcap_close(handle);
    exit(0);
}

void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    
    // save file
    pcap_dump(user, pkthdr, packet);

    // print log on console
    struct ethhdr* eth = (struct ethhdr*)packet;
    if (ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr* ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

        std::cout << "[Live] Len: " << pkthdr->len << " | " << src_ip << " -> " << dst_ip;

        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr* tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + ip->ihl * 4);
            std::cout << " | TCP Port: " << ntohs(tcp->source) << " -> " << ntohs(tcp->dest);
        }
        std::cout << std::endl;
    }
}

int main(int argc, char* argv[]) {

    // argument check
    if (argc != 4) {
        std::cout << "Usage: " << argv[0] << " <IP> <PORT> <NIC Interface>" << std::endl;
        std::cout << "Example: " << argv[0] << " 192.168.0.10 443 eth0" << std::endl;
        return 1;
    }


    const char* target_ip = argv[1];
    const char* target_port = argv[2];
    const char* dev = argv[3];
    char errbuf[PCAP_ERRBUF_SIZE];

    std::string filter_str = "tcp port " + std::string(target_port) + " and host " + std::string(target_ip);

    // open device
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "can't open device: " << errbuf << std::endl;
        return 1;
    }

    // filter compile and apply
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "filter error: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    pcap_setfilter(handle, &fp);

    // dump file open
    pdumper = pcap_dump_open(handle, "capture_result.pcap");
    if (!pdumper) return 1;

    signal(SIGINT, signal_handler);

    std::cout << "--- capture start ---" << std::endl;
    std::cout << "filter: " << filter_str << std::endl;
    std::cout << "dump file: capture_result.pcap (exit: Ctrl+C)" << std::endl;

    pcap_loop(handle, 0, packet_handler, (u_char*)pdumper);

    return 0;

}
