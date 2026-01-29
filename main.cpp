#include <iostream>
#include <pcap.h>
#include <signal.h>

pcap_t* handle;
pcap_dumper_t* pdumper;

void signal_handler(int sig) {
    std::cout << "\nstop capture and save file..." << std::endl;
    if (pdumper) pcap_dump_close(pdumper);
    if (handle) pcap_close(handle);
    exit(0);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* dev = "lo";            // name of NIC (check with ifconfig)
    const char* filename = "capture.pcap";
    const char* target_ip = "localhost";
    int target_port = 8888;

    // 1. open NIC
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        std::cerr << "can't open NIC: " << errbuf << std::endl;
        return 1;
    }

    // 2. configure filter (IP and Port)
    struct bpf_program fp;
    char filter_exp[100];
    sprintf(filter_exp, "host %s and port %d", target_ip, target_port);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "fileter compile error: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "filter apply error: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // 3. pcap file create
    pdumper = pcap_dump_open(handle, filename);
    if (pdumper == NULL) {
        std::cerr << "create pcap file error: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    signal(SIGINT, signal_handler); // exit with Ctrl+C 

    std::cout << "capture start: " << filter_exp << " -> " << filename << std::endl;

    // 4. packet capture loop
    pcap_loop(handle, 0, pcap_dump, (u_char*)pdumper);

    return 0;
}
