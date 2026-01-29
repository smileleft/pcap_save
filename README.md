# pcap_save
filter packet and save as pcap file wit C++

## how to build

```bash
# install library
sudo apt-get install libpcap-dev

# compile use lpcap option
g++ main.cpp -o packet_capture -lpcap

# execute
sudo ./packet_capture {target ip} {target port} {target NIC device}
```
