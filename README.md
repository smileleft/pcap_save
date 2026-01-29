# pcap_save
filter packet and save as pcap file wit C++

## how to build

```bash
# install library
sudo apt-get install libpcap-dev

# compile use lpcap option
g++ packet_capture.cpp -o packet_capture -lpcap

# execute
sudo ./packet_capture
```
