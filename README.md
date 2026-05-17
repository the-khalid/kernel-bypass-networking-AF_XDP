# kernel bypass networking using AF_XDP

The XDP program (`xdp_prog.c`) attaches to the receiving interface and intercepts UDP packets destined for port 9000 before the kernel allocates socket buffers, traverses the IP/UDP stack, or runs netfilter hooks. Matching packets are redirected directly into a pre-allocated userspace memory region (UMEM) via an `XSKMAP`. The receiver (`xsk_receiver.cpp`) busy-polls the RX ring and reads packets.

### Results
 
Benchmarked across two isolated network namespaces connected via a `veth` pair:
 
| Metric | AF_INET (UDP) | AF_XDP |
|--------|--------------|--------|
| Mean   | 200 µs    | 8 µs |
| P50    | 218 µs     | 6 µs |
| P99    | 300 µs    | 80 µs |
| `udp_rcv` calls (5s window) | 1,221,304 | 0 |
| `__skb_recv_udp` calls (5s window) | 333 | 0 |
| Hot-path syscalls (per 100 packets) | 100 (`recvfrom`) | **0** |


### Setup
 
- #### Compile the XDP program
```bash
clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o
```
 
- #### Compile the receiver
```bash
g++ -O2 xsk_receiver.cpp -o xsk_receiver \
    -I/usr/include \
    -I/usr/local/include \
    -lbpf -lxdp -lelf -lz -lpthread
```

- #### Create network namespaces and veth pair

- #### Attach the XDP program to veth2
```bash
sudo ip netns exec ns2 ip link set veth2 xdp obj xdp_prog.o sec xdp
```

- #### Pin the XSKMAP
```bash
# Find the map ID
sudo bpftool map list | grep xsks_map
 
# Pin it (replace <ID> with the actual ID from above)
sudo bpftool map pin id <ID> /sys/fs/bpf/tc/globals/xsks_map
```

- #### Run the receiver
```bash
sudo nsenter --net=/var/run/netns/ns2 ./xsk_receiver
```

Expected output:
```
Socket registered in xsks_map at key=0, fd=7
XSK listening on veth2 queue 0, port 9000...
```


### Kernel Tracing
 
**Confirm `udp_rcv` is bypassed:**
```bash
sudo bpftrace -e '
kprobe:ip_rcv        { @ip_rcv        = count(); }
kprobe:udp_rcv       { @udp_rcv       = count(); }
kprobe:__skb_recv_udp { @skb_recv_udp = count(); }
kprobe:sock_def_readable { @sock_readable = count(); }
interval:s:5 {
    print(@ip_rcv); print(@udp_rcv);
    print(@skb_recv_udp); print(@sock_readable);
    exit();
}
'
```
 
With AF_INET running, `udp_rcv` reaches ~1.2M per 5s window, and drops to 0 with AF_XDP! 
 
