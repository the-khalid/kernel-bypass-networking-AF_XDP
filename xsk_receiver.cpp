#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <cstring>
#include <cerrno>
#include <net/if.h>
#include <unistd.h>
#include <sys/mman.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

extern "C" {
#include <xdp/xsk.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
}

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE   // 4096 (x86 page size, UMEM designed around page-aligned memory)
#define BATCH_SIZE 64

constexpr size_t MAX_SAMPLES = 100;

struct Message {
    uint32_t magic;
    uint64_t timestamp;
};

inline uint64_t now_ns() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

int main() {

    std::vector<uint64_t> latencies;
    latencies.reserve(MAX_SAMPLES);

    const char* ifname = "lo";
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        std::cerr << "ERROR: if_nametoindex failed for " << ifname << "\n";
        return 1;
    }

    // UMEM buffer allocation
    void* buffer = nullptr;
    size_t buf_size = (size_t)NUM_FRAMES * FRAME_SIZE;

    /*	removed posix aligned memory to use hugepages
    if (posix_memalign(&buffer, getpagesize(), buf_size)) {
        std::cerr << "ERROR: posix_memalign failed: " << strerror(errno) << "\n";
        return 1;
    }
    */

    buffer = mmap(NULL, buf_size,
              PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
              -1, 0);
    if (buffer == MAP_FAILED) {
        std::cerr << "ERROR: mmap hugepages failed: " << strerror(errno) << "\n";
        std::cerr << "       Are huge pages allocated? Check /proc/meminfo\n";
        return 1;
    }

    /* removed mlock call as well coz hugepages are already pinned (required for XSK to work reliably) in RAM by default
    if (mlock(buffer, buf_size)) {
        std::cerr << "WARNING: mlock failed (running without CAP_IPC_LOCK?): "
                  << strerror(errno) << "\n";
    }
    */

    // UMEM creation
    struct xsk_umem* umem = nullptr;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    memset(&fill, 0, sizeof(fill));
    memset(&comp, 0, sizeof(comp));

    xsk_umem_config umem_cfg = {};
    umem_cfg.fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS;  // 2048
    umem_cfg.comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS;  // 2048
    umem_cfg.frame_size     = FRAME_SIZE;
    umem_cfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;  // 0
    umem_cfg.flags          = 0;

    int ret = xsk_umem__create(&umem, buffer, buf_size, &fill, &comp, &umem_cfg);
    if (ret) {
        std::cerr << "ERROR: xsk_umem__create failed: " << strerror(-ret) << "\n";
        return 1;
    }

    // Pre-population of fill ring so the kernel has frames to receive into
    uint32_t idx = 0;
    ret = xsk_ring_prod__reserve(&fill, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != (int)XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        std::cerr << "ERROR: fill ring reserve failed, got " << ret << "\n";
        return 1;
    }
    for (uint32_t i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
        *xsk_ring_prod__fill_addr(&fill, idx + i) = (uint64_t)i * FRAME_SIZE;
    }
    xsk_ring_prod__submit(&fill, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    // XSK socket creation
    struct xsk_socket* xsk = nullptr;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    memset(&rx, 0, sizeof(rx));
    memset(&tx, 0, sizeof(tx));

    xsk_socket_config cfg = {};
    cfg.rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.libbpf_flags  = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    cfg.xdp_flags    = 0;
    cfg.bind_flags   = 0;  // 0 for busy polling

    ret = xsk_socket__create(&xsk, ifname, 0 /*queue*/, umem, &rx, &tx, &cfg);
    if (ret) {
        std::cerr << "ERROR: xsk_socket__create failed: " << strerror(-ret) << "\n";
        std::cerr << "       Are you running as root?\n";
        return 1;
    }

    // socket registration in the XSK map
    int xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map_fd < 0) {
        std::cerr << "ERROR: bpf_obj_get xsks_map failed: " << strerror(errno) << "\n";
        std::cerr << "       Is the XDP program loaded and map pinned?\n";
        return 1;
    }

    int xsk_fd = xsk_socket__fd(xsk);
    int key = 0;
    ret = bpf_map_update_elem(xsks_map_fd, &key, &xsk_fd, 0);
    if (ret) {
        std::cerr << "ERROR: bpf_map_update_elem failed: " << strerror(errno) << "\n";
        return 1;
    }

    std::cout << "XSK listening on " << ifname << " queue 0, port 9000...\n";

    #include <pthread.h>
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(2, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);


    // RX loop
    while (true) {
        uint32_t rx_idx = 0;
        int rcvd = xsk_ring_cons__peek(&rx, BATCH_SIZE, &rx_idx);
        if (!rcvd) continue;

        for (int i = 0; i < rcvd; i++) {
            const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&rx, rx_idx + i);
            void* pkt = xsk_umem__get_data(buffer, desc->addr);

            // ethernet(14) + IP(20) + UDP(8) = 42 bytes header
            auto* eth = (struct ethhdr*)pkt;
            auto* ip = (struct iphdr*)((char*)pkt + sizeof(struct ethhdr));
            int ip_hdr_len = ip->ihl * 4;
            auto* udp = (struct udphdr*)((char*)ip + ip_hdr_len);
            void* payload = (char*)udp + sizeof(struct udphdr);

            if (desc->len >= 42 + sizeof(Message)) {
                Message* msg = (Message*)payload;
                uint64_t latency = now_ns() - msg->timestamp;
                latencies.push_back(latency);

                if (latencies.size() >= MAX_SAMPLES) {
                    uint64_t sum = std::accumulate(latencies.begin(), latencies.end(), 0ULL);
                    double mean = static_cast<double>(sum) / latencies.size();

                    std::sort(latencies.begin(), latencies.end());

                    auto p50  = latencies[latencies.size() * 50 / 100];
                    auto p99  = latencies[latencies.size() * 99 / 100];
                    auto p999 = latencies[latencies.size() * 999 / 1000];

                    std::cout << "\n=== Latency Stats ===\n";
                    std::cout << "Mean : " << mean << "\n";
                    std::cout << "P50  : " << p50 << "\n";
                    std::cout << "P99  : " << p99 << "\n";
                    std::cout << "P999 : " << p999 << "\n";

                    latencies.clear();
                    xsk_ring_cons__release(&rx, rcvd);
                    xsk_socket__delete(xsk);
                    xsk_umem__delete(umem);
                    munmap(buffer, buf_size);
                    return 0;
        	    }
            } else {
                std::cout << "Received short packet (" << desc->len << " bytes)\n";
            }

            // recycling frame back to fill ring
            uint32_t fill_idx = 0;
            if (xsk_ring_prod__reserve(&fill, 1, &fill_idx) == 1) {
                *xsk_ring_prod__fill_addr(&fill, fill_idx) = desc->addr;
                xsk_ring_prod__submit(&fill, 1);
            }
        }
        xsk_ring_cons__release(&rx, rcvd);
    }

    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    // free(buffer);
    return 0;
}
