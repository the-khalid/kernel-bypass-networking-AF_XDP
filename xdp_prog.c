#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define TARGET_PORT 9000

/*
  XSKMAP — userspace registers its XSK socket fd into this map at key=0.
  Pinned automatically to /sys/fs/bpf/tc/globals/xsks_map by LIBBPF_PIN_BY_NAME.
*/

struct {
    __uint(type,        BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __uint(pinning,     LIBBPF_PIN_BY_NAME);
    __type(key,         __u32);
    __type(value,       __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ethernet header bounds checking */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* handling only IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* IP header bounds checking */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* handling only UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* UDP header bounds check — respects IP options via ihl */
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* redirecting target port traffic to userspace via XSKMAP */
    if (udp->dest == __constant_htons(TARGET_PORT)) {
        __u32 index = ctx->rx_queue_index;
        return bpf_redirect_map(&xsks_map, index, 0);
    }

    /* everything else through the normal kernel stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";