#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h> // [FIX] Required for bpf_htons
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>

struct { __uint(type, BPF_MAP_TYPE_XSKMAP); __uint(max_entries, 64); __uint(key_size, 4); __uint(value_size, 4); } xsks_map SEC(".maps");

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > end) return XDP_PASS;

    if (udp->dest == bpf_htons(51820)) {
        int idx = ctx->rx_queue_index;
        if (bpf_map_lookup_elem(&xsks_map, &idx)) return bpf_redirect_map(&xsks_map, idx, 0);
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
