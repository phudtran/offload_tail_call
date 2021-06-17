#include <linux/bpf.h>
#include <linux/types.h>
#include <stddef.h>
#include <string.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

struct transit_packet {
	void *data;
	void *data_end;

	/* interface index */
	int itf_idx;
	__u32 itf_ipv4;

	/* xdp*/
	struct xdp_md *xdp;

	/* Ether */
	struct ethhdr *eth;
	__u64 eth_off;

	/* IP */
	struct iphdr *ip;

	/* UDP */
	struct udphdr *udp;
} __attribute__((packed));

struct bpf_map_def SEC("maps") counter_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
	.map_flags = 0,
};
BPF_ANNOTATE_KV_PAIR(counter_map, __u32, __u32);

static __inline int process_ip(struct transit_packet *pkt)
{
	/* Get the IP header */
	pkt->ip = (void *)pkt->eth + pkt->eth_off;

	if (pkt->ip + 1 > pkt->data_end) {
		return XDP_ABORTED;
	}

	if (!pkt->ip->ttl)
		return XDP_DROP;
	__u32 key = 0;
	__u32 *val = bpf_map_lookup_elem(&counter_map, &key);
	if (!val) {
		return XDP_DROP;
	}
	if (pkt->ip->ttl == 99) {
		__sync_fetch_and_add(val, 1);
	}

	return XDP_DROP;
}

static __inline int process_eth(struct transit_packet *pkt)
{
	pkt->eth = pkt->data;
	pkt->eth_off = sizeof(*pkt->eth);
	if (pkt->data + pkt->eth_off > pkt->data_end) {
		return XDP_ABORTED;
	}
	return process_ip(pkt);
}



SEC("xdp")
int eth(struct xdp_md *ctx)
{
	struct transit_packet pkt;
	pkt.data = (void *)(long)ctx->data;
	pkt.data_end = (void *)(long)ctx->data_end;
	pkt.xdp = ctx;
	// Read the ttl written by veth program and update map counter if found.
	int action = process_eth(&pkt);
	return action;
}
char _license[] SEC("license") = "GPL";