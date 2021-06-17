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


struct bpf_map_def SEC("maps") jmp_table = {
	.type = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 3,
};
BPF_ANNOTATE_KV_PAIR(jmp_table, __u32, __u32);



static __inline int process_ip(struct transit_packet *pkt)
{
	/* Get the IP header */
	pkt->ip = (void *)pkt->eth + pkt->eth_off;

	if (pkt->ip + 1 > pkt->data_end) {
		bpf_debug("[Transit:%d:0x%x] ABORTED: Bad offset\n", __LINE__,
			  bpf_ntohl(pkt->itf_ipv4));
		return XDP_ABORTED;
	}

	if (!pkt->ip->ttl)
		pkt->ip->ttl = 99;
		bpf_debug("VETH: Modified TTL of packet to %d\n", pkt->ip->ttl, __LINE__);

	/* Only process packets designated to this interface!
	 * In functional tests - relying on docker0 - we see such packets!
	 */
	if (pkt->ip->daddr != pkt->itf_ipv4) {
		bpf_debug(
			"[Transit:%d:0x%x] DROP: packet dst address [0x%x] mismatch interface address.\n",
			__LINE__, bpf_ntohl(pkt->itf_ipv4),
			bpf_ntohl(pkt->ip->daddr));
		return XDP_DROP;
	}
	return XDP_TX;
}

static __inline int process_eth(struct transit_packet *pkt)
{
	pkt->eth = pkt->data;
	pkt->eth_off = sizeof(*pkt->eth);

	if (pkt->data + pkt->eth_off > pkt->data_end) {
		bpf_debug("[Transit:%d:0x%x] ABORTED: Bad offset\n", __LINE__,
			  bpf_ntohl(pkt->itf_ipv4));
		return XDP_ABORTED;
	}
	return process_ip(pkt);
}



SEC("xdp")
int veth(struct xdp_md *ctx)
{
	struct transit_packet pkt;
	pkt.data = (void *)(long)ctx->data;
	pkt.data_end = (void *)(long)ctx->data_end;
	pkt.xdp = ctx;
	__u32 key = 1;
	__u32 key2 = 0;
	// Write something unique into the packet here.
	int action = process_eth(&pkt);
	bpf_tail_call(ctx, &jmp_table, key);
	bpf_tail_call(ctx, &jmp_table, key2);
	return action;
}
char _license[] SEC("license") = "GPL";