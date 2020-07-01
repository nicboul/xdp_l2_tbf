// SPDX-License-Identifier: GPL-2.0

#define KBUILD_MODNAME "xdp_l2_tbf"

#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include "bpf_helpers.h"

struct bpf_elf_map {
	__u32	type;
	__u32	key_size;
	__u32	value_size;
	__u32	max_elem;
	__u32	flags;
};

struct lladdr_state {
	u32	tokens;
	u64	timestamp;
} __attribute__((packed));

struct bpf_elf_map SEC("maps") lladdr_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.key_size	= sizeof(u8) * ETH_ALEN,
	.value_size	= sizeof(struct lladdr_state),
	.max_elem	= 500,
};

#define bpf_debug(fmt, ...) \
({ \
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
	##__VA_ARGS__); \
})


#define NS_IN_SEC	1000000000LL

SEC("proc")

int xdp_l2_tbf(struct xdp_md *ctx)
{
	struct	lladdr_state	*elem, entry;
	u64			 now;
	void			*data_end = (void *)(long)ctx->data_end;
	void			*data = (void *)(long)ctx->data;

	bpf_debug("here !\n");

	/* we map the Ethernet header to the data pointer */
	struct ethhdr *eth = data;

	// Verify size of ethernet header
	uint64_t nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		bpf_debug("dropped here !\n");
		return XDP_DROP;
	}

	bpf_debug("addr: %x:%x\n",
		eth->h_source[0],
		eth->h_source[1]);

	elem = bpf_map_lookup_elem(&lladdr_map, eth->h_source);
	if (elem == NULL) {
		entry.tokens = 10;
		entry.timestamp = bpf_ktime_get_ns();

		bpf_map_update_elem(&lladdr_map, eth->h_source, &entry, BPF_ANY);
		bpf_debug("this element is empty\n");
	} else {
		bpf_debug("tokens %d\n", elem->tokens);
		if (elem->tokens <= 0) {

			now = bpf_ktime_get_ns();
			if (now - elem->timestamp > (NS_IN_SEC*5)) {
				elem->timestamp = now;
				elem->tokens = 10;
				bpf_debug("now at 10 !!!!\n");
			} else {
				bpf_debug("dropped !\n");
				return XDP_DROP;
			}
		}
		entry.tokens = elem->tokens - 1;
		entry.timestamp = elem->timestamp;
		bpf_map_update_elem(&lladdr_map, eth->h_source, &entry, BPF_ANY);
	}


	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
