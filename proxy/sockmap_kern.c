// sockmap_kern.c
#include <linux/bpf.h>
#include <stddef.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define LISTEN_PORT 6379

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned short),
	.value_size = sizeof(int),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") sock_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 2,
};

SEC("prog_parser")
int bpf_prog1(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("prog_verdict")
int bpf_prog2(struct __sk_buff *skb)
{
	__u32 *index = 0;
	__u16 port = (__u16)bpf_ntohl(skb->remote_port);
	char info_fmt[] = "data to port [%d]\n";

	bpf_trace_printk(info_fmt, sizeof(info_fmt), port);
	index = bpf_map_lookup_elem(&proxy_map, &port);
	if (index == NULL)
		return 0;

	return bpf_sk_redirect_map(skb, &sock_map, *index, 0);
}


char _license[] SEC("license") = "GPL";

