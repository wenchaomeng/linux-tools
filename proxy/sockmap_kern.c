// sockmap_kern.c
#include <linux/bpf.h>
#include <stddef.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define LISTEN_PORT 6379
#define AUTH_PORT 4321

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
        void *data_end = (void *)(long) skb->data_end;
        void *data = (void *)(long) skb->data;
	__u32 *index = 0;
	__u16 port = (__u16)bpf_ntohl(skb->remote_port);
	char info_fmt[] = "data to port [%d]\n";
        __u8 *d = data;
        int ret = SK_PASS, i;

	bpf_trace_printk(info_fmt, sizeof(info_fmt), port);


	index = bpf_map_lookup_elem(&proxy_map, &port);
	if (index == NULL)
		return SK_PASS;
	bpf_printk("bpf_prog2: redirest to index:%d\n", *index);
	ret = bpf_sk_redirect_map(skb, &sock_map, *index, 0);

        //pass delete from sockmap
        if ( port == AUTH_PORT ){
	        bpf_printk("bpf_prog2: from auth server ok, remove socket in sockmap\n");
                i = 0;
                err = bpf_map_delete_elem(&sock_map, &i);
                if( err ){
                        bpf_printk("bpf_prog2: remove error: %s\n", strerror(errno));
                }
        }
        return ret;
}


SEC("bpf_prog_listen")
int bpf_prog3(struct bpf_sock_ops *skops)
{
        __u32 lport, rport;
        int op, err = 0, index, key, ret;


        bpf_printk("\nbpf_prog3\n");
        op = (int) skops->op;

         lport = skops->local_port;
         rport = skops->remote_port;
        bpf_printk("bpf_prog3 local port:%d, remote port:%d\n", lport, bpf_ntohl(rport));

        switch (op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
                lport = skops->local_port;
                rport = skops->remote_port;

                if (lport == LISTEN_PORT) {
                        ret = 0;
                        err = bpf_sock_map_update(skops, &sock_map, &ret,
                                                  BPF_NOEXIST);

                        ret = 1;
			index = bpf_ntohl(rport);
                        err = bpf_map_update_elem(&proxy_map, &index, &ret, BPF_ANY);
                        bpf_printk("passive(%i -> %i) map ctx update err: %d\n",
                                   lport, bpf_ntohl(rport), err);
                }
                break;
        }
	return 0;
}

char _license[] SEC("license") = "GPL";

