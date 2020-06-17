#include <string.h>
#include <linux/bpf.h>
#include <stddef.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define LISTEN_PORT 6379
#define AUTH_PORT 4321
#define SUCCESS -1
#define FAIL -2


#define SOCKMAP_INDEX 0
#define REDIR_INDEX 1

static int peerPort = 0;

struct bpf_map_def SEC("maps") proxy_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned short),
	.value_size = sizeof(int),
	.max_entries = 10,
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
	void *data_end = (void *)(long) skb->data_end;
    void *data = (void *)(long) skb->data;
    __u32 lport = skb->local_port;
    __u32 rport = bpf_ntohl(skb->remote_port);
    __u8 *d = data;
    __u32 len = (__u32) data_end - (__u32) data;
    int err;
    int pullLen = 10;

	bpf_printk("\n-----------bpf_prog1 lport:%d, rport:%d: \n", lport, rport);
    return skb->len;
}  

SEC("prog_verdict")
int bpf_prog2(struct __sk_buff *skb)
{
    void *data_end = (void *)(long) skb->data_end;
    void *data = (void *)(long) skb->data;
	__u32 *index = 0;
	__u16 port = (__u16)bpf_ntohl(skb->remote_port);
	__u16 lport = skb->local_port;
    __u8 *d = data;
    int ret = SK_PASS, i, err = 0;

	bpf_printk("\n-----------bpf_prog2 lport:%d, rport:%d: \n", lport, port);
	index = bpf_map_lookup_elem(&proxy_map, &port);
	if (index == NULL)
		return SK_PASS;

	 bpf_printk("bpf_prog2: index:%d\n", *index);
	if (*index == SUCCESS){
	        bpf_printk("bpf_prog2: success pass and remove bpf map\n");
		
		err = bpf_map_delete_elem(&proxy_map, &port);
	        if ( err ) bpf_printk("bpf_prog2: remove proxy map %d\n", err);
		return SK_PASS;
	}
	if(*index == FAIL){
	        bpf_printk("bpf_prog2: fail drop!!\n");
		return SK_DROP;
	}

     if ( port == AUTH_PORT ){
			err = bpf_skb_pull_data(skb, 2);
			if (err){
	        	bpf_printk("bpf_prog3: pull data err %d\n", err);
				return SK_DROP;
			}
			data = (void*)(long)skb->data;
			data_end = (void*)(long)skb->data_end;
			d = (void*)(long)skb->data;
			if(data + 2 > data_end){
	        	bpf_printk("bpf_prog3: pull data size err %d\n", err);
				return SK_DROP;
			}

			if ( d[0] == 'O' && d[1] == 'K'){
	        	bpf_printk("bpf_prog2: success", peerPort);
				i = SUCCESS;
			}else{
	        	bpf_printk("bpf_prog2: fail", peerPort);
				i = FAIL;
			}
			err = bpf_map_update_elem(&proxy_map, &peerPort, &i, BPF_ANY);
			if ( err ) bpf_printk("bpf_prog2: update elem %i!\n", err);
     }

	bpf_printk("bpf_prog2: redirest to index:%d\n", *index);
	ret = bpf_sk_redirect_map(skb, &sock_map, *index, 0);
    return ret;
}


SEC("bpf_prog_listen")
int bpf_prog3(struct bpf_sock_ops *skops)
{
        __u32 lport = skops->local_port, rport = bpf_ntohl(skops->remote_port);
        int op, err = 0, index, key, ret;

		bpf_printk("\n-----------bpf_prog3 lport:%d, rport:%d: \n", lport, rport);

        op = (int) skops->op;
        switch (op) {
			case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			lport = skops->local_port;
			rport = skops->remote_port;
			if (lport == LISTEN_PORT) {
				bpf_printk("bpf_prog3: got peer socket\n");
				ret = SOCKMAP_INDEX;
				err = bpf_sock_map_update(skops, &sock_map, &ret, BPF_ANY);
				if( err ){
					bpf_printk("bpf_prog3: update sockmap: %d\n", err);
				}

				ret = REDIR_INDEX;
				index = bpf_ntohl(rport);
				peerPort = index;
				err = bpf_map_update_elem(&proxy_map, &index, &ret, BPF_ANY);
				if( err )
					bpf_printk("passive(%i -> %i) map ctx update err: %d\n", lport, bpf_ntohl(rport), err);
				}
				break;
        }
	return 0;
}

char _license[] SEC("license") = "GPL";
