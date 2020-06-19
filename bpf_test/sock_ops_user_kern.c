#include <string.h>
#include <linux/bpf.h>
#include <stddef.h>
#include "include/bpf_helpers.h"
#include "include/bpf_endian.h"

static void print_op(int op){
	switch (op) {
		case  BPF_SOCK_OPS_VOID:
			bpf_printk("BPF_SOCK_OPS_VOID\n");
			break;
		case BPF_SOCK_OPS_TIMEOUT_INIT:
			bpf_printk("BPF_SOCK_OPS_TIMEOUT_INIT\n");	
			break;
		case BPF_SOCK_OPS_RWND_INIT:
			bpf_printk("BPF_SOCK_OPS_RWND_INIT\n");	
			break;
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_printk("BPF_SOCK_OPS_TCP_CONNECT_CB\n");
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			bpf_printk("BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB\n");
			break;
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			bpf_printk("BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB\n");
			break;
		case BPF_SOCK_OPS_NEEDS_ECN:
			bpf_printk("BPF_SOCK_OPS_NEEDS_ECN\n");	
			break;
		case BPF_SOCK_OPS_BASE_RTT:
			bpf_printk("BPF_SOCK_OPS_BASE_RTT\n");
			break;
		case BPF_SOCK_OPS_RTO_CB:
			bpf_printk("BPF_SOCK_OPS_RTO_CB\n");
			break;
		case BPF_SOCK_OPS_RETRANS_CB:
			bpf_printk("BPF_SOCK_OPS_RETRANS_CB\n");
			break;
		case BPF_SOCK_OPS_STATE_CB:
			bpf_printk("BPF_SOCK_OPS_STATE_CB\n");
			break;
		case BPF_SOCK_OPS_TCP_LISTEN_CB:
			bpf_printk("BPF_SOCK_OPS_TCP_LISTEN_CB\n");	
			break;
		case BPF_SOCK_OPS_RTT_CB:
			bpf_printk("BPF_SOCK_OPS_RTT_CB\n");
			break;
		default:
			bpf_printk("error op %d", op);
			break;
	}
}
	
static void print_state(int state){
	switch(state){
		case BPF_TCP_ESTABLISHED:
			bpf_printk("BPF_TCP_SYN_SENT\n");
			break;
		case BPF_TCP_SYN_SENT:
			bpf_printk("BPF_TCP_SYN_SENT\n");
			break;
		case BPF_TCP_SYN_RECV:
			bpf_printk("BPF_TCP_SYN_RECV\n");
			break;
		case BPF_TCP_FIN_WAIT1:
			bpf_printk("BPF_TCP_FIN_WAIT1\n");
			break;
		case BPF_TCP_FIN_WAIT2:
			bpf_printk("BPF_TCP_FIN_WAIT2\n");
			break;
		case BPF_TCP_TIME_WAIT:
			bpf_printk("BPF_TCP_TIME_WAIT\n");
			break;
		case BPF_TCP_CLOSE:
			bpf_printk("BPF_TCP_CLOSE\n");
			break;
		case BPF_TCP_CLOSE_WAIT:
			bpf_printk("BPF_TCP_CLOSE_WAIT\n");
			break;
		case BPF_TCP_LAST_ACK:
			bpf_printk("BPF_TCP_LAST_ACK\n");
			break;
		case BPF_TCP_LISTEN:
			bpf_printk("BPF_TCP_LISTEN\n");
			break;
		case BPF_TCP_CLOSING:
			bpf_printk("BPF_TCP_CLOSING\n");
			break;
		case BPF_TCP_NEW_SYN_RECV:
			bpf_printk("BPF_TCP_NEW_SYN_RECV\n");
			break;
		case BPF_TCP_MAX_STATES:
			bpf_printk("BPF_TCP_MAX_STATES\n");
			break;
		default:
				bpf_printk("error op %d\n", state);
			break;
	};
}

SEC("bpf_prog_listen")
int bpf_prog3(struct bpf_sock_ops *skops)
{
	__u32 lport = skops->local_port, rport = bpf_ntohl(skops->remote_port);
	int op, err = 0, len;

	op = (int) skops->op;
	bpf_printk("bpf_prog3 lport:%d, rport:%d: XX op:%d ------------\n", lport, rport, op);
	print_op(op);	
	switch (op) {
			case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
				 bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
			break;
			case BPF_SOCK_OPS_STATE_CB:
				bpf_printk("bpf_prog3: BPF_SOCK_OPS_STATE_CBchange state %d->%d\n", skops->args[0], skops->args[1]);
				print_state(skops->args[0]);
				print_state(skops->args[1]);
			break;
	}
	return 0;
	
}

char _license[] SEC("license") = "GPL";
