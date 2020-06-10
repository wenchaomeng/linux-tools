#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include <bits/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

#define SEC(NAME) __attribute__((section(NAME), used))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_constant_htons(x) ___constant_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_htons(x) (x)
#define __bpf_constant_htons(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif

#define bpf_htons(x) \
  (__builtin_constant_p(x) ? __bpf_constant_htons(x) : __bpf_htons(x))

#define trace_printk(fmt, ...)                                                 \
  do {                                                                         \
    char _fmt[] = fmt;                                                         \
    bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                       \
  } while (0)

unsigned long long load_byte(void *skb,
                             unsigned long long off) asm("llvm.bpf.load.byte");

struct http_payload {
  int method;
};

static inline int is_http(struct __sk_buff *skb, __u64 nh_off);
static inline void show_ip_checksum(struct __sk_buff *skb);
static inline int inspect(struct __sk_buff *skb);

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

SEC("classifier")
static inline int classification(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;

  __u16 h_proto;
  __u64 nh_off = 0;
  nh_off = sizeof(*eth);

  if (data + nh_off > data_end) {
    return TC_ACT_OK;
  }

  h_proto = eth->h_proto;

  if (h_proto == bpf_htons(ETH_P_IP)) {
    int ishttp = is_http(skb, nh_off);
    if (ishttp == -1) {
      return TC_ACT_SHOT;
    }
    if (ishttp == 1) {
      trace_printk("Yes! It is HTTP!\n");
    }
  }

  return TC_ACT_OK;
}

static inline int is_http(struct __sk_buff *skb, __u64 nh_off) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct iphdr *iph = data + nh_off;
  struct ethhdr *eth;

  if (iph + 1 > data_end) {
    return 0;
  }

  if (iph->protocol != IPPROTO_TCP) {
    return 0;
  }
  __u32 tcp_hlen = 0;
  __u32 ip_hlen = 0;
  __u32 poffset = 0;
  __u32 plength = 0;
  __u16 ip_total_length = __bpf_htons(iph->tot_len);

  ip_hlen = iph->ihl << 2;

  if (ip_hlen < sizeof(*iph)) {
    return 0;
  }

  struct tcphdr *tcph = data + nh_off + sizeof(*iph);

  if (tcph + 1 > data_end) {
    return 0;
  }

  tcp_hlen = tcph->doff << 2;

  __u16 port = __bpf_htons(tcph->dest);
  if(port != 8888) {
    return 0;
  }
  poffset = ETH_HLEN + ip_hlen + tcp_hlen;
  plength = ip_total_length - ip_hlen - tcp_hlen;
  if (plength >= 7) {
    unsigned long p[7];
    int i = 0;
    for (i = 0; i < 7; i++) {

      p[i] = load_byte(skb, poffset + i);
    }
    int *value;

  
    if ((p[0] == 'A') && (p[1] == 'B') && (p[2] == 'C') && (p[3] == 'D')) {

      //bpf_skb_adjust_room(skb, -2, BPF_ADJ_ROOM_NET, 0);
      trace_printk("TCP body start offset: %d, total length: %d\n",poffset, plength);
      // trace_printk("LEN2: %d\n", sizeof(ethhdr_copy) + sizeof(iphdr_copy) + sizeof(tcphdr_copy));

      // int buf_size = 200;
      // unsigned char buf[200];
      // trace_printk("LEN: %d\n", sizeof(buf));

      int token_len = 10;
      // inspect(skb);

      /*
      unsigned char buf[10];
      int total = 0;
      int remain = plength - token_len;
      //#pragma clang loop unroll(full)
      for (i = 0; i < 20; i++) {
          if(remain < 10) {
            break;
          }
          int ret = bpf_skb_load_bytes(skb, poffset + token_len + total, buf, 10);
          // trace_printk("load: %d\n", ret);
          ret = bpf_skb_store_bytes(skb, poffset + total, buf, 10, 0);
          // trace_printk("store: %d\n", ret);
          total += 10;
          remain -= 10;
      }

      char b;
      for (i = 0; i < 10; i++) {
        if(remain <= 0) {
          break;
        }
        int ret = bpf_skb_load_bytes(skb, poffset + token_len + total, &b, 1);
        // trace_printk("load: %d\n", ret);
        ret = bpf_skb_store_bytes(skb, poffset + total, &b, 1, 0);
        // trace_printk("store: %d\n", ret);
        total += 1;
        remain -= 1;
      }
      */
      int ret = 0;

      // change length of ip package
      trace_printk("ip_total_len: %d\n", ip_total_length);
      __u16 new_len = __bpf_htons(ip_total_length - token_len);
      bpf_skb_store_bytes(skb, ETH_HLEN + 2, &new_len, 2, 0);

      // move tcp header down
      if(tcp_hlen != 32) {
        trace_printk("============TCP HEADER LEN============\n");
      }
      unsigned char buf2[32];
      ret = bpf_skb_load_bytes(skb, ETH_HLEN + ip_hlen, buf2, 32);
      ret = bpf_skb_store_bytes(skb, ETH_HLEN + ip_hlen + token_len, buf2, 32, 0);

      // move ethernet and ip header down
      ret = bpf_skb_adjust_room(skb, -token_len, BPF_ADJ_ROOM_NET, 0);
      trace_printk("bpf_skb_adjust_room: %d\n", ret);
      


      // trace_printk("len before: %d\n", skb->len);
      // int ret = bpf_skb_change_tail(skb, skb->len - token_len, 0);
      // trace_printk("bpf_skb_change_tail: %d\n", ret);
      // trace_printk("len after: %d\n", skb->len);

      //change ip checksum
      ret = bpf_l3_csum_replace(skb, ETH_HLEN + 10, __bpf_htons(ip_total_length), __bpf_htons(ip_total_length - token_len), 2);
      trace_printk("l3 csum replace: %d\n", ret);

      //change tcp checksum
      // ret = bpf_l4_csum_replace(skb, ETH_HLEN + ip_hlen + 16, 10, 0, 2);
      // trace_printk("l4 csum replace: %d\n", ret);

      show_ip_checksum(skb);
      inspect(skb);

      return 1;
    } else {
      trace_printk("WILL DROP len: %d\n", plength);
      for(int i=0;i<7;i++) {
        trace_printk("data[%d]: %x\n", i, p[i]);
      }
      return 1;
    }
  }

  return 0;
}

static inline int inspect(struct __sk_buff *skb) {
  __u64 nh_off = 0;
  nh_off = sizeof(struct ethhdr);
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  struct iphdr *iph = data + nh_off;
  struct ethhdr *eth;

  if (iph + 1 > data_end) {
    return 0;
  }

  if (iph->protocol != IPPROTO_TCP) {
    return 0;
  }
  
  __u32 tcp_hlen = 0;
  __u32 ip_hlen = 0;
  __u32 poffset = 0;
  __u32 plength = 0;
  __u16 ip_total_length = __bpf_htons(iph->tot_len);

  ip_hlen = iph->ihl << 2;

  if (ip_hlen < sizeof(*iph)) {
    return 0;
  }

  struct tcphdr *tcph = data + nh_off + sizeof(*iph);

  if (tcph + 1 > data_end) {
    return 0;
  }

  tcp_hlen = tcph->doff << 2;
  __u16 port = __bpf_htons(tcph->dest);
  if(port != 8888) {
    trace_printk("INSPECT PORT: %d\n", port);
    return 0;
  }
  poffset = ETH_HLEN + ip_hlen + tcp_hlen;
  plength = ip_total_length - ip_hlen - tcp_hlen;

  trace_printk("INSPECT plength: %d\n", plength);

  unsigned char b[10];
  int total = 0;
  int remain = ETH_HLEN + ip_total_length;
  for (int i = 0; i < 20; i++) {
    if(remain < 10) {
      break;
    }
    int ret = bpf_skb_load_bytes(skb, total, &b, 10);
    if(ret != 0) {
      trace_printk("load error: %d\n", ret);
    }
    for(int j=0;j<10;j++) {
        trace_printk("data[%d]: %x\n", total + j, b[j]);
      }
    total += 10;
    remain -= 10;
  }

  unsigned char cc;
  for (int i = 0; i < 10; i++) {
    if(remain <=0) {
      break;
    }
    int ret = bpf_skb_load_bytes(skb, total, &cc, 1);
    if(ret != 0) {
      trace_printk("load error: %d\n", ret);
    }
    trace_printk("data[%d]: %x\n", total, cc);
    total += 1;
    remain -= 1;
  }

  int ret = bpf_skb_load_bytes(skb, total, &cc, 1);
  if(ret == 0) {
    trace_printk("=========unexpected extra load success=========\n", ret);
  }

  return 1;
}

static inline void show_ip_checksum(struct __sk_buff *skb) {
  unsigned int csum = 0;
  __u16 cc = 0 ;
  for(int i=0;i<10;i++) {
    bpf_skb_load_bytes(skb, ETH_HLEN + (i*2), &cc, 2);
    csum += cc;
    // trace_printk("%x\n", cc);
  }
  trace_printk("IPCSUM: %x\n", csum);
}

char _license[] SEC("license") = "GPL";
