#include <linux/if_ether.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdatomic.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>

#include "../libbpf/src/bpf_helpers.h"

#define printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define htons(x) ((__be16)___constant_swab16((x)))
#define ntohs(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))
#define ntohl(x) ((__be32)___constant_swab32((x)))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htons(x) (x)
#define ntohs(X) (x)
#define htonl(x) (x)
#define ntohl(x) (x)
#endif

struct bpf_map_def SEC("maps") xsks_map = 
{
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 64
};

SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{    
    // Initialize data.
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Initialize ethernet header.
    struct ethhdr *ethhdr = data;

    // Check if the ethernet header is valid.
    if (ethhdr + 1 > (struct ethhdr *)data_end)
    {
        return XDP_DROP;
    }

    // Check Ethernet protocol.
    if (unlikely(ethhdr->h_proto != htons(ETH_P_IP)))
    {
        return XDP_PASS;
    }

    // Initialize IP header.
    struct iphdr *iph = data + sizeof(struct ethhdr);

    // Check if the IP header is valid.
    if (unlikely(iph + 1 > (struct iphdr *)data_end))
    {
        return XDP_DROP;
    }

    if (iph->protocol == IPPROTO_UDP)
    {
        // Initialize UDP header.
        struct udphdr *udph = data + sizeof(struct ethhdr) + (iph->ihl * 4);

        // Check UDP header.
        if (udph + 1 > (struct udphdr *)data_end)
        {
            return XDP_DROP;
        }

        // Check destination port.
        if (udph->dest == htons(27015))
        {
            // Redirect.
            int x = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);

            printk("Redirecting packet to RX queue %d with BPF redirect return num %d", ctx->rx_queue_index, x);

            return x;
        }
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";