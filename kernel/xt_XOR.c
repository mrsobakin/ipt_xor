#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <net/gre.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_XOR.h"

MODULE_AUTHOR("faicker.mo <faicker.mo@gmail.com>");
MODULE_DESCRIPTION("iptables XOR module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_XOR");

static inline void transform(char *buffer, uint32_t len, const struct xt_xor_info *info)
{
    if (info->first && len > info->first) {
        len = info->first;
    }

    const unsigned char* key = info->key;
    uint32_t key_len = info->key_len;

    uint32_t i;
    for (i = 0; i < len; ++i) {
        buffer[i] ^= key[i % key_len];
    }
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
static unsigned int xt_xor_target4(struct sk_buff *skb, const struct xt_action_param *par)
#else
static unsigned int xt_xor_target4(struct sk_buff *skb, const struct xt_target_param *par)
#endif
{
    const struct xt_xor_info *info = par->targinfo;
    struct iphdr *iph;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct gre_base_hdr *greh = NULL;
    unsigned char *buf_pos;
    int ip_payload_len, data_len;

    iph = ip_hdr(skb);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
    if (unlikely(skb_ensure_writable(skb, ntohs(iph->tot_len))))
        return NF_DROP;
#else
    if (unlikely(!skb_make_writable(skb, ntohs(iph->tot_len))))
        return NF_DROP;
#endif

    iph = ip_hdr(skb);
    buf_pos = skb->data + iph->ihl*4;
    ip_payload_len = skb->len - iph->ihl*4;
    
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)buf_pos;
        buf_pos += tcph->doff*4;
        data_len =  ip_payload_len - tcph->doff*4;

        if (unlikely(data_len < 0)) {
            return NF_DROP;
        }

        transform(buf_pos, data_len, info);

        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            tcph->check = 0;
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       ip_payload_len, IPPROTO_TCP,
                                       csum_partial((char *)tcph, ip_payload_len, 0));
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)buf_pos;
        buf_pos += sizeof(struct udphdr);
        data_len = ip_payload_len - sizeof(struct udphdr);

        if (unlikely(data_len < 0)) {
            return NF_DROP;
        }

        transform(buf_pos, data_len, info);

        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            udph->check = 0;
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       ip_payload_len, IPPROTO_UDP,
                                       csum_partial((char *)udph, ip_payload_len, 0));
        }
    } else if (iph->protocol == IPPROTO_GRE) {
        greh = (struct gre_base_hdr *)buf_pos;
        if (greh->flags == 0 &&
                   (greh->protocol == htons(ETH_P_IP) || greh->protocol == htons(0x0101))) {
            greh->protocol = greh->protocol == htons(ETH_P_IP) ? htons(0x0101) : htons(ETH_P_IP);
            buf_pos += sizeof(struct gre_base_hdr);
            data_len = ip_payload_len - sizeof(struct gre_base_hdr);
            if (unlikely(data_len < 0)) {
                return NF_DROP;
            }
            transform(buf_pos, data_len, info);
        }
    }
    return XT_CONTINUE;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
static unsigned int xt_xor_target6(struct sk_buff *skb, const struct xt_action_param *par)
#else
static unsigned int xt_xor_target6(struct sk_buff *skb, const struct xt_target_param *par)
#endif
{
    const struct xt_xor_info *info = par->targinfo;
    struct ipv6hdr *ip6h;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct gre_base_hdr *greh = NULL;
    unsigned char* buf_pos;
    int ip_payload_len, data_len;

    ip6h = ipv6_hdr(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
    if (unlikely(skb_ensure_writable(skb, skb->len)))
        return NF_DROP;
#else
    if (unlikely(!skb_make_writable(skb, skb->len)))
        return NF_DROP;
#endif

    ip6h = ipv6_hdr(skb);
    buf_pos = skb->data + 40;
    ip_payload_len = ntohs(ip6h->payload_len);

    if (ip6h->nexthdr == IPPROTO_TCP) {
        tcph = (struct tcphdr *)buf_pos;
        buf_pos += tcph->doff*4;
        data_len = ip_payload_len - tcph->doff*4;

        if (unlikely(data_len < 0)) {
            return NF_DROP;
        }

        transform(buf_pos, data_len, info);

        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            tcph->check = 0;
            tcph->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
                                       ip_payload_len, IPPROTO_TCP,
                                       csum_partial((char *)tcph, ip_payload_len, 0));
        }
    } else if (ip6h->nexthdr == IPPROTO_UDP) {
        udph = (struct udphdr *)buf_pos;
        buf_pos += sizeof(struct udphdr);
        data_len = ip_payload_len - sizeof(struct udphdr);

        if (unlikely(data_len < 0)) {
            return NF_DROP;
        }

        transform(buf_pos, data_len, info);

        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            udph->check = 0;
            udph->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
                                       ip_payload_len, IPPROTO_UDP,
                                       csum_partial((char *)udph, ip_payload_len, 0));
        }
    } else if (ip6h->nexthdr == IPPROTO_GRE) {
        greh = (struct gre_base_hdr *)buf_pos;
        if (greh->flags == 0 &&
                   (greh->protocol == htons(ETH_P_IP) || greh->protocol == htons(0x0101))) {
            greh->protocol = greh->protocol == htons(ETH_P_IP) ? htons(0x0101) : htons(ETH_P_IP);
            buf_pos += sizeof(struct gre_base_hdr);
            data_len = ip_payload_len - sizeof(struct gre_base_hdr);
            if (unlikely(data_len < 0)) {
                return NF_DROP;
            }
            transform(buf_pos, data_len, info);
        }
    }
    return XT_CONTINUE;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static int xt_xor_checkentry(const struct xt_tgchk_param *par)
{
    if (strcmp(par->table, "mangle")) {
        printk(KERN_WARNING "XOR: can only be called from"
                "\"mangle\" table, not \"%s\"\n", par->table);
        return -EINVAL;
    }

    return 0;
}
#else
static bool xt_xor_checkentry(const struct xt_tgchk_param *par)
{
    if (strcmp(par->table, "mangle")) {
        printk(KERN_WARNING "XOR: can only be called from"
                "\"mangle\" table, not \"%s\"\n", par->table);
        return false;
    }

    return true;
}
#endif

static struct xt_target xt_xor[] = {
    {
        .name = "XOR",
        .revision = 0,
        .family = NFPROTO_IPV4,
        .table = "mangle",
        .target = xt_xor_target4,
        .targetsize = sizeof(struct xt_xor_info),
        .checkentry = xt_xor_checkentry,
        .me = THIS_MODULE,
    },
    {
        .name = "XOR",
        .revision = 0,
        .family = NFPROTO_IPV6,
        .table = "mangle",
        .target = xt_xor_target6,
        .targetsize = sizeof(struct xt_xor_info),
        .checkentry = xt_xor_checkentry,
        .me = THIS_MODULE,
    },
};

static int __init xor_tg_init(void)
{
    return xt_register_targets(xt_xor, ARRAY_SIZE(xt_xor));
}

static void __exit xor_target_exit(void)
{
    xt_unregister_targets(xt_xor, ARRAY_SIZE(xt_xor));
}

module_init(xor_tg_init);
module_exit(xor_target_exit);
