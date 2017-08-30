#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define BLOCK_PORT 7777

struct nf_hook_ops bundle;

uint32_t netfilter_hook(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    if (skb->protocol == htons(ETH_P_IP))
    {
        ip = (struct iphdr *)skb_network_header(skb);
        if (ip->version == 4) 
        {
            skb_set_transport_header(skb, ip->ihl * 4);
            
            switch(ip->protocol) {
                case IPPROTO_TCP:
                    tcp = (struct tcphdr *)skb_transport_header(skb);
                    if (tcp->dest == htons(BLOCK_PORT))
                        return NF_DROP;
                    break;
                case IPPROTO_UDP:
                    udp = (struct udphdr *)skb_transport_header(skb);
                    if (udp->dest == htons(BLOCK_PORT))
                        return NF_DROP;
                    break;
            }
        }
    }
    return NF_ACCEPT;
}

int __init pf_init(void)
{
    printk(KERN_INFO "start module port filter\n");

    bundle.hook = netfilter_hook;
    bundle.pf = PF_INET;
    bundle.hooknum = NF_INET_LOCAL_OUT;
    bundle.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&bundle);
    return 0;
}

void __exit pf_exit(void)
{
    nf_unregister_hook(&bundle);
    printk(KERN_INFO "end module port filter\n");
}

module_init(pf_init);
module_exit(pf_exit);
