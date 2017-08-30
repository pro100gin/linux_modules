#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <net/ip.h>

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define SOURCE_IP "192.168.2.1"
#define DEST_IP "8.8.8.8"

struct nf_hook_ops bundle;

uint32_t netfilter_hook(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    struct icmphdr* icmp = NULL;

    if (skb->protocol == htons(ETH_P_IP))
    {
        ip = (struct iphdr *)skb_network_header(skb);
        if (ip->version == 4) 
        {
            skb_set_transport_header(skb, ip->ihl * 4);
            
            switch(ip->protocol) {
                case IPPROTO_ICMP:
                    icmp = icmp_hdr(skb);
                    /*if (icmp->un.echo.id == htons(2))*/
                        printk(KERN_ALERT "ICMP packet, ezhi!\n");
                        /*return NF_DROP;*/
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
    bundle.hooknum = NF_INET_POST_ROUTING;
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

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
