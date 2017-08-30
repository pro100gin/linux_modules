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

#define SOURCE_IP "192.168.43.146"
#define DEST_IP "8.8.8.8"

struct nf_hook_ops bundle;

unsigned int inet_addr(char *str) 
{ 
    int a,b,c,d; 
    char arr[4]; 
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d); 
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d; 
    return *(unsigned int*)arr; 
} 

void icmp_ping(void) {
    struct net_device *net_dev = NULL;
    struct net *net = NULL;
	struct rtable *route_table = NULL;
	struct flowi4 fl4;
	struct sk_buff *skb = NULL;
    
	struct iphdr* iph = NULL;
    struct icmphdr* icmph = NULL;
    int hdr_size = 0;

    hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);

    skb = alloc_skb(hdr_size, GFP_ATOMIC);
    printk(KERN_ALERT "after alloc\n");
    if (skb == NULL) {
        printk(KERN_ALERT "alloc_skb");
        return;
    }

    skb_reserve(skb, hdr_size);
    skb_push(skb, sizeof(struct icmphdr));
    skb_push(skb, sizeof(struct iphdr));
    
    skb_set_mac_header(skb, 0);
    skb_set_network_header(skb, 0);
    skb_set_transport_header(skb, sizeof(struct iphdr));

    iph = ip_hdr(skb);

    iph->ihl = sizeof(struct iphdr)/4;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    iph->id = htons(1234);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = inet_addr(SOURCE_IP);
    iph->daddr = inet_addr(DEST_IP);

    icmph = icmp_hdr(skb);
    
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->un.echo.sequence = 0;
    icmph->un.echo.id = 0;

    /*iph->check = ip_fast_csum(iph, iph->ihl);*/
    icmph->checksum = ip_compute_csum(icmph, sizeof(struct icmphdr));

    net_dev = dev_get_by_name(&init_net, "enp0s3");
	/*net = dev_net(net_dev);*/
    skb->dev = net_dev;
	fl4.flowi4_oif = net_dev->ifindex;
	fl4.daddr = inet_addr(DEST_IP);
	fl4.saddr = inet_addr(SOURCE_IP);

	route_table = ip_route_output_key(&init_net, &fl4);

    skb_dst_set(skb, &route_table->dst);

    printk(KERN_ALERT "before ip_local_out\n");
    pr_info("ip_local_out: %d", ip_local_out(&init_net, NULL, skb));

}

int __init pf_init(void)
{
    printk(KERN_INFO "start module port filter\n");

	icmp_ping();
    return 0;
}

void __exit pf_exit(void)
{
    printk(KERN_INFO "end module port filter\n");
}

module_init(pf_init);
module_exit(pf_exit);

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
