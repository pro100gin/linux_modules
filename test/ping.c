#include "ping.h"

/*static uint16_t f_port;*/

static int __init
nf_ping_init(void)
{
	/*f_port = htons(7777);
	nf_register_hook(&nf_port_hook);*/
	if(send_icmp_request() < 0)
	{
		pr_alert("PING: send_icmp_request");
		return -1;
	}
	pr_info("PING: loaded");
	return 0;
}

static void __exit
nf_ping_exit(void)
{
	pr_info("PING: unload");
/*	nf_unregister_hook(&nf_port);*/
}

module_init(nf_ping_init);
module_exit(nf_ping_exit);

static int
send_icmp_request(void)
{
	struct net_device* dev;
	struct sk_buff *skb;
	struct flowi4 flw4;
	struct rtable *rtbl;
	struct iphdr *iph;
	struct icmphdr *icmph;

	skb = alloc_skb(PING_HDR_SIZE, GFP_ATOMIC);
	if(skb == NULL)
	{
		pr_alert("PING: cannot alloc_skb");
		return -1;
	}
	skb_reserve(skb, PING_HDR_SIZE);
	skb_push(skb, sizeof(struct icmphdr));
	skb_push(skb, sizeof(struct iphdr));
	skb_set_mac_header(skb, 0);
	skb_set_network_header(skb, 0);
	skb_set_transport_header(skb, sizeof(struct iphdr));

	dev = dev_get_by_name(&init_net, PING_IFNAME);
	skb->dev = dev;
	flw4.saddr = inet_addr(SADDR); 
	flw4.daddr = inet_addr(DADDR); 
	flw4.flowi4_oif = dev->ifindex; 

	iph = ip_hdr(skb);
	iph->version	= 4;
	iph->ihl	= sizeof(struct iphdr) / 4;
	iph->tos	= 0;
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
	iph->protocol	= IPPROTO_ICMP;
	iph->check	= 0;
	iph->saddr	= flw4.saddr;
	iph->daddr	= flw4.daddr;
	iph->ttl	= 255;
	icmph = icmp_hdr(skb);
	icmph->type = ICMP_ECHO;                                                     
 	icmph->code = 0;
 	icmph->un.echo.sequence = 1234;
 	icmph->un.echo.id = 0;
 	icmph->checksum = ip_compute_csum(icmph, sizeof(struct icmphdr));

	rtbl = ip_route_output_key(&init_net, &flw4);
	skb_dst_set(skb, &rtbl->dst);
	
	if (skb_network_header(skb) < skb->data) {
		pr_info("PING: 12321312312");
		pr_info("PING: nh = %p\ndata = %p", skb_network_header(skb), skb->data);
	}

	if (skb_network_header(skb) > skb_tail_pointer(skb)) {
		pr_info("PING: 098765");
	}

	pr_info("PING: ilo=%d", ip_local_out(&init_net, NULL, skb));
	return 0;
}

static unsigned int
inet_addr(char *str)
{
    int a, b, c, d;
    char arr[4];
    sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;
    return *(unsigned int *)arr;
}
/*uint32_t
block_packet_by_port(void *priv, struct sk_buff * skb, const struct nf_hook_state *state)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	ip_header = ip_hdr(skb);

	switch(ip_header->protocol) {
		case IPPROTO_TCP:
			tcp_header = tcp_hdr(skb);
			if(tcp_header->source == f_port|| tcp_header->dest == f_port)
			{
				return NF_DROP;
			}
			break;
		case IPPROTO_UDP:
			udp_header = udp_hdr(skb);
			if(udp_header->source == f_port || udp_header->dest == f_port)
			{
				return NF_DROP;
			}
			break;
	}

	return NF_ACCEPT;
}*/
