#include "dns_header.h"

DNS_RECORD *search_dr(struct rb_root *root, char *name)
{
  	struct rb_node *node = root->rb_node;

  	while (node) {
  		DNS_RECORD *data = container_of(node, DNS_RECORD, node);
		int result;

		result = strcmp(name, data->name);

		if (result < 0)
  			node = node->rb_left;
		else if (result > 0)
  			node = node->rb_right;
		else
  			return data;
	}

	return NULL;
}

int insert_dr(struct rb_root *root, DNS_RECORD *data)
{
    struct rb_node **new = &(root->rb_node), *parent = NULL;

  	/* Figure out where to put new node */
  	while (*new) {
  		DNS_RECORD *this = container_of(*new, DNS_RECORD, node);
  		int result = strcmp(data->name, this->name);

		parent = *new;
  		if (result < 0)
  			new = &((*new)->rb_left);
  		else if (result > 0)
  			new = &((*new)->rb_right);
  		else
  			return 0;
  	}

  	/* Add new node and rebalance tree. */
  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, root);

	return 1;
}

unsigned int inet_addr(char *str) 
{ 
    int a,b,c,d; 
    char arr[4]; 
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d); 
    arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d; 
    return *(unsigned int*)arr; 
} 

void send_reply(struct sk_buff *dns_request, DNS_RECORD *dns_record) {
	struct rtable *route_table = NULL;
	struct flowi4 fl4;
	struct sk_buff *skb = NULL;
    
	struct iphdr* iph = NULL;
	struct udphdr* udph = NULL;
    DNS_HEADER *dnsh = NULL;
    RES_RECORD *ans = NULL;

    uint8_t *ip_addr_byte = NULL;

    int tmp_addr = 0; 
    short tmp_port = 0; 
    int hdr_size = 0;
    
    hdr_size = 
        sizeof(struct ethhdr) +
        sizeof(struct iphdr) +
        sizeof(struct udphdr) +
        sizeof(DNS_HEADER) +
        strlen(dns_record->name) + 5 + /*queries except name*/
        sizeof(RES_RECORD);

    printk(KERN_INFO "[dns reply] dns request len: %d", dns_request->len);
    printk(KERN_INFO "[dns reply] skb data len: %d", dns_request->data_len);
    /*skb = alloc_skb(hdr_size, GFP_ATOMIC);
    printk(KERN_ALERT "after alloc\n");
    if (skb == NULL) {
        printk(KERN_ALERT "alloc_skb");
        return;
    }*/

    /*printk(KERN_ALERT "sizeof(skb) %d skb->len %d truesize %d", sizeof(struct sk_buff), dns_request->len, dns_request->truesize);*/
    fl4.flowi4_oif = dns_request->dev->ifindex;
    skb = skb_copy_expand(dns_request, 0, 16, GFP_ATOMIC);
    skb->len += 16;
    /*skb->data_len += 16;*/
    skb->tail += 16;
    //skb->end +=160;
    /*skb_reserve(skb, hdr_size);
    skb_push(skb, hdr_size - sizeof(struct ethhdr));
    
    skb_set_mac_header(skb, 0);
    skb_set_network_header(skb, 0);
    skb_set_transport_header(skb, sizeof(struct iphdr));
    */

    iph = ip_hdr(skb);
    iph->tot_len = htons(ntohs(iph->tot_len) + 16);
    iph->ttl = 255;
    iph->check = 0;
    tmp_addr = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_addr;
    iph->check = ip_fast_csum(iph, iph->ihl);
    printk(KERN_INFO "[dns reply] iph->protocol: %d", iph->protocol);
   
    udph = udp_hdr(skb);
    udph->len = htons(ntohs(udph->len) + 16);
    printk(KERN_INFO "[dns reply] udph->dest: %d", ntohs(udph->dest));
    tmp_port = udph->source;
    udph->source = udph->dest;
    udph->dest = tmp_port; 

    dnsh = (DNS_HEADER *) (udph +1);
    dnsh->qr = 1;
    dnsh->rd = 1;
    dnsh->ra = 1;
    dnsh->ad = 0;
    dnsh->q_count = htons(1);
    dnsh->ans_count = htons(1);
    dnsh->auth_count = htons(0);
    dnsh->add_count = htons(0);
        
    ans = (RES_RECORD *) ((char *) udph + 
            sizeof(struct udphdr) + 
            sizeof(DNS_HEADER) + 
            strlen(dns_record->name) + 5);
    ans->name = 0xcc0;
    ans->type = htons(1);
    ans->_class = htons(1);
    ans->ttl = dns_record->ttl;
    ans->data_len = htons(4);
    ans->rdata = dns_record->addr;

    printk(KERN_INFO "[dns reply] name: %s # (%hu)", (char*)udph + sizeof(struct udphdr) + sizeof(DNS_HEADER), htons(ans->name));

	fl4.daddr = iph->daddr;
	fl4.saddr = iph->saddr;
	route_table = ip_route_output_key(&init_net, &fl4);
    skb_dst_set(skb, &route_table->dst);

    /*skb_reserve(skb, hdr_size);
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

    iph->check = ip_fast_csum(iph, iph->ihl);
    icmph->checksum = ip_compute_csum(icmph, sizeof(struct icmphdr));*/

    /*net_dev = dev_get_by_name(&init_net, "enp0s3");
    skb->dev = net_dev;
	fl4.flowi4_oif = net_dev->ifindex;
	fl4.daddr = inet_addr(DEST_IP);
	fl4.saddr = inet_addr(SOURCE_IP);

	route_table = ip_route_output_key(&init_net, &fl4);

    skb_dst_set(skb, &route_table->dst);*/
    
    /*skb_reset_mac_header(skb);
    memcpy(skb->sk, dns_request->sk, sizeof(struct sock));*/
    
    ip_addr_byte = (uint8_t*) &ans->rdata;
    printk(KERN_INFO "[dns reply] addr: %d.%d.%d.%d # (%d)", ip_addr_byte[0], ip_addr_byte[1], ip_addr_byte[2], ip_addr_byte[3], ntohl(ans->rdata));
    printk(KERN_INFO "[dns reply] skb len: %d", skb->len);
    printk(KERN_INFO "[dns reply] skb data len: %d", skb->data_len);
    
    printk(KERN_INFO "[dns reply] ip_local_out: %d", ip_local_out(&init_net, NULL, skb));
    printk(KERN_INFO "\n");
}

uint32_t dns_request_hook(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
    struct iphdr *ip = NULL;
    struct udphdr *udp = NULL;

	DNS_HEADER *dns = NULL;
	QUERY *qinfo = NULL;
    DNS_RECORD *dr_node = NULL, *dr_tmp_node = NULL; 

    uint8_t *name = NULL;

    if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	ip = (struct iphdr *)skb_network_header(skb);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP)
		return NF_ACCEPT; 

    skb_set_transport_header(skb, ip->ihl * 4);
    udp = (struct udphdr *)skb_transport_header(skb);
    if (udp->dest != ntohs(DNS_PORT))
		return NF_ACCEPT;
	
    printk(KERN_INFO "[dns query] udp dest port: %d", ntohs(udp->dest));

	dns = (DNS_HEADER *)(udp + 1);	
	printk(KERN_INFO "[dns query] transaction id: %hu", ntohs(dns->id));

	qinfo = (QUERY *)(dns + 1);
	name = (uint8_t *)qinfo;
    printk(KERN_INFO "[dns query] name: %s (%d)", name, strlen(name));
    printk(KERN_INFO "\n");
    
    dr_node = kmalloc(sizeof(DNS_RECORD), GFP_KERNEL);
	if (dr_node == NULL) {
		printk("kmalloc(dr)");
		return -ENOMEM;
	}

    dr_tmp_node = search_dr(&dr_tree, name);
    if (dr_tmp_node == NULL)
        return NF_ACCEPT;

    send_reply(skb, dr_tmp_node);
    printk(KERN_INFO "\n");
    
    return NF_DROP/*NF_STOLEN*/;
}

uint32_t dns_reply_hook(void *priv,
			       struct sk_buff *skb,
			       const struct nf_hook_state *state)
{
    struct iphdr *ip = NULL;
    struct udphdr *udp = NULL;

	DNS_HEADER *dns = NULL;
	QUERY *qinfo = NULL;
    DNS_RECORD *dr_node = NULL, *dr_tmp_node = NULL; 
    RES_RECORD *ans = NULL;

    uint8_t *name = NULL, *ip_addr_byte = NULL;
    uint16_t ans_offset = 0;

    if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	ip = (struct iphdr *)skb_network_header(skb);
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP)
		return NF_ACCEPT; 

    skb_set_transport_header(skb, ip->ihl * 4);
    udp = (struct udphdr *)skb_transport_header(skb);
    if (udp->source != ntohs(DNS_PORT))
		return NF_ACCEPT;
	
    printk(KERN_INFO "[dns answer] udp source  port: %d", ntohs(udp->source));

	dns = (DNS_HEADER *)(udp + 1);	
	printk(KERN_INFO "[dns answer] transaction id: %hu", ntohs(dns->id));

	qinfo = (QUERY *)(dns + 1);
	name = (uint8_t *)qinfo;

    /*dr_tmp_node = search_dr(&dr_tree, name);
    if (dr_tmp_node != NULL)
        return NF_ACCEPT;*/

    ans_offset = strlen(name) + 5; 
    ans = (RES_RECORD *) ((uint8_t *)qinfo + ans_offset);
    ip_addr_byte = (uint8_t*) &ans->rdata;

    printk(KERN_INFO "[dns answer] addr #1: %d.%d.%d.%d # (%d)", ip_addr_byte[0], ip_addr_byte[1], ip_addr_byte[2], ip_addr_byte[3], ntohl(ans->rdata));

    dr_tmp_node = search_dr(&dr_tree, name);
    if (dr_tmp_node != NULL)
        return NF_ACCEPT;

    dr_node = kmalloc(sizeof(DNS_RECORD), GFP_KERNEL);
	if (dr_node == NULL) {
		printk("kmalloc(dr)");
		return -ENOMEM;
	}

    strncpy(dr_node->name, name, MAX_HOSTNAME_SIZE);
    dr_node->addr = ans->rdata;
    dr_node->ttl = ans->ttl;

    printk(KERN_INFO "[dns answer] name: %s (%d) # (%hu)", dr_node->name, strlen(dr_node->name), ntohs(ans->name));
    printk(KERN_INFO "[dns answer] type: %hu", ntohs(ans->type));
    printk(KERN_INFO "[dns answer] class: %hu", ntohs(ans->_class));
    printk(KERN_INFO "[dns answer] ttl: %d", ntohl(dr_node->ttl));
    printk(KERN_INFO "[dns answer] data length: %hu", ntohs(ans->data_len));
    printk(KERN_INFO "[dns answer] addr: %d.%d.%d.%d # (%d)", ip_addr_byte[0], ip_addr_byte[1], ip_addr_byte[2], ip_addr_byte[3], ntohl(dr_node->addr));
    printk(KERN_INFO "\n");

    insert_dr(&dr_tree, dr_node);
    
    return NF_ACCEPT /*NF_DROP*/;
}

int __init pf_init(void)
{

    printk(KERN_INFO "[dns proxy server module] start");
    printk(KERN_INFO "\n");

    bundle[0].hook = dns_request_hook;
    bundle[0].pf = PF_INET;
    bundle[0].hooknum = NF_INET_POST_ROUTING;
    bundle[0].priority = NF_IP_PRI_FIRST;
    nf_register_hook(&bundle[0]);
    
    bundle[1].hook = dns_reply_hook;
    bundle[1].pf = PF_INET;
    bundle[1].hooknum = NF_INET_LOCAL_IN;
    bundle[1].priority = NF_IP_PRI_FIRST;
    nf_register_hook(&bundle[1]);
    
    return 0;
}

void __exit pf_exit(void)
{
    nf_unregister_hook(&bundle[0]);
    nf_unregister_hook(&bundle[1]);
    
    printk(KERN_INFO "[dns proxy server module] end");
    printk(KERN_INFO "\n");
}

module_init(pf_init);
module_exit(pf_exit);

MODULE_LICENSE("GPL");
MODULE_LICENSE("GPL v2");
