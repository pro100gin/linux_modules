#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/string.h>
#include <asm/uaccess.h>

#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <net/ip.h>
#include <net/flow.h>
#include <net/net_namespace.h>
#include <net/checksum.h>

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Alexander Lopatin");
MODULE_DESCRIPTION("A module for simple one-time icmp-request request.");

#define PING_IFNAME "enp0s3"
#define SADDR "192.168.43.146" 
#define DADDR "8.8.8.8" 

#define PING_HDR_SIZE sizeof(struct ethhdr) + \
					   sizeof(struct iphdr) +  \
					   sizeof(struct icmphdr)

static int send_icmp_request(void);
static unsigned int inet_addr(char *str);

static int __init nf_ping_init(void);
static void __exit nf_ping_exit(void);

/*static uint32_t block_packet_by_port(void *priv, struct sk_buff * skb, const struct nf_hook_state *state);

static struct nf_hook_ops nf_port_hook = {
	.hook = block_packet_by_port,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};
*/
