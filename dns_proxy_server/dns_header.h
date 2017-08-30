#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/net_namespace.h>
#include <net/route.h>
#include <net/ip.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rbtree.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define DNS_PORT 53
#define MAX_HOSTNAME_SIZE 256
#define BITS 3

typedef struct _rb_tree {
    struct rb_node node;
    unsigned char name[MAX_HOSTNAME_SIZE];
    unsigned int addr;
    unsigned int ttl;
} DNS_RECORD;

typedef struct
{
	unsigned short id;       // identification number
	unsigned char rd :1;     // recursion desired
	unsigned char tc :1;     // truncated message
	unsigned char aa :1;     // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1;     // query/response flag
	unsigned char rcode :4;  // response code
	unsigned char cd :1;     // checking disabled
	unsigned char ad :1;     // authenticated data
	unsigned char z :1;      // its z! reserved
	unsigned char ra :1;     // recursion available
	unsigned short q_count;  // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
} DNS_HEADER;

typedef struct
{
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;

typedef struct
{
    int a;
} R_DATA;

typedef struct
{
    unsigned short name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    /*R_DATA *resource;*/
    unsigned int rdata;
} __attribute__((packed))  RES_RECORD;
 
typedef struct
{
    unsigned char *name;
    QUESTION *ques;
} QUERY;

struct nf_hook_ops bundle[2];
struct rb_root dr_tree = RB_ROOT;
