/********************************************************
*	Filename:	netfilter.c		               			*
*	Author	:	wyq(wzbaxmt@gmail.com)               *
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/
#include <linux/inetdevice.h>
#include <linux/inet.h>

#include "netfilter.h"
#include "func.h"
#include "protocol.h"
#include "replyMsg.h"

PKT_INFO hD;
unsigned char	localDeviceID[8] = {0};

unsigned char dst_mac[ETH_ALEN] = {0x30, 0x9c, 0x23, 0x34, 0x86, 0x9c}; /* dst MAC */
unsigned char src_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x2c, 0xda, 0x58}; /* src MAC */


#define SERVER_IP "192.168.66.47"
#define CLIENT_IP "192.168.94.146"


char *ifname = "eth0";
char *buffer = "wyq test from kernel!\n";
__u32 srcip = 0xc0a8426f;//192.168.66.111
__u32 dstip = 0xc0a8422f;//192.168.66.47

__u32 dstip2 = 0x2f42a8c0;
__u32 srcip2 = 0x6f42a8c0;//192.168.66.111

__s16 dstport = 8000;
__s16 dstport2 = 80;

#define ETH_ALEN 6

int do_filter(struct iphdr *iph)
{
	//if ((iph->daddr == in_aton(ENCCLT_IP)) || (iph->saddr == in_aton(ENCCLT_IP)))
	if(IPPROTO_ICMP == iph->protocol)
		return 1;
	else 
		return 0;
}
static unsigned int nf_hook_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct ethhdr *eth = NULL; //Mac header
	struct iphdr *iph = NULL;  //IP header

	if (skb == NULL)
	{
		printk("skb is NULL!\n");
		return NF_ACCEPT;
	}
	eth = (struct ethhdr *)skb_mac_header(skb);
	if (eth == NULL)
	{
		printk("eth is NULL!\n");
		return NF_ACCEPT;
	}
	else if (ETH_P_IP != ntohs(eth->h_proto))
	{
		//debug("not IP packet! h_dest:%pM, h_source:%pM, h_proto:%x\n", eth->h_dest, eth->h_source, ntohs(eth->h_proto));
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	if (iph == NULL)
	{
		printk("iph is NULL!\n");
		return NF_ACCEPT;
	}
	if (do_filter(iph))
	{
		
		memcpy(&hD.sMac, &eth->h_source, sizeof(eth->h_source));
		memcpy(&hD.dMac, &eth->h_dest, sizeof(eth->h_dest));
		memcpy(&hD.sIP, &iph->saddr, sizeof(iph->saddr));
		memcpy(&hD.dIP, &iph->daddr, sizeof(iph->daddr));
		memcpy(&hD.sPort, &dstport2, 2);
		memcpy(&hD.dPort, &dstport2, 2);
		
		ENC_HEADER enc_header = {0};
		enc_header.flag[0] = 0xff;
		enc_header.flag[1] = 0xff;
		enc_header.encType = 0xff;
		memcpy(&enc_header.deviceID, localDeviceID, DIDLen);
		enc_header.CRC = 0x2222;
		send_by_skb(&hD, (unsigned char*)&enc_header, sizeof(ENC_HEADER), skb->dev->name);
		
		debug("skb->len:%d, version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",
			skb->len, iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), ntohs(iph->frag_off) & ~(0x7 << 13), iph->ttl, iph->protocol, iph->check, &iph->saddr, &iph->daddr);
	}
	return NF_ACCEPT;
}
int nf_init(void)
{
	printk("qtec mudule nf_init##############\n");
	nfhk_local_in.hook = nf_hook_in;
	nfhk_local_in.pf = PF_BRIDGE;
	nfhk_local_in.hooknum = NF_BR_PRE_ROUTING;
	nfhk_local_in.priority = NF_BR_PRI_FIRST;

	return nf_register_hook(&nfhk_local_in);
}
void nf_fini(void)
{
	printk("qtec mudule nf_fini##############\n");
	nf_unregister_hook(&nfhk_local_in);
}
