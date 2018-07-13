/********************************************************
*	Filename:	netfilter.c		               			*
*	Author	:	wyq(wzbaxmt@gmail.com)               *
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/
#include "netfilter.h"
#include "func.h"

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
	#if 1
	//debug("IP packet! h_dest:%pM, h_source:%pM, h_proto:%x\n", eth->h_dest, eth->h_source, ntohs(eth->h_proto));
	debug("skb->len:%d, version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",
		   skb->len, iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), ntohs(iph->frag_off) & ~(0x7 << 13), iph->ttl, iph->protocol, iph->check, &iph->saddr, &iph->daddr);
	#endif
	#if 0 
	iph->tos = 0x3c;
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl); //re-checksum for IP
	debug("tos:%x~~~~~~~~~~\n",iph->tos);
	#else
	debug("1 iph->frag_off:%x~~~~~~~~~~\n",iph->frag_off);
	iph->frag_off = htons(ntohs(iph->frag_off) | IP_CE);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl); //re-checksum for IP
	debug("2 iph->frag_off:%x~~~~~~~~~~\n",iph->frag_off);
	#endif
	return NF_ACCEPT;
}

int nf_init(void)
{
	printk("qtec mudule nf_init##############\n");
	nfhk_local_in.hook = nf_hook_in;
	nfhk_local_in.pf = PF_BRIDGE;
	nfhk_local_in.hooknum = NF_BR_FORWARD;
	nfhk_local_in.priority = NF_BR_PRI_FIRST;

	return nf_register_hook(&nfhk_local_in);
}
void nf_fini(void)
{
	printk("qtec mudule nf_fini##############\n");
	nf_unregister_hook(&nfhk_local_in);
}
