/********************************************************
*	Filename:	replyMsg.c		               			*
*	Author	:	wyq(wangyunqiang@qtec.cn)               *
*                                                      	*
* 	History                                         	*
*		2018/07/17	Create								*
********************************************************/
#include <linux/inetdevice.h>
#include <net/ip.h>

#include "protocol.h"
#include "replyMsg.h"
#include "func.h"

struct socket *sock;

void send_by_skb(PKT_INFO* hD, unsigned char* buf, int data_len, unsigned char* ifname)
{
        struct net_device *netdev;
        struct net *net;
        struct sk_buff *skb;
        struct ethhdr *eth;
        struct iphdr *iph;
        struct udphdr *udph;
        u16 expand_len = 16;        /* for skb align */
        u8 *pdata = NULL;
        u32 skb_len;
		
		printk("ifname:%s\n", ifname);
        netdev = dev_get_by_name(&init_net,ifname);
        skb_len = LL_RESERVED_SPACE(netdev) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len + expand_len;
        
        skb = dev_alloc_skb(skb_len);
        if (!skb) {
                return;
        }

        skb_reserve(skb, LL_RESERVED_SPACE(netdev));
        skb->dev = netdev;
        skb->pkt_type = PACKET_OTHERHOST;
        skb->protocol = htons(ETH_P_IP);
        skb->ip_summed = CHECKSUM_NONE;
        skb->priority = 0;

        
        /* construct ethernet header in skb */
        eth = (struct ethhdr *) skb_put(skb, sizeof(struct ethhdr));
		memcpy(&eth->h_dest, &hD->sMac, sizeof(hD->sMac));
		memcpy(&eth->h_source, &hD->dMac, sizeof(hD->dMac));
        eth->h_proto = htons(ETH_P_IP);

        /* construct ip header in skb */
		skb_set_network_header(skb, sizeof(struct ethhdr));
        skb_put(skb, sizeof(struct iphdr));
        iph = ip_hdr(skb);
        iph->version = 4;
        iph->ihl = sizeof(struct iphdr) >> 2;
        iph->frag_off = htons(IP_CE);
        iph->protocol = IPPROTO_UDP;
        iph->tos = 0;
		iph->id = 0x5555;
		memcpy(&iph->daddr, &hD->sIP, sizeof(hD->sIP));
		memcpy(&iph->saddr, &hD->dIP, sizeof(hD->dIP));
        iph->ttl = 0x40;
        iph->tot_len = htons(iph->ihl * 4 + data_len + 8);
        iph->check = 0;
        

        /* construct udp header in skb */
        //skb_set_transport_header(skb, sizeof(struct iphdr));
        skb_set_transport_header(skb, sizeof(struct ethhdr) + sizeof(struct iphdr));
        skb_put(skb, sizeof(struct udphdr));
        udph = udp_hdr(skb);
		
		//udph->source = htons(*(hD->dPort));
        //udph->dest = htons(*(hD->sPort));
		memcpy(&udph->source, hD->dPort, 2);
		memcpy(&udph->dest, hD->sPort, 2);
        /* insert data in skb */
        pdata = skb_put(skb, data_len);
        if (pdata) {
                memcpy(pdata, buf, data_len);
        }
		udph->len = htons(8 + data_len);
        /* caculate checksum */
        //udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
		udph->check = 0;
        skb->csum = skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0);

		printkHex(iph, iph->ihl * 4 + data_len, 8, "send_by_skb ip");
        /* send packet */
        if (dev_queue_xmit(skb) < 0) {
                dev_put(netdev);
                kfree_skb(skb);
                printk("send packet by skb failed.\n");
                return;
        }
        printk("send packet by skb success.\n");
}

