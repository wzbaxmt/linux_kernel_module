/********************************************************
*	Filename:	netfilter.c		               			*
*	Author	:	wyq(wzbaxmt@gmail.com)               *
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/
#include <linux/inetdevice.h>

#include "netfilter.h"
#include "func.h"

typedef struct
{
	unsigned char sIP[4];
	unsigned char dIP[4];
	unsigned char sMac[6];
	unsigned char dMac[6];
	unsigned char sPort[2];
	unsigned char dPort[2];

} PKT_INFO; //24
PKT_INFO hD;

unsigned char dst_mac[ETH_ALEN] = {0x30, 0x9c, 0x23, 0x34, 0x86, 0x9c}; /* dst MAC */
unsigned char src_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x2c, 0xda, 0x58}; /* src MAC */


#define SERVER_IP "192.168.66.47"
#define CLIENT_IP "192.168.94.146"

struct socket *sock;

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
	if(iph->saddr == in_aton(SERVER_IP) && IPPROTO_ICMP == iph->protocol)
		return 1;
	else 
		return 0;
}
static void sock_init()
{
        struct ifreq ifr;
        
        sock_create_kern(PF_INET, SOCK_DGRAM, 0, &sock);
        strcpy(ifr.ifr_ifrn.ifrn_name, ifname);
        kernel_sock_ioctl(sock, SIOCSIFNAME, (unsigned long) &ifr);
}
static void pack_hD(void)
{
	memcpy(&hD.sMac, &dst_mac, sizeof(dst_mac));
	memcpy(&hD.dMac, &src_mac, sizeof(src_mac));
	memcpy(&hD.sIP, &dstip2, sizeof(dstip2));
	memcpy(&hD.dIP, &srcip2, sizeof(srcip2));
	memcpy(&hD.sPort, &dstport2, sizeof(dstport));
	memcpy(&hD.dPort, &dstport2, sizeof(dstport));
}
static void send_by_skb(PKT_INFO* hD, unsigned char* buf, int data_len)
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

        netdev = dev_get_by_name(&init_net,ifname);
        skb_len = LL_RESERVED_SPACE(netdev) + sizeof(struct iphdr) + sizeof(struct udphdr) + data_len + expand_len;
        printk("iphdr: %d\n", sizeof(struct iphdr));
        printk("udphdr: %d\n", sizeof(struct udphdr));
        printk("data_len: %d\n", data_len);
        printk("skb_len: %d\n", skb_len);
        
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
		
		udph->source = htons(*(hD->dPort));
        udph->dest = htons(*(hD->sPort));
		//memcpy(udph->source, hD->dPort, 2);
		//memcpy(udph->dest, hD->sPort, 2);
		printk("hD->sPort = %x,udph->dest = %x\n",hD->sPort,udph->dest);
        /* insert data in skb */
        pdata = skb_put(skb, data_len);
        if (pdata) {
                memcpy(pdata, buf, data_len);
        }
		udph->len = htons(8 + data_len);
        /* caculate checksum */
        udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, skb->csum);
        skb->csum = skb_checksum(skb, iph->ihl * 4, skb->len - iph->ihl * 4, 0);


        /* send packet */
        if (dev_queue_xmit(skb) < 0) {
                dev_put(netdev);
                kfree_skb(skb);
                printk("send packet by skb failed.\n");
                return;
        }
        printk("send packet by skb success.\n");
}

static int create_sock(void)
{
    int err = 0;
    err = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    return err;
}

static int bind_to_device(struct socket *sock, char *ifname)
{
    struct net *net;
    struct net_device *dev;
    __be32 addr;
    struct sockaddr_in sin;
    int err;
    net = sock_net(sock->sk);
    dev = __dev_get_by_name(net, ifname);

    if (!dev) {
        printk(KERN_ALERT "No such device named %s\n", ifname);
        return -ENODEV;    
    }
    addr = inet_select_addr(dev, 0, RT_SCOPE_UNIVERSE);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = addr;
    sin.sin_port = 0;
    err = sock->ops->bind(sock, (struct sockaddr*)&sin, sizeof(sin));
    if (err < 0) {
        printk(KERN_ALERT "sock bind err, err=%d\n", err);
        return err;
    }
    return 0;
}

static int connect_to_addr(struct socket *sock, __u32 dstip, __s16 dstport)
{
    struct sockaddr_in daddr;
    int err;
    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = dstip;
    daddr.sin_port = dstport;
    err = sock->ops->connect(sock, (struct sockaddr *)&daddr,
                             sizeof(struct sockaddr), 0);
    if (err < 0)
    {
        printk(KERN_ALERT "sock connect err, err=%d\n", err);
        return err;
    }
    return 0;
}

static int send_udp_pkt(char *buffer)
{
    struct kvec iov;
    struct msghdr msg = {.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL};
    int len;
    iov.iov_base = (void *)buffer;
    iov.iov_len = strlen(buffer);
    len = kernel_sendmsg(sock, &msg, &iov, 1, strlen(buffer));
    if (len != strlen(buffer))
    {
        printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%d\n", len, (int)strlen(buffer));
        if (len == -ECONNREFUSED)
        {
            printk(KERN_ALERT "Receive Port Unreachable packet!\n");
        }
		return -1;
    }
	return 0;
}

int send_udp_reply(char *ifname, __u32 dstip, __s16 dstport, char *buffer)
{
    int err = 0;
	err = create_sock();
	if (err < 0)
    {
        printk(KERN_ALERT "UDP create sock err, err=%d\n", err);
        return err;
    }
    //sock->sk->sk_reuse = 1; //端口复用
    
    err = bind_to_device(sock, ifname);
    if (err < 0)
    {
        printk(KERN_ALERT "Bind to %s err, err=%d\n", ifname, err);
    }
    err = connect_to_addr(sock, dstip, dstport);
    if (err < 0)
    {
        printk(KERN_ALERT "sock connect err, err=%d\n", err);
    }
	err = send_udp_pkt(buffer);
	{
        printk(KERN_ALERT "send_udp_pkt err, err=%d\n", err);
	}
	
	sk_release_kernel(sock->sk);
	return err;
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
		
		debug("skb->len:%d, version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",
			skb->len, iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), ntohs(iph->frag_off) & ~(0x7 << 13), iph->ttl, iph->protocol, iph->check, &iph->saddr, &iph->daddr);
		//send_udp_reply(ifname, dstip2, dstport2, buffer);
		pack_hD();
		send_by_skb(&hD, buffer, 21);
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
