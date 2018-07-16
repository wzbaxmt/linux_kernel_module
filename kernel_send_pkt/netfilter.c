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

#define SERVER_IP "192.168.66.47"
#define CLIENT_IP "192.168.94.146"

struct socket *sock;

char *ifname = "eth1";
char *buffer = "wyq test from kernel!\n";
__u32 dstip = 0xc0a8422f;//192.168.66.47
__s16 dstport = 8000;

int do_filter(struct iphdr *iph)
{
	//if ((iph->daddr == in_aton(ENCCLT_IP)) || (iph->saddr == in_aton(ENCCLT_IP)))
	if(iph->saddr == in_aton(SERVER_IP) && IPPROTO_ICMP == iph->protocol)
		return 1;
	else 
		return 0;
}
static int send_udp_pkt(void)
{
	printk("send_udp_pkt\n");
	struct kvec iov;
	struct msghdr msg = {.msg_flags = MSG_DONTWAIT|MSG_NOSIGNAL};
	int len;
	iov.iov_base = (void *)buffer;
	iov.iov_len = strlen(buffer);
	len = kernel_sendmsg(sock, &msg, &iov, 1, strlen(buffer));
	if (len != strlen(buffer)) 
	{
		printk(KERN_ALERT "kernel_sendmsg err, len=%d, buffer=%d\n",len, (int)strlen(buffer));
		if (len == -ECONNREFUSED) 
		{
			printk(KERN_ALERT "Receive Port Unreachable packet!\n");
		}
	}
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
		
		debug("skb->len:%d, version:%d, ihl:%d, tos:%x, tot_len:%d,id:%d, frag_off:%d,ttl:%d, protocol:%d, check:%d, saddr:%pI4, daddr:%pI4\n",
			skb->len, iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len), ntohs(iph->id), ntohs(iph->frag_off) & ~(0x7 << 13), iph->ttl, iph->protocol, iph->check, &iph->saddr, &iph->daddr);
		send_udp_pkt();
	}
	return NF_ACCEPT;
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

static int connect_to_addr(struct socket *sock)
{
    struct sockaddr_in daddr;
    int err;
    daddr.sin_family = AF_INET;
    daddr.sin_addr.s_addr = cpu_to_be32(dstip);
    daddr.sin_port = cpu_to_be16(dstport);
    err = sock->ops->connect(sock, (struct sockaddr*)&daddr,
            sizeof(struct sockaddr), 0);
    if (err < 0) {
        printk(KERN_ALERT "sock connect err, err=%d\n", err);
        return err;
    }
    return 0;
}

static int udp_send_init(void)
{
    int err = 0;
    printk(KERN_ALERT "UDP send init\n");
    err = sock_create_kern(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
    if (err < 0) {
        printk(KERN_ALERT "UDP create sock err, err=%d\n", err);
        goto create_error;
    }
    sock->sk->sk_reuse = 1;

    err = bind_to_device(sock, ifname);
    if (err < 0) {
        printk(KERN_ALERT "Bind to %s err, err=%d\n", ifname, err);
        goto bind_error;
    }    
    err = connect_to_addr(sock);
    if (err < 0) {
        printk(KERN_ALERT "sock connect err, err=%d\n", err);
        goto connect_error;
    }
    
    return 0;
	
bind_error:
connect_error:
    sk_release_kernel(sock->sk);
create_error:
    return -1;
}

static void udp_send_exit(void)
{
	sk_release_kernel(sock->sk);
    printk(KERN_ALERT "UDP send quit\n");
    return;
}

int nf_init(void)
{
	printk("qtec mudule nf_init##############\n");
	udp_send_init();
	nfhk_local_in.hook = nf_hook_in;
	nfhk_local_in.pf = PF_BRIDGE;
	nfhk_local_in.hooknum = NF_BR_PRE_ROUTING;
	nfhk_local_in.priority = NF_BR_PRI_FIRST;

	return nf_register_hook(&nfhk_local_in);
}
void nf_fini(void)
{
	printk("qtec mudule nf_fini##############\n");
	udp_send_exit();
	nf_unregister_hook(&nfhk_local_in);
}
