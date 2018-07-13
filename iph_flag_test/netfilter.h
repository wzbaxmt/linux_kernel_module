/********************************************************
*	Filename:	netfilter.h		               			*
*	Author	:	wyq(wzbaxmt@gmail.com)               	*
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/
#ifndef __NETFILTER_H__
#define __NETFILTER_H__

#include <linux/netfilter_bridge.h>
#include <net/ip.h>

#define PKT_IN	1
#define PKT_OUT	0

#define ENC_OUT 1
#define DEC_IN	0


#define ACCEPT	0
#define STOLEN	1
#define	DROP	2
#define TIME_OUT_SEC 20 //udp id超时时间，超时后删除
#define MTU 1400
		



struct udp_id_node
{
	unsigned short id;
	uint16_t sPort;
	uint16_t dPort;
	unsigned long create_time;
	struct list_head udp_id_list;
};

static struct nf_hook_ops nfhk_local_in;

int nf_init(void);
void nf_fini(void);

#endif
