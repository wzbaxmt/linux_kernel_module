/********************************************************
*	Filename:	replyMsg.h		               			*
*	Author	:	wyq(wangyunqiang@qtec.cn)               *
*                                                      	*
* 	History                                         	*
*		2018/07/17	Create								*
********************************************************/

#ifndef __SENDMSG_H__
#define __SENDMSG_H__
#if 0
char *ifname = "eth1";
char *buffer = "wyq test from kernel!\n";
__u32 dstip = 0xc0a8422f;//192.168.66.47
__s16 dstport = 8000;
#endif

void send_by_skb(PKT_INFO* hD, unsigned char* buf, int data_len, unsigned char* ifname);

#endif
