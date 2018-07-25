/********************************************************
*	Filename:	protocol.h		               			*
*	Author	:	wyq(wangyunqiang@qtec.cn)               *
*                                                      	*
* 	History                                         	*
*		2018/06/19	Create								*
********************************************************/
#ifndef __PROTOCOL_H__
#define __PROTOCOL_H__
#include <linux/list.h>

#define TIME_INTERVAL 60 * 10

#define DIDLen 8
#define KIDLen 16 //最带KeyID字节数
#define KEYLen 32

#define comKey 4
#define spKey 3

/*=======================================================================*/
#pragma pack(push)
#pragma pack(1)
typedef struct
{
	unsigned char flag[2];
	unsigned short msgLen;
	unsigned char encType;
	unsigned char keyType;	 //0 common 1 sp
	unsigned char deviceID[8]; // local deviceid
	unsigned char keyID[16];
	unsigned short CRC;
} ENC_HEADER; //32

struct psd_header //6 用于计算校验和
{
	unsigned int saddr;
	unsigned int daddr;
	char mbz;
	char ptcl;
	unsigned short tcpl;
};

typedef struct
{
	unsigned char version;
	unsigned char msgType;
	unsigned short requestID;
} NLMSG_HEADER;

typedef struct
{
	unsigned char sIP[4];
	unsigned char dIP[4];
	unsigned char sMac[6];
	unsigned char dMac[6];
	unsigned char sPort[2];
	unsigned char dPort[2];

} PKT_INFO; //24

typedef struct
{
	int ruleID;
	unsigned char encType;
	PKT_INFO pktInfo;
	unsigned char reserved[3];
	struct list_head storeList;
} LOCAL_CONFIG; //decide whether encrypt or not

typedef struct //48 +
{
	unsigned char keyID[16];
	unsigned char keyValue[32];
	unsigned char sm4OFB[1472];
} KEY_INFO;

typedef struct
{
	unsigned char deviceID[8];
	KEY_INFO keyInfo[3];
	struct list_head storeList;
} SPKEY_INFO;

typedef struct //4 与上层交互请求头
{
	unsigned char version;  //版本号，默认为1
	unsigned char msg_type; //0x01配置下发,0x10配置下发确认; 0x02配置上报,0x20,配置上报确认; 0x03密钥下发,0x30密钥下发确认
	unsigned short rq_id;   //消息序号，由发送端决定
} MSG_HD;

typedef struct
{
	MSG_HD msg_hd;
	unsigned short msg_type; // 0x00 ask key update  1 stop key update
	unsigned char deviceID[8];
} OPP_DID_MSG;

typedef struct
{
	MSG_HD msg_hd;
	unsigned int dataIn;
	unsigned int dataOut;
} FLOW_MSG;

typedef struct //48 +
{
	unsigned char keyID[16];
	unsigned char keyValue[32];
} KEY_INFO_RCV;

typedef struct //8 回复信息
{
	MSG_HD msg_hd;
	unsigned char status; //0x00 success
	unsigned char reserved[3];
} REPLY_MSG;
/*
store the key of each deviceID,
netfilter or netlink create node,
each node send deviceID to user layer once,
update by the netlink
*/
typedef struct
{
	unsigned char deviceID[8];
	int report; //reportID 0 not report
	int keyNum;
	KEY_INFO keyInfo[3];
	unsigned long seconds;
	struct list_head storeList;
} DEVICE_INFO;

/*store the deviceID of each IP, 
netfilter create node
*/
typedef struct
{
	PKT_INFO config;
	unsigned char deviceID[8]; //the other device
	unsigned char report;
	struct list_head storeList;
} IP2ID;

#pragma pack(pop)
/*=======================================================================*/
#endif
