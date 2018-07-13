/********************************************************
*	Filename:	fun.h 	                    			*
*	Author	:	wyq(wzbaxmt@gmail.com)               	*
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/
#ifndef __FUNC_H__
#define __FUNC_H__
#include <linux/kernel.h>

//ver=debug 开打印
#ifdef DEBUG  
#define debug(format,...) printk(KERN_DEBUG format, ##__VA_ARGS__)  
#else  
#define debug(format,...)  
#endif  

void printkHex(char *data, int data_len, int padding_len, char *pt_mark);





#endif
