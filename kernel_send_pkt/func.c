/********************************************************
*	Filename:	fun.c 	                    			*
*	Author	:	wyq(wzbaxmt@gmail.com)              	*
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/
#include "func.h"

void printkHex(char *data, int data_len, int padding_len, char *pt_mark)
{ 
	#ifdef DEBUG 
	int i = 0;
	printk("[%s]length=%d:%d;Data Content:\n", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len + padding_len); i++)
	{
		if (0 == (i % 16) && i != 0)
			printk("[%d]\n", i / 16);
		printk("%02x ", data[i] & 0xFF);
	}
	printk(" \n");
	#else  
	;
	#endif  
}


