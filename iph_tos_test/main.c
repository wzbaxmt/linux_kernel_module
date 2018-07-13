/********************************************************
*	Filename:	main.c 	                    			*
*	Author	:	wyq(wzbaxmt@gmail.com)					*
*                                                      	*
* 	History                                         	*
*		2018/05/29	Create								*
********************************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include "main.h"
#include "netfilter.h"

MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_VERSION(DRV_VERSION);
MODULE_AUTHOR(DRV_COPYRIGHT " " DRV_AUTHOR);
MODULE_LICENSE("GPL");
MODULE_ALIAS("wyq");

static int init(void)
{
	printk("mudule init#####################################################################################################################\n");
	unsigned int ret;
	ret = nf_init();
	if (ret < 0)
	{
		printk("Netfilter Register Error\n");
		return ret;
	}
	return 0;
}

static void fini(void)
{
	nf_fini();
	printk("module exit #####################################################################################################################\n");
}

module_init(init);
module_exit(fini);
