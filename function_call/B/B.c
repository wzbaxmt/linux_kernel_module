#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/jiffies.h>

extern void A_func(void);

static int __init B_init(void)
{
        printk("B module init!\n");
	printk("B func ,B jiffies is : %llu\n", (u64)jiffies);
        A_func();
	printk("B func ,B jiffies is : %llu\n", (u64)jiffies);
        return 0;
}

static void __exit B_exit(void)
{
        printk("B module exit!\n");
        return;
}

module_init(B_init);
module_exit(B_exit);

MODULE_LICENSE("GPL");
