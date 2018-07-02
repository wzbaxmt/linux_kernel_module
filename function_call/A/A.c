#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/jiffies.h>

void A_func(void)
{
	printk("A func ,A jiffies is : %llu\n", (u64)jiffies);
        return;
}
EXPORT_SYMBOL(A_func);
static int __init A_init(void)
{
        printk("A module init!\n");
        return 0;
}

static void __exit A_exit(void)
{
        printk("A module exit!\n");
        return;
}

module_init(A_init);
module_exit(A_exit);

MODULE_LICENSE("GPL");
