#include <linux/module.h>
//#include <linux/kernel.h>

void helloworld(void)
{
	printk("hello world\n");
}
static int __init hello_init(void)
{
	printk("test module init\n");
	helloworld();
	return 0;
}

static void __exit hello_exit(void)
{
	printk("test module exit\n");
}

module_init(hello_init);
module_exit(hello_exit);

