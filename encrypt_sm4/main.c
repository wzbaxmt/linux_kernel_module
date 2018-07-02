#include <linux/module.h>
#include <linux/kthread.h>
#include "sm4.h"
#include <linux/jiffies.h>

static struct task_struct *t1;
static struct task_struct *t2;

typedef char BYTE;
BYTE dest[1024] = {0};
BYTE dest2[1024] = {0};
BYTE src[1024] = {0};
BYTE key[32] = {0};

int SM4ECBEncrypt( 
    BYTE *dest, 
    BYTE *source, 
    int sourceLen, 
    BYTE *key)
{
  sm4_context ctx;
  
  sm4_setkey_enc(&ctx,key);
  sm4_crypt_ecb(&ctx, 1, sourceLen, source, dest);

  return 0;
}

int SM4ECBDecrypt( 
    BYTE *dest, 
    BYTE *source, 
    int sourceLen, 
    BYTE *key)
{
  sm4_context ctx;
  
  sm4_setkey_dec(&ctx,key);
  sm4_crypt_ecb(&ctx,0, sourceLen, source, dest);
  
  return 0;
}
void test_sm4_enc1(void)
{
	//printk("test_sm4_enc1\n");
	SM4ECBEncrypt(&dest, &src, sizeof(src), &key);
}
void test_sm4_enc2(void)
{
	//printk("test_sm4_enc1\n");
	SM4ECBEncrypt(&dest2, &src, sizeof(src), &key);
}

void test_sm4_dec(void)
{
	printk("test_sm4_dec\n");

}

static int kthread_encrypt1(void *unused)
{
	unsigned int i;
	u32 start_time = jiffies_to_msecs(jiffies);
	i = 0;
	while(!kthread_should_stop())
	{
		i++;
		test_sm4_enc1();
		if(i%10000 == 0)
		{
			u32 curr_time = jiffies_to_msecs(jiffies);
			printk("thread 1 Total running time:  %lu ms, encrypt %d \tByte\n", curr_time - start_time, i);
			if(i > 4000000000)
				i = 0;
			//ssleep(1);//睡眠，放弃cpu
			msleep(2);
			//mdelay(20);//忙等待，不放弃cpu
		}
	}
	printk(KERN_ALERT "Stopping thread 1 ...\n");
	return 0;
}

static int kthread_encrypt2(void *unused)
{
	unsigned int i;
	u32 start_time = jiffies_to_msecs(jiffies);
	i = 0;
	while(!kthread_should_stop())
	{
		i++;
		test_sm4_enc2();
		if(i%10000 == 0)
		{
			u32 curr_time = jiffies_to_msecs(jiffies);
			printk("thread 2 Total running time:  %lu ms, encrypt %d \tByte\n", curr_time - start_time, i);
			if(i > 4000000000)
				i = 0;
			//ssleep(1);//睡眠，放弃cpu
			msleep(2);
			//mdelay(20);//忙等待，不放弃cpu
		}
	}
	printk(KERN_ALERT "Stopping thread 2 ...\n");
	return 0;
}

static int __init wyq_init(void)
{

	t1 = kthread_create(kthread_encrypt1,NULL,"mythread1");
	if(t1)
	{
		printk(KERN_INFO "Thread Created Sucessfully\n");
		wake_up_process(t1);
	}
	else
	{
		printk(KERN_ALERT "Thread Creation Failed\n");
	}
	
	t2 = kthread_create(kthread_encrypt2,NULL,"mythread2");
	if(t2)
	{
		printk(KERN_INFO "Thread Created Sucessfully\n");
		wake_up_process(t2);
	}
	else
	{
		printk(KERN_ALERT "Thread Creation Failed\n");
	}
	printk(KERN_INFO "wyq module init successful\n");

	return 0;
}

static void __exit wyq_exit(void)
{
	int ret;
	ret = kthread_stop(t1);
	if(!ret)
		printk(KERN_ALERT "Thread1 stopped");
	
	int ret2;
	ret2 = kthread_stop(t2);
	if(!ret2)
		printk(KERN_ALERT "Thread2 stopped");
	
	printk(KERN_INFO "wyq module exit successful\n");
}

module_init(wyq_init);
module_exit(wyq_exit);

MODULE_AUTHOR("houjian");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("netlink test module");
