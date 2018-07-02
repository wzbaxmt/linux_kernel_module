#include <linux/module.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/highmem.h>

static void printkHex(char *data, int data_len, int padding_len, char* pt_mark)
{	
	int i = 0;
	printk("[%s]length=%d:%d;Data Content:\n", pt_mark, data_len, padding_len);
	for (i = 0; i < (data_len+padding_len); i ++) 
	{
		if(0 == (i%16) && i != 0)
			printk("[%d]\n",i/16);
		printk("%02x ", data[i] & 0xFF);
	}
	printk("\n");
}
static void aes_cbc(void) //实现函数
{
	unsigned int ret;
	int i;
	char code[17] = "1234567887654321";
	char *key = "0123456789abcdef";//关键key
	char *iv = "1234567887654321";//设置iv值
	struct scatterlist sgd;//散集序列，输出
	struct scatterlist sgs;//散集序列，输入
	struct scatterlist sgl;//散集序列，解密后输出
	char last_mem[17];
	char dst_mem[17];
	char *out = NULL;
	char *result = NULL;
	char *src = NULL;
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	memset(last_mem,0,17);
	memset(dst_mem,0,17);
	/*分配块加密上下文
	cbc(aes)表示模式，也可以ofb(aes)等，通常第一个参数为0，第三个参数表示加密模式,
	*/
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);	
	desc.tfm = tfm;
	desc.flags = 0;
	/*设置散集序列，将Linux内核中虚拟内存的数据传送到散集序列供dma应用，其中dst_mem，code,last_mem是我们自己设定的值，后面的16表示数据长度大小*/
	sg_init_one(&sgd,dst_mem,16);
	sg_init_one(&sgs,code,16);
	sg_init_one(&sgl,last_mem,16);
	crypto_blkcipher_setkey(tfm,key,16);//设置key
	crypto_blkcipher_set_iv(tfm,iv,16);//设置iv
	/*将sgs(散集序列，物理内存)映射到Linux内核的虚拟内存中，目的是我们可以显示其数据*/
	src = kmap(sg_page(&sgs))+sgs.offset;
	printkHex(src, sgs.length, 0, "the orginal data is");
	kunmap(sg_page(&sgs));
	//加密
	ret = crypto_blkcipher_encrypt(&desc,&sgd,&sgs,sgs.length);
	if (!ret) 
	{
		printk("AES encrypt success*************************\n");
		out = kmap(sg_page(&sgd))+sgd.offset;
		printkHex(out, sgd.length, 0, "aes encrypt");
		kunmap(sg_page(&sgd));
	}
	else
	{
		printk("the encrypt is wrong\n");
		return ;
	}
	crypto_blkcipher_setkey(tfm,key,16);
	crypto_blkcipher_set_iv(tfm,iv,16);
	//解密
	ret = crypto_blkcipher_decrypt(&desc,&sgl,&sgd,sgd.length);
	if(!ret)
	{
		printk(KERN_INFO"AES decrypt success*************************\n"); 
		result = kmap(sg_page(&sgl))+sgl.offset;
		printkHex(result, sgl.length, 0, "aes decrypt");
		kunmap(sg_page(&sgl));
	}
	else
	{
		printk("the decrypt is wrong\n");
		return;
	}
	crypto_free_blkcipher(tfm); 
}
static void aes_ctr(void) //实现函数
{
	char iv[128];
	struct crypto_blkcipher *tfm;
	struct blkcipher_desc desc;
	struct scatterlist sgd;
	unsigned int iv_len;
	int ret = 0;
	char buf[17] = "1234567887654321";
	char *result = NULL;
	char *out = NULL;
	
	char *iv_org= "1234567887654321";//设置iv值
	char *src = NULL;
	char key[16] = "0123456789abcdef";//关键key
	unsigned int buflen = 16;
	unsigned int keylen = 16;
	sg_init_one(&sgd, (u8 *)buf, buflen);
	
	tfm = crypto_alloc_blkcipher("ctr(aes)", 0, CRYPTO_ALG_ASYNC);
	desc.tfm = tfm;
	desc.flags = 0;
	
	ret = crypto_blkcipher_setkey(tfm, key, keylen);
	#if 0
	iv_len = crypto_blkcipher_ivsize(tfm);
	if (iv_len) 
	{
		memset(&iv, 0xff, iv_len);
		crypto_blkcipher_set_iv(tfm, iv, iv_len);
	}
	#endif
	crypto_blkcipher_set_iv(tfm,iv_org,16);//设置iv
	/*将sgs(散集序列，物理内存)映射到Linux内核的虚拟内存中，目的是我们可以显示其数据*/
	src = kmap(sg_page(&sgd))+sgd.offset;
	printkHex(src, sgd.length, 0, "the orginal data is");
	kunmap(sg_page(&sgd));
	ret = crypto_blkcipher_encrypt(&desc, &sgd, &sgd, buflen);
	if (!ret) 
	{
		printk("AES encrypt success*************************\n");
		out = kmap(sg_page(&sgd))+sgd.offset;
		printkHex(out, sgd.length, 0, "aes encrypt");
		kunmap(sg_page(&sgd));
	}
	
	crypto_blkcipher_setkey(tfm,key,16);
	crypto_blkcipher_set_iv(tfm,iv_org,16);
	ret = crypto_blkcipher_decrypt(&desc, &sgd, &sgd, buflen);
	if(!ret)
	{
		printk(KERN_INFO"AES decrypt success*************************\n"); 
		result = kmap(sg_page(&sgd))+sgd.offset;
		printkHex(result, sgd.length, 0, "aes decrypt");
		kunmap(sg_page(&sgd));
	}
	crypto_free_blkcipher(tfm);
}


static void aes_gcm(void) //实现函数
{
	#if 0
	struct scatterlist assoc, pt, ct[2];

	char aead_req_data[sizeof(struct aead_request) +
			   crypto_aead_reqsize(tfm)]
		__aligned(__alignof__(struct aead_request));
	struct aead_request *aead_req = (void *) aead_req_data;
	char *data = "1234567887654321";
	char *b_0 = "1234567887654321";//设置iv值
	int data_len = 16;
	struct crypto_aead *tfm;
	int err;

	tfm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm))
	{
		printk("IS_ERR(tfm)\n");
		return;
	}
	err = crypto_aead_setkey(tfm, key, 16);
	if (!err)
		err = crypto_aead_setauthsize(tfm, 16);
	if (err)
	{
		printk("err tfm\n");		
		crypto_free_aead(tfm);
		return;
	}
	

	memset(aead_req, 0, sizeof(aead_req_data));

	sg_init_one(&pt, data, data_len);
	sg_init_one(&assoc, &aad[2], be16_to_cpup((__be16 *)aad));
	sg_init_table(ct, 2);
	sg_set_buf(&ct[0], data, data_len);
	sg_set_buf(&ct[1], mic, mic_len);

	aead_request_set_tfm(aead_req, tfm);
	aead_request_set_assoc(aead_req, &assoc, assoc.length);
	aead_request_set_crypt(aead_req, &pt, ct, data_len, b_0);

	crypto_aead_encrypt(aead_req);
	#else
	;
	#endif
}

static int __init aes_mod_init(void)
{
	printk("**************************aes_mod_init**************************************\n\n");
  	aes_cbc();
	aes_gcm();
	aes_ctr();
	return 0;
}
static void __exit aes_mod_fini(void) 
{
	printk("\n**************************aes_mod_fini**************************************\n");
}
module_init(aes_mod_init);
module_exit(aes_mod_fini);
 
 
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Quick & dirty crypto testing module");
MODULE_AUTHOR("dachuan");
// from http://blog.csdn.net/fengjingge/article/details/42192151

