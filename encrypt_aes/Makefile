NAME = aes
ifneq ($(KERNELRELEASE),)
	obj-m := aes.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -f *.o *.o.cmd *.ko *.mod.c *.symvers *.order *.unsigned
	rm -rf .tmp_versions
endif
