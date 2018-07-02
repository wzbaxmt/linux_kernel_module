NAME = test
ifneq ($(KERNELRELEASE),)
	obj-m := $(NAME).o
	$(NAME)-objs := main.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)

clean:
	rm -f *.o *.o.cmd *.ko *.mod.c *.symvers *.order *.unsigned
	rm -rf .tmp_versions
endif
