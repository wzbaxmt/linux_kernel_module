ver = release
ifeq ($(ver), debug)
VERSION = `date "+%m%d.%H.%M"`D
EXTRA_CFLAGS += -D DEBUG -g
NAME = wyq
else
VERSION = `date "+%m%d.%H.%M"`R
NAME = wyq
endif

ifneq ($(KERNELRELEASE),)
	obj-m := $(NAME).o
	$(NAME)-objs := main.o netfilter.o func.o
else
	PWD := $(shell pwd)
	KDIR := /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)
	cp -rf $(NAME).ko ../$(NAME)_v$(VERSION).ko
	ld -r -d -o wyq.ko.debug wyq.o

clean:
	rm -f *.o *.o.cmd *.ko *.mod.c *.symvers *.order *.unsigned *.debug
	rm -rf .tmp_versions  ../*.ko
endif
