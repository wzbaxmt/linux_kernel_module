NAME := A
obj-m := $(NAME).o
KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	cp Module.symvers ../B
	cp -rf $(NAME).ko ../$(NAME).ko
clean:
	rm -rf *.o *.ko *.mod.c *.order *.symvers *.unsigned
	rm -rf ../$(NAME).ko
