obj-m += eme2_module.o eme2_test.o

eme2_module-objs += blockwalk.o eme2.o

KERNEL_VERSION=$(shell uname -r)

all:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean
