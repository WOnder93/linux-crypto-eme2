obj-m += eme2.o

KERNEL_VERSION=$(shell uname -r)

all: eme2.c
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(KERNEL_VERSION)/build M=$(PWD) clean
