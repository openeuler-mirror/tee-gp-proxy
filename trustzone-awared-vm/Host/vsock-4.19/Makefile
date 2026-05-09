# SPDX-License-Identifier: GPL-2.0
obj-m += vhost_vsock.o

vhost_vsock-y := vsock.o

KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ifeq ($(KERNELRELEASE),)

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
endif