#Makefile
obj-m   := virtio_console.o

vtzfdriver-objs := virtio_console.o

RESULT := $(shell cat /proc/kallsyms | grep vsnprintf_s)

STATUS := $(findstring vsnprintf_s, $(RESULT))

# ifneq ($(STATUS), vsnprintf_s)

# endif

KERN_VER = $(shell uname -r)
KERN_DIR = /lib/modules/$(KERN_VER)/build

EXTRA_CFLAGS += -fstack-protector-strong -DCONFIG_AUTH_ENHANCE
EXTRA_CFLAGS += -I$(PWD)/../tty/hvc

all:
	make -C $(KERN_DIR) M=`pwd` modules


.PHONY: clean
clean:
	# make -C $(KERN_DIR) M=`pwd` modules clean
	-rm -vrf *.o *.ko
	-rm -vrf *.order *.symvers *.mod.c *.mod.o .tmp_versions .*o.cmd .*.o.d
	-rm -vrf *.mod



