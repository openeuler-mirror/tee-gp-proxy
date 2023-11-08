#Makefile
obj-m   := vtzfdriver.o

vtzfdriver-objs := vtzf.o

RESULT := $(shell cat /proc/kallsyms | grep vsnprintf_s)

STATUS := $(findstring vsnprintf_s, $(RESULT))

# ifneq ($(STATUS), vsnprintf_s)
vtzfdriver-objs += libboundscheck/src/memcpy_s.o libboundscheck/src/memset_s.o libboundscheck/src/strcpy_s.o libboundscheck/src/strncpy_s.o \
libboundscheck/src/memmove_s.o libboundscheck/src/strcat_s.o libboundscheck/src/strncat_s.o libboundscheck/src/strtok_s.o \
libboundscheck/src/securecutil.o libboundscheck/src/secureprintoutput_a.o libboundscheck/src/snprintf_s.o libboundscheck/src/vsnprintf_s.o
vtzfdriver-objs += tlogger.o serialport.o tee_info.o reserved_shm.o process_data.o block_pages.o

# endif

KERN_VER = $(shell uname -r)
KERN_DIR = /lib/modules/$(KERN_VER)/build

EXTRA_CFLAGS += -fstack-protector-strong -DCONFIG_AUTH_ENHANCE
EXTRA_CFLAGS += -I$(PWD)/libboundscheck/include/
EXTRA_CFLAGS += -I$(PWD)/inc/

all:
	make -C $(KERN_DIR) M=`pwd` modules


.PHONY: clean
clean:
	# make -C $(KERN_DIR) M=`pwd` modules clean
	-rm -vrf *.o *.ko
	-rm -vrf *.order *.symvers *.mod.c *.mod.o .tmp_versions .*o.cmd .*.o.d *.mod


