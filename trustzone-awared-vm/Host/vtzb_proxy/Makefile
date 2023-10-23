TARGET_APP := vtz_proxy
LIBC_SEC   := libboundscheck
TARGET_LIBSEC := libboundscheck.so

all: $(TARGET_LIBSEC) $(TARGET_APP)
	@cd $(LIBC_SEC) && $(MAKE) clean

$(TARGET_LIBSEC):
	@echo "compile libboundscheck ..."
	@$(MAKE) -C $(LIBC_SEC)
	sudo cp -rf $(LIBC_SEC)/lib/libboundscheck.so /usr/lib64
	@echo "compile libboundscheck done"

APP_CFLAGS += -DSECURITY_AUTH_ENHANCE
APP_CFLAGS += -Ilibboundscheck/include
APP_CFLAGS += -Iinclude -Iinclude/cloud
APP_CFLAGS += -Werror -Wall -Wextra -fstack-protector-all -Wl,-z,relro,-z,now,-z,noexecstack -s -fPIE -pie -D_FORTIFY_SOURCE=2 -O2
APP_LDFLAGS += -lboundscheck -Llibboundscheck/lib -lpthread

APP_SOURCES := ./vtzb_proxy.c \
				./thread_pool.c \
				./virt.c \
				./serial_port.c \
				./debug.c \
				./agent.c \
				./process_data.c \
				./tlogcat.c \

APP_OBJECTS := $(APP_SOURCES:.c=.o)

$(TARGET_APP): $(TARGET_LIBSEC) $(APP_SOURCES)
	@echo "compile vtzb_proxy ..."
	@$(CC) $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)
	@echo "compile vtzb_proxy done"

clean:
	@cd $(LIBC_SEC) && $(MAKE) clean
	@rm -rf vtz_proxy
