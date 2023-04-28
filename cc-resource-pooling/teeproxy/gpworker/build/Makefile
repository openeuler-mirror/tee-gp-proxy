CUR_DIR=$(shell pwd)
iTrustee_SDK_PATH=${CUR_DIR}/../../../..

TARGET_APP := gpworker

APP_SOURCES := ../gpworker.c ../threadpool.c ../condition.c ../tzcp_dbus.c

# APP_SOURCES += $(iTrustee_SDK_PATH)/src/CA/cloud/libteec_adaptor.c

APP_CFLAGS += -fstack-protector-strong -fPIC -g

APP_CFLAGS += -I$(iTrustee_SDK_PATH)/include/CA -I$(iTrustee_SDK_PATH)/thirdparty/open_source/libboundscheck/include 

APP_CFLAGS += -I/usr/include/dbus-1.0 -I/usr/lib64/dbus-1.0/include

APP_LDFLAGS += -ldl -lpthread -lboundscheck -lteec -lm

APP_LDFLAGS += -z text -z now -z relro -z noexecstack -pie

APP_LDFLAGS += `pkg-config --libs --cflags dbus-1`

APP_OBJECTS := $(APP_SOURCES:.c=.o)
$(TARGET_APP): $(APP_SOURCES)
	@$(CC) $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)
#	aarch64-linux-gnu-gcc $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)

clean:
	rm -f *.o $(TARGET_APP)
