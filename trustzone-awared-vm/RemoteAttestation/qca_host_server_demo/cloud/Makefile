CUR_DIR=$(shell pwd)
iTrustee_SDK_PATH=${CUR_DIR}/../../../../

TARGET_APP := qca_host_server

APP_SOURCES := ../qca_host_server_demo.c \
			   ../cJSON/cJSON.c \

APP_SOURCES += $(iTrustee_SDK_PATH)/src/CA/cloud/libteec_adaptor.c

APP_CFLAGS += -fstack-protector-strong -fPIC

APP_CFLAGS += -I$(CUR_DIR)/../cJSON

APP_CFLAGS += -I$(iTrustee_SDK_PATH)/include/CA -I$(iTrustee_SDK_PATH)/thirdparty/open_source/libboundscheck/include

APP_CFLAGS += -DHOST_QCA

APP_LDFLAGS += -ldl -lpthread

APP_LDFLAGS += -L/usr/lib64 -lqca

APP_LDFLAGS += -z text -z now -z relro -z noexecstack -pie

APP_OBJECTS := $(APP_SOURCES:.c=.o)
$(TARGET_APP): $(APP_SOURCES)
	@$(CC) $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)

clean:
	rm -f *.o $(TARGET_APP)



