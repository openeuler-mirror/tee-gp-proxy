CUR_DIR=$(shell pwd)

TARGET_APP := client

APP_SOURCES := ./client.c \
			   ./cJSON/cJSON.c \

APP_CFLAGS += -fstack-protector-strong

APP_CFLAGS += -I$(CUR_DIR)/./cJSON

APP_OBJECTS := $(APP_SOURCES:.c=.o)
$(TARGET_APP): $(APP_SOURCES)
	@$(CC) $(APP_CFLAGS) -o $@ $(APP_SOURCES) $(APP_LDFLAGS)

clean:
	rm -f *.o $(TARGET_APP)


