/*
 * tlogger.h
 *
 * TEE Logging Subsystem, read the tee os log from rdr memory
 */
#ifndef TLOGGER_H
#define TLOGGER_H

#include <linux/miscdevice.h>
#include <linux/types.h>
#include "tc_ns_client.h"

#define OPEN_FILE_MODE          0640U
#define ROOT_UID                0
#define ROOT_GID                0
#define SYSTEM_GID              1000
#ifdef LAST_TEE_MSG_ROOT_GID
#define FILE_CHOWN_GID                0
#else
/* system gid for last_teemsg file sys chown */
#define FILE_CHOWN_GID                1000
#endif

#define UINT64_MAX (uint64_t)(~((uint64_t)0)) /* 0xFFFFFFFFFFFFFFFF */

/* for log item ----------------------------------- */
#define LOG_ITEM_MAGIC          0x5A5A
#define LOG_ITEM_LEN_ALIGN      64
#define LOG_ITEM_MAX_LEN        1024
#define LOG_READ_STATUS_ERROR   0x000FFFF

/* =================================================== */
#define LOGGER_LOG_TEEOS        "teelog" /* tee os log */
#define LOGGERIOCTL             0xBE /* for ioctl */

#define DUMP_START_MAGIC "Dump SPI notification"
#define DUMP_END_MAGIC "Dump task states END"

#define GET_VERSION_BASE       5
#define SET_READERPOS_CUR_BASE 6
#define SET_TLOGCAT_STAT_BASE  7
#define GET_TLOGCAT_STAT_BASE  8
#define GET_TEE_INFO_BASE      9

/* get tee verison */
#define MAX_TEE_VERSION_LEN     256
#define TEELOGGER_GET_VERSION \
	_IOR(LOGGERIOCTL, GET_VERSION_BASE, char[MAX_TEE_VERSION_LEN])
/* set the log reader pos to current pos */
#define TEELOGGER_SET_READERPOS_CUR \
	_IO(LOGGERIOCTL, SET_READERPOS_CUR_BASE)
#define TEELOGGER_SET_TLOGCAT_STAT \
	_IO(LOGGERIOCTL, SET_TLOGCAT_STAT_BASE)
#define TEELOGGER_GET_TLOGCAT_STAT \
	_IO(LOGGERIOCTL, GET_TLOGCAT_STAT_BASE)
#define TEELOGGER_GET_TEE_INFO \
	_IOR(LOGGERIOCTL, GET_TEE_INFO_BASE, struct tc_ns_tee_info)

#define NEVER_USED_LEN 28U
#define LOG_ITEM_RESERVED_LEN 1U

/* 64 byte head + user log */
struct log_item {
	unsigned char never_used[NEVER_USED_LEN];
	unsigned int nsid;
	unsigned short magic;
	unsigned short reserved0;
	uint32_t serial_no;
	unsigned short real_len; /* log real len */
	unsigned short buffer_len; /* log buffer's len, multiple of 32 bytes */
	unsigned char uuid[UUID_LEN];
	unsigned char log_source_type;
	unsigned char reserved[LOG_ITEM_RESERVED_LEN];
	unsigned char log_level;
	unsigned char new_line; /* '\n' char, easy viewing log in bbox.bin file */
	unsigned char log_buffer[];
};

/* --- for log mem --------------------------------- */
#define TEMP_LOG_MEM_SIZE          (64 * SZ_1K)

#define LOG_BUFFER_RESERVED_LEN    11U
#define VERSION_INFO_LEN           256U

#define LOG_BUFFER_LEN                2000

/*
 * Log's buffer flag info, size: 64 bytes head + 156 bytes's version info.
 * For filed description:
 * last_pos : current log's end position, last log's start position.
 * write_loops: Write cyclically. Init value is 0, when memory is used
 *              up, the value add 1.
 */
struct log_buffer_flag {
	uint32_t reserved0;
	uint32_t last_pos;
	uint32_t write_loops;
	uint32_t log_level;
	/* [0] is magic failed, [1] is serial_no failed, used fior log retention feature */
	uint32_t reserved[LOG_BUFFER_RESERVED_LEN];
	uint32_t max_len;
	unsigned char version_info[VERSION_INFO_LEN];
};

struct log_buffer {
	struct log_buffer_flag flag;
	unsigned char buffer_start[];
};

struct tlogger_log {
	unsigned char *buffer_info; /* ring buffer info */
	struct mutex mutex_info; /* this mutex protects buffer_info */
	struct list_head logs; /* log channels list */
	struct mutex mutex_log_chnl; /* this mutex protects log channels */
	struct miscdevice misc_device; /* misc device log */
	struct list_head readers; /* log's readers */
};

struct tlogger_group {
	struct list_head node;
	uint32_t nsid;
	volatile uint32_t reader_cnt;
	volatile uint32_t tlogf_stat;
};

struct tlogger_reader {
	struct tlogger_log *log; /* tlogger_log info data */
	struct tlogger_group *group; /* tlogger_group info data */
	struct pid *pid; /* current process pid */
	struct list_head list; /* log entry in tlogger_log's list */
	wait_queue_head_t wait_queue_head; /* wait queue head for reader */
	/* Current reading position, start position of next read again */
	uint32_t r_off;
	uint32_t r_loops;
	uint32_t r_sn;
	uint32_t r_failtimes;
	uint32_t r_from_cur;
	uint32_t r_is_tlogf;
	bool r_all; /* whether this reader can read all entries */
	uint32_t r_ver;
	int32_t ptzfd;
};

typedef struct {
	uint32_t packet_size;
	uint32_t cmd;
	uint32_t seq_num;
	int32_t ptzfd;
} struct_packet_cmd_get_ver;

typedef struct {
	uint32_t packet_size;
	uint32_t seq_num;
	uint32_t ret;
	unsigned char version_info[VERSION_INFO_LEN];
} struct_packet_rsp_get_ver;

typedef struct {
	uint32_t packet_size;
	uint32_t cmd;
	uint32_t seq_num;
	int32_t ptzfd;
} struct_packet_cmd_set_reader_cur;

typedef struct {
	uint32_t packet_size;
	uint32_t seq_num;
	uint32_t ret;
} struct_packet_rsp_set_reader_cur;

typedef struct {
	uint32_t packet_size;
	uint32_t cmd;
	uint32_t seq_num;
	int32_t ptzfd;
} struct_packet_cmd_set_tlogcat_stat;

typedef struct {
	uint32_t packet_size;
	uint32_t seq_num;
	uint32_t ret;
} struct_packet_rsp_set_tlogcat_stat;

typedef struct {
	uint32_t packet_size;
	uint32_t cmd;
	uint32_t seq_num;
	int32_t ptzfd;
} struct_packet_cmd_get_tlogcat_stat;

typedef struct {
	uint32_t packet_size;
	uint32_t seq_num;
	uint32_t ret;
} struct_packet_rsp_get_tlogcat_stat;

typedef struct {
	uint32_t packet_size;
	uint32_t cmd;
	uint32_t seq_num;
	int32_t ptzfd;
} struct_packet_cmd_get_log;

typedef struct {
	uint32_t packet_size;
	uint32_t seq_num;
	uint32_t ret;
	int length;
	char buffer[];
} struct_packet_rsp_get_log;

int tlogger_init(void);
void tlogger_exit(void);
#endif





