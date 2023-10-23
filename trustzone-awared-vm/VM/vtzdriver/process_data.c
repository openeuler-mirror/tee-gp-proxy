#include <linux/types.h>
#include <securec.h>
#include "serialport.h"
#include "process_data.h"
#include "comm_structs.h"
#include "tlogger.h"

/*
void *malloc_copy(void *buf, int buf_len , int size, int *poffset)
{
	void *res;
	int offset = *poffset;
	if (buf_len < offset + size || size < 4) {
		memmove_s(buf, buf_len, buf + offset, buf_len - offset);
		*poffset = buf_len - offset;
		return NULL;
	}
	res = kzalloc(size, GFP_KERNEL);
	if (!res) {
		tloge("failed malloc\n");
		return NULL;
	}
	if (memcpy_s(res, size, buf + offset, size)) {
		tloge("memcpy err\n");
	}
	*poffset = offset + size;
	return res;
}
*/

void *malloc_copy(void *buf, int buf_len , int size, int *poffset)
{
	void *res;
	int offset = *poffset;
	if (buf_len < offset + size || size < 4) {
		memmove_s(buf, buf_len, buf + offset, buf_len - offset);
		*poffset = buf_len - offset;
		return NULL;
	}
	*poffset = offset + size;
	res = buf + offset;
	return res;
}

void *get_packet_item(void *buf, int buf_len, int *poffset, int *packet_sizep)
{
	uint32_t packet_size = 0;
	void *res = NULL;

	if (buf_len == *poffset) {
		*poffset = 0;
		return NULL;
	}
	if (buf_len < *poffset + 4) {
		return malloc_copy(buf, buf_len, buf_len - *poffset, poffset);
	}
	packet_size = *(uint32_t*)(buf + *poffset);
	if (packet_size > SERIAL_PORT_BUF_LEN) {
		tloge("packet_size err, size = %u\n", packet_size);
	}

	res = malloc_copy(buf, buf_len, packet_size, poffset);
	*packet_sizep = packet_size;
	return res; 
}



