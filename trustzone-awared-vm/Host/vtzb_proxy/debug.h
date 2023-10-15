#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <sys/time.h>
#include <stdio.h>

//#define DEBUG 1

double __get_us(struct timeval t);
#ifdef DEBUG
void debug(const char* fmt, ...);
void dump_buff(const char* buffer, size_t bufLen);
#else
#define debug(fmt, ...) \
    do {                \
    } while (0)

#define dump_buff(buffer, bufLen) \
    do {                          \
    } while (0)
#endif

#endif
