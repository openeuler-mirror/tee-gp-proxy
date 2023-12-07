#include "debug.h"
#include <sys/time.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdarg.h>

double __get_us(struct timeval t)
{
    return (t.tv_sec * 1000000 + t.tv_usec);
}

#ifdef DEBUG
void debug(const char* fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

#define PRINTF_SIZE 16
void dump_buff(const char* buffer, size_t bufLen)
{
    size_t i;
    if (buffer == NULL || bufLen == 0) {
        return;
    }
    printf("--------------------------------------------------\n");
    printf("bufLen = %d\n", (int)bufLen);
    for (i = 0; i < bufLen; i++) {
        if (i % PRINTF_SIZE == 0 && i != 0) {
            printf("\n");
        }
        printf("%02x ", *(buffer + i));
    }
    printf("\n--------------------------------------------------\n");
    return;
}
#endif