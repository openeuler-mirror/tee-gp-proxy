#ifndef TEE_INFO_H
#define TEE_INFO_H

#include <linux/types.h>

int tc_ns_get_tee_info(int ptzfd, void __user *argp, bool flag);

#endif