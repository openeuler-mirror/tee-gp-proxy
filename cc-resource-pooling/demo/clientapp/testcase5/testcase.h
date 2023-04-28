/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: multi_core_demo CA application header file
 */

#ifndef __MULTI_CORE_CA_H
#define __MULTI_CORE_CA_H

// #define TEST_CASE_TA_PATH         "/data/ebc87fc2-05dc-41b3-85b9-f9f0ef481bad.sec"

#define VALUE_A     55
#define VALUE_B     33
#define REE_TEMP_BUF    "hello tee"
#define TEE_TEMP_BUF    "hello ree"
#define TEMP_BUF_SIZE   20
#define THREAD_COUNT    3

#define TEST_TIME       10 * 6
#define EXPIRE_TIME     10 * 6 * 5

#define RSA_KEY_SIZE                256    // 2048bits
#define RSA_MASSAGE_SIZE            100   
#define RSA_INPUT_ERROR_PARAMETER   0x10000001
#define RSA_KEY_1                   1
#define RSA_ALG_PSS_SHA256          2      // use TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256 mode for sign

#define PARAMS_INDEX_2              2      // params参数的下标索引 2
#define PARAMS_INDEX_3              3      // params参数的下标索引 3
#define PRINTF_SIZE                 32

enum {
    CMD_NULL = 0,
    CMD_SHARE_MEM_FULL,
    CMD_SHARE_MEM_PATR,
    CMD_MUL_THREAD,
    CMD_SIGN_PSS_MGF1_SHA256,
};

#endif
