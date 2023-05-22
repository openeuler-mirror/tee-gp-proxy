/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: multi_core_demo
 */

#include "testcase.h"
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <sys/sysinfo.h>
// #include <openssl/bn.h>
// #include <openssl/rsa.h>
// #include <openssl/evp.h>
// #include <openssl/sha.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// #include "tee_client_api.h"
#include "teecc/teec_client_api.h"
#include "dbusc_jwt.h"

#define TESTCASE 1

#if TESTCASE == 2
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530002.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x02}
};
#elif TESTCASE == 3
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530003.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x03}
};
#elif TESTCASE == 4
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530004.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x04}
};
#elif TESTCASE == 5
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530005.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x05}
};
#elif TESTCASE == 6
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530006.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x06}
};
#elif TESTCASE == 7
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530007.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x07}
};
#elif TESTCASE == 8
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530008.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x08}
};
#elif TESTCASE == 9
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530009.sec"
static const TEEC_UUID TEST_CASE_UUID = {
    0xb8ff9049, 0x9cbb, 0x46b0,
    {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x09}
};
#else
#define TEST_CASE_TA_PATH "/data/testcase/b8ff9049-9cbb-46b0-bcae-7aaa02530001.sec"
static const TEEC_UUID TEST_CASE_UUID = {
      0xb8ff9049, 0x9cbb, 0x46b0,
      {0xbc, 0xae, 0x7a, 0xaa, 0x02, 0x53, 0x00, 0x01}
};
#endif

static void DumpBuff(const char *buffer, size_t bufLen)
{
   size_t i;
   if (buffer == NULL || bufLen == 0)
   {
      return;
   }

   printf("\n--------------------------------------------------\n");
   printf("bufLen = %d\n", bufLen);
   for (i = 0; i < bufLen; i++)
   {
      if (i % PRINTF_SIZE == 0)
      {
         printf("\n");
      }
      printf("%02x ", *(buffer + i));
   }
   printf("\n--------------------------------------------------\n");
   return;
}

static TEEC_Result testcase_1()
{
   TEEC_Context context;
   // uint64_t context_addr;
   TEEC_Session session;
   TEEC_Operation operation;
   uint32_t origin;
   TEEC_Result ret;

   //Interface_Function-001
   ret = TEEC_InitializeContext(NULL, &context);
   assert(!ret);
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   //Interface_Function-002
   operation.started = 1;
   memset(&operation.paramTypes, 0, sizeof(operation.paramTypes));
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(!ret);

   //Interface_Function-003 -- no param
   operation.started = 1;
   memset(&operation.paramTypes, 0, sizeof(operation.paramTypes));
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);

   //Interface_Function-003 -- value param
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].value.a = 55;
   operation.params[0].value.b = 33;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);
   assert(operation.params[0].value.a == VALUE_A);
   assert(operation.params[0].value.b == VALUE_B);

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].value.a = 55;
   operation.params[0].value.b = 33;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);
   assert(operation.params[0].value.a == VALUE_B);
   assert(operation.params[0].value.b == VALUE_A);

   // Interface_Function-003 -- temp buf param
   char tmpbuf[TEMP_BUF_SIZE] = REE_TEMP_BUF;
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].tmpref.buffer = tmpbuf;
   operation.params[0].tmpref.size = TEMP_BUF_SIZE;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].tmpref.buffer = tmpbuf;
   operation.params[0].tmpref.size = TEMP_BUF_SIZE;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);
   assert(!strcmp(tmpbuf, TEE_TEMP_BUF));

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].tmpref.buffer = tmpbuf;
   operation.params[0].tmpref.size = TEMP_BUF_SIZE;
   memset(tmpbuf, 0, TEMP_BUF_SIZE);
   memcpy(tmpbuf, REE_TEMP_BUF, strlen(REE_TEMP_BUF));
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(!ret);
   assert(!strcmp(tmpbuf, TEE_TEMP_BUF));

   //Interface_Function-004
   TEEC_CloseSession(&session);
   //Interface_Function-005
   TEEC_FinalizeContext(&context);
   if (!ret)
   {
      printf("interface_testcase pass\n");
   }
   return ret;
}

static void share_mem_test(
      TEEC_Session *session,
      TEEC_SharedMemory *sharebuf
)
{
   TEEC_Result ret;
   TEEC_Operation operation;
   uint32_t origin;

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].memref.parent = sharebuf;
   memset(sharebuf->buffer, 0, sharebuf->size);
   memcpy(sharebuf->buffer, REE_TEMP_BUF, strlen(REE_TEMP_BUF));
   ret = TEEC_InvokeCommand(session, CMD_SHARE_MEM_FULL, &operation, &origin);
   assert(!ret);
   assert(!strcmp(sharebuf->buffer, TEE_TEMP_BUF));

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].memref.parent = sharebuf;
   operation.params[0].memref.offset = 1;
   operation.params[0].memref.size = TEMP_BUF_SIZE - 1;
   memset(sharebuf->buffer, 0, sharebuf->size);
   memcpy(sharebuf->buffer + 1, REE_TEMP_BUF, strlen(REE_TEMP_BUF));
   ret = TEEC_InvokeCommand(session, CMD_SHARE_MEM_PATR, &operation, &origin);
   assert(!ret);

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].memref.parent = sharebuf;
   operation.params[0].memref.offset = 1;
   operation.params[0].memref.size = TEMP_BUF_SIZE - 1;
   ret = TEEC_InvokeCommand(session, CMD_SHARE_MEM_PATR, &operation, &origin);
   assert(!ret);
   assert(!strcmp(sharebuf->buffer + 1, TEE_TEMP_BUF));

   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].memref.parent = sharebuf;
   operation.params[0].memref.offset = 1;
   operation.params[0].memref.size = TEMP_BUF_SIZE - 1;
   memset(sharebuf->buffer, 0, sharebuf->size);
   memcpy(sharebuf->buffer + 1, REE_TEMP_BUF, strlen(REE_TEMP_BUF));
   ret = TEEC_InvokeCommand(session, CMD_SHARE_MEM_PATR, &operation, &origin);
   assert(!ret);
   assert(!strcmp(sharebuf->buffer + 1, TEE_TEMP_BUF));
}

static TEEC_Result testcase_2()
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation;
   TEEC_SharedMemory sharebuf;
   char tmpbuf[TEMP_BUF_SIZE];
   uint32_t origin;
   TEEC_Result ret;

   ret = TEEC_InitializeContext(NULL, &context);
   assert(!ret);
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   operation.started = 1;
   memset(&operation.paramTypes, 0, sizeof(operation.paramTypes));
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(!ret);

   // Interface_Function-006
   sharebuf.size = TEMP_BUF_SIZE;
   sharebuf.flags = TEEC_MEM_INOUT;
   ret = TEEC_AllocateSharedMemory(&context, &sharebuf);
   assert(!ret);

   // Interface_Function-011
   share_mem_test(&session, &sharebuf);

   // Interface_Function-008
   TEEC_ReleaseSharedMemory(&sharebuf);

   // Interface_Function-007
   memset(&sharebuf, 0, sizeof(sharebuf));
   sharebuf.buffer = tmpbuf;
   sharebuf.size = TEMP_BUF_SIZE;
   sharebuf.flags = TEEC_MEM_INOUT;
   ret = TEEC_RegisterSharedMemory(&context, &sharebuf);
   assert(!ret);

   // Interface_Function-012
   share_mem_test(&session, &sharebuf);

   TEEC_ReleaseSharedMemory(&sharebuf);

// exit:
   TEEC_CloseSession(&session);
   TEEC_FinalizeContext(&context);

   if (!ret)
   {
      printf("sharemem_interface_testcase pass\n");
   }
   return ret;
}


static void *thread_function(void *param)
{
   TEEC_Result ret = TEEC_SUCCESS;
   TEEC_Session session;
   TEEC_Operation operation;
   TEEC_SharedMemory sharebuf;
   TEEC_Context *context = (TEEC_Context *) param;
   pthread_t tid;
   uint32_t origin;
   struct timeval start, end, tokenset;

   tid = (pthread_t) pthread_self();

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   memset(&operation.paramTypes, 0, sizeof(operation.paramTypes));
   ret = TEEC_OpenSession(context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   if (ret)
   {
      printf("thread %u open session failed, ret=%x\n", tid, ret);
      goto exit;
   }

   sharebuf.size = TEMP_BUF_SIZE;
   sharebuf.flags = TEEC_MEM_INOUT;
   ret = TEEC_AllocateSharedMemory(context, &sharebuf);
   if (ret)
   {
      printf("thread %u share buffer alloc failed, ret=%x\n", tid, ret);
      goto exit;
   }

   printf("begin multi-thread test, during %u\n", TEST_TIME);
   gettimeofday(&start, NULL);
   gettimeofday(&tokenset, NULL);
   while (1)
   {
      memset(&operation, 0, sizeof(operation));
      operation.started = 1;
      operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
      memset(sharebuf.buffer, 0, sharebuf.size);
      memcpy(sharebuf.buffer, REE_TEMP_BUF, strlen(REE_TEMP_BUF));
      operation.params[0].memref.parent = &sharebuf;
      operation.params[1].value.a = 1;

      ret = TEEC_InvokeCommand(&session, CMD_MUL_THREAD, &operation, &origin);
      if (ret)
      {
         printf("thread %u invoke failed, ret=%x, origin=%u\n", tid, ret, origin);
         break;
      }

      if (strcmp(sharebuf.buffer, TEE_TEMP_BUF) || operation.params[1].value.a || operation.params[1].value.b != 1)
      {
         printf("thread %u get wrong comptue result.\n", tid);
         break;
      }
      gettimeofday(&end, NULL);
      if (end.tv_sec - start.tv_sec > TEST_TIME)
         break;

      if (end.tv_sec - tokenset.tv_sec > EXPIRE_TIME)
      {
         char token[1024];
         int iret;
         iret =
               dbusmethodcall_fetch_jwt(
                     token
               );
         if (iret != 0)
         {
            printf("Token fetching failed. \n");
            break;
         }
         printf("The fetched token: %s \n", token);

         ret =
               TEEC_SetJwt(
                     token
               );
         if (ret != TEEC_SUCCESS)
         {
            printf("Token set failed. \n");
            break;
         }
         printf("Token set succed. \n");
         gettimeofday(&tokenset, NULL);
      }

      sleep(1);
   }

   TEEC_CloseSession(&session);
   exit:
   return (void *) ret;
}

static TEEC_Result testcase_3()
{
   TEEC_Result ret;
   TEEC_Operation operation;
   TEEC_Context context;
   pthread_t tid[THREAD_COUNT];
   void *thread_ret = NULL;
   uint32_t i;

   ret = TEEC_InitializeContext(NULL, &context);
   assert(!ret);
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   for (i = 0; i < THREAD_COUNT; i++)
   {
      pthread_create(&tid[i], NULL, thread_function, (void *) &context);
   }

   for (i = 0; i < THREAD_COUNT; i++)
   {
      pthread_join(tid[i], &thread_ret);
      if ((TEEC_Result) thread_ret != TEEC_SUCCESS)
      {
         printf("thread %u return fail, ret=%x\n", tid[i], (TEEC_Result) thread_ret);
         ret = TEEC_FAIL;
      }
   }

   exit:
   TEEC_FinalizeContext(&context);
   if (!ret)
   {
      printf("multi_thread_testcase pass\n");
   }
   return ret;
}


// Exception Test
static TEEC_Result testcase_4()
{
#define TEEC_ERROR_NO_WORKER_MATCHED 0xAAAA0017
   TEEC_Result ret = TEEC_SUCCESS;
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation;
   TEEC_SharedMemory sharemem;
   uint32_t origin;

   // Interface_Exception_001ll
   ret = TEEC_InitializeContext(NULL, NULL);
   assert(ret == TEEC_ERROR_BAD_PARAMETERS);

   ret = TEEC_InitializeContext(NULL, &context);
   assert(!ret);

   // Interface_Exception_002
   ret = TEEC_OpenSession(NULL,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(ret == TEEC_ERROR_BAD_PARAMETERS);

   ret = TEEC_OpenSession(&context,
                          NULL, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(ret == TEEC_ERROR_BAD_PARAMETERS);

   ret = TEEC_OpenSession(&context,
                          &session, NULL, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(ret == TEEC_ERROR_BAD_PARAMETERS);

   context.ta_path = (uint8_t *) "/data/not_found.sec";
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   // assert(ret == TEEC_ERROR_TRUSTED_APP_LOAD_ERROR);
   // assert(ret == TEEC_ERROR_NOT_IMPLEMENTED);
   printf("OpenSession tapath not_found.sec case, ret = 0x %16.16lx. \n", ret);
   assert(ret);

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(!ret);

   // Interface_Exception_003
   ret = TEEC_InvokeCommand(NULL, CMD_NULL, &operation, &origin);
   assert(ret == TEEC_ERROR_BAD_PARAMETERS);

   session.session_id++;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   // assert(ret == TEEC_ERROR_ACCESS_DENIED);
   assert(ret == TEEC_ERROR_NO_WORKER_MATCHED);

   session.session_id--;
   operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
   operation.params[0].memref.parent = &sharemem;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
   assert(ret);

   ret = TEEC_InvokeCommand(&session, CMD_NULL, NULL, NULL);
   assert(ret == TEEC_ERROR_BAD_PARAMETERS);

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, NULL);
   assert(!ret);

   // Interface_Exception_004
   TEEC_CloseSession(NULL);

   // Interface_Exception_005
   TEEC_FinalizeContext(NULL);

   TEEC_CloseSession(&session);
   TEEC_FinalizeContext(&context);

   if (!ret)
   {
      printf("exception_testcase pass\n");
   }
   return ret;
}

static TEEC_Result testcase_5()
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation;
   TEEC_Result ret;
   uint32_t origin;

   ret = TEEC_InitializeContext(NULL, &context);
   assert(!ret);
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   assert(!ret);

   // CA_KILL_Test_001
   printf("CA Killed Test begin!, process exit!\n");
   exit(0);

   TEEC_CloseSession(&session);
   TEEC_FinalizeContext(&context);
   return ret;
}

static TEEC_Result testcase_6()
{
   TEEC_Context context;
   struct timeval start, end, tokenset;
   uint32_t cost = 0;
   uint32_t i;
   TEEC_Result ret;
   uint32_t count = 1000;

   gettimeofday(&tokenset, NULL);
   for (i = 0; i < count; i++)
   {
      gettimeofday(&start, NULL);
      ret = TEEC_InitializeContext(NULL, &context);
      gettimeofday(&end, NULL);
      if (ret)
      {
         break;
      }
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
      TEEC_FinalizeContext(&context);

      if (end.tv_sec - tokenset.tv_sec > EXPIRE_TIME)
      {
         char token[1024];
         int iret;
         iret =
               dbusmethodcall_fetch_jwt(
                     token
               );
         if (iret != 0)
         {
            printf("Token fetching failed. \n");
            break;
         }
         printf("The fetched token: %s \n", token);

         ret =
               TEEC_SetJwt(
                     token
               );
         if (ret != TEEC_SUCCESS)
         {
            printf("Token set failed. \n");
            break;
         }
         printf("Token set succed. \n");
         gettimeofday(&tokenset, NULL);
      }
   }

   if (!ret)
   {
      printf("TEEC_InitializeContext cost: %f us\n", cost * 1.0 / count);
   }
   return ret;
}

static TEEC_Result testcase_7()
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation;
   struct timeval start, end, tokenset;
   uint32_t cost = 0;
   uint32_t i;
   TEEC_Result ret;
   uint32_t count = 1000;
   uint32_t origin;

   ret = TEEC_InitializeContext(NULL, &context);
   if (ret)
   {
      printf("initail conatext failed\n");
      return ret;
   }
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   gettimeofday(&tokenset, NULL);
   for (i = 0; i < count; i++)
   {
      memset(&operation, 0, sizeof(operation));
      operation.started = 1;
      gettimeofday(&start, NULL);
      ret = TEEC_OpenSession(&context,
                             &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
      gettimeofday(&end, NULL);
      if (ret)
      {
         break;
      }
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
      TEEC_CloseSession(&session);

      if (end.tv_sec - tokenset.tv_sec > EXPIRE_TIME)
      {
         char token[1024];
         int iret;
         iret =
               dbusmethodcall_fetch_jwt(
                     token
               );
         if (iret != 0)
         {
            printf("Token fetching failed. \n");
            break;
         }
         printf("The fetched token: %s \n", token);

         ret =
               TEEC_SetJwt(
                     token
               );
         if (ret != TEEC_SUCCESS)
         {
            printf("Token set failed. \n");
            break;
         }
         printf("Token set succed. \n");
         gettimeofday(&tokenset, NULL);
      }
   }

   if (!ret)
   {
      printf("TEEC_OpenSession cost: %f us\n", cost * 1.0 / count);
   }
   TEEC_FinalizeContext(&context);
   return ret;
}

static TEEC_Result testcase_8(void)
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation;
   struct timeval start, end, tokenset;
   uint32_t cost = 0;
   uint32_t i;
   TEEC_Result ret;
   uint32_t count = 1000;
   uint32_t origin;

   ret = TEEC_InitializeContext(NULL, &context);
   if (ret)
   {
      printf("initail conatext failed\n");
      return ret;
   }
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   if (ret)
   {
      printf("opensession failed!, ret=%x, origin=%u\n", ret, origin);
      TEEC_FinalizeContext(&context);
      return ret;
   }

   gettimeofday(&tokenset, NULL);
   for (i = 0; i < count; i++)
   {
      operation.started = 1;
      memset(&operation.paramTypes, 0, sizeof(operation.paramTypes));
      gettimeofday(&start, NULL);
      ret = TEEC_InvokeCommand(&session, CMD_NULL, &operation, &origin);
      gettimeofday(&end, NULL);
      if (ret)
      {
         break;
      }
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);

      if (end.tv_sec - tokenset.tv_sec > EXPIRE_TIME)
      {
         char token[1024];
         int iret;
         iret =
               dbusmethodcall_fetch_jwt(
                     token
               );
         if (iret != 0)
         {
            printf("Token fetching failed. \n");
            break;
         }
         printf("The fetched token: %s \n", token);

         ret =
               TEEC_SetJwt(
                     token
               );
         if (ret != TEEC_SUCCESS)
         {
            printf("Token set failed. \n");
            break;
         }
         printf("Token set succed. \n");
         gettimeofday(&tokenset, NULL);
      }
   }

   if (!ret)
   {
      printf("TEEC_InvokeCommand cost: %f us\n", cost * 1.0 / count);
   }
   TEEC_CloseSession(&session);
   TEEC_FinalizeContext(&context);
   return ret;
}

static TEEC_Result RsaSignCmd(char *msgBuf, uint32_t msgLen, char *signBuf, uint32_t *bufLen,
                              TEEC_Session *session)
{
   TEEC_Operation operation;
   TEEC_Result result;
   uint32_t origin;

   if (msgBuf == NULL || signBuf == NULL || (bufLen == NULL))
   {
      TEEC_Error("invoke RsaSignCmd has wrong params.");
      return (TEEC_Result) RSA_INPUT_ERROR_PARAMETER;
   }

   operation.started = 1;
   operation.paramTypes = TEEC_PARAM_TYPES(
         TEEC_VALUE_INPUT,
         TEEC_NONE,
         TEEC_MEMREF_TEMP_INPUT,
         TEEC_MEMREF_TEMP_OUTPUT);

   operation.params[0].value.a = RSA_KEY_1;
   operation.params[0].value.b = RSA_ALG_PSS_SHA256;
   operation.params[PARAMS_INDEX_2].tmpref.buffer = msgBuf;
   operation.params[PARAMS_INDEX_2].tmpref.size = msgLen;
   operation.params[PARAMS_INDEX_3].tmpref.buffer = signBuf;
   operation.params[PARAMS_INDEX_3].tmpref.size = *bufLen;

   result = TEEC_InvokeCommand(session, CMD_SIGN_PSS_MGF1_SHA256, &operation, &origin);
   if (result != TEEC_SUCCESS)
   {
      TEEC_Error("invoke RsaSignCmd failed, codes=0x%x, origin=0x%x.", result, origin);
   } else if (operation.params[PARAMS_INDEX_3].tmpref.size != RSA_KEY_SIZE)
   {
      TEEC_Error("invoke RsaSignCmd failed, returned Encrypted data size is %d.",
                 operation.params[PARAMS_INDEX_3].tmpref.size);
   } else
   {
      printf("signBuf is : \n");
      DumpBuff(signBuf, operation.params[PARAMS_INDEX_3].tmpref.size);
      *bufLen = operation.params[PARAMS_INDEX_3].tmpref.size;
   }

   return result;
}

static TEEC_Result testcase_9(void)
{
   TEEC_Context context;
   TEEC_Session session;
   TEEC_Operation operation;
   TEEC_Result ret;
   uint32_t origin;
   char msgBuf[RSA_KEY_SIZE] = {0};
   char signature[RSA_KEY_SIZE] = {0};
   uint32_t bufLen = RSA_KEY_SIZE;

   ret = TEEC_InitializeContext(NULL, &context);
   if (ret)
   {
      printf("initail conatext failed\n");
      return ret;
   }
   context.ta_path = (uint8_t *) TEST_CASE_TA_PATH;

   memset(&operation, 0, sizeof(operation));
   operation.started = 1;
   ret = TEEC_OpenSession(&context,
                          &session, &TEST_CASE_UUID, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
   if (ret)
   {
      printf("opensession failed!, ret=%x, origin=%u\n", ret, origin);
      TEEC_FinalizeContext(&context);
      return ret;
   }

   ret = RsaSignCmd(msgBuf, RSA_MASSAGE_SIZE, signature, &bufLen, &session);
   printf("TEE RSA Sign %s.\n", ret ? "failed" : "success");

   TEEC_CloseSession(&session);
   TEEC_FinalizeContext(&context);
   return ret;
}

static TEEC_Result testcase_10(void)
{

   TEEC_Result ret;
   char infile_path[1024];
   char *subdir = "testcase";
   memset(infile_path, 0, sizeof(infile_path));
   //basic_function
   sprintf(infile_path,
           "/home/john/projects/tzc02/09/demo/ta/itrustee_sdk/output/testcase/testcase%d/b8ff9049-9cbb-46b0-bcae-7aaa0253000%d.sec",
           TESTCASE, TESTCASE);
   ret = TEEC_DeployTa(infile_path, subdir, NULL);
   if (ret != TEEC_SUCCESS)
   {
      printf("Deploy ta（size <= 1M）  failed. \n");
      return ret;
   } else
   {
      printf("Deploy ta（size <= 1M）  succed. \n");
   }
   //8M_TA_TEST
   sprintf(infile_path, "/home/john/projects/tzc02/09/demo/ta/itrustee_sdk/output/testcase/testcase1/8M_TA_TEST.sec");
   ret = TEEC_DeployTa(infile_path, subdir, NULL);
   if (ret != TEEC_SUCCESS)
   {
      printf("Deploy ta（size = 8M） failed. \n", TESTCASE);
      return ret;
   } else
   {
      printf("Deploy ta（size = 8M） succed. \n", TESTCASE);
   }

   //TA_NOT_FOUND
   sprintf(infile_path, "/home/john/projects/tzc02/09/demo/ta/itrustee_sdk/output/testcase/testcase1/not_found.sec");
   ret = TEEC_DeployTa(infile_path, subdir, NULL);
   if (ret == TEEC_INFILE_NOT_FOUND)
   {
      printf("Deploy ta not found test success\n");
   } else
   {
      printf("Deploy TA not found test failed \n");
      return ret;
   }

   //outfile_path_not_exist
   subdir = "not_exist_path";
   sprintf(infile_path,
           "/home/john/projects/tzc02/09/demo/ta/itrustee_sdk/output/testcase/testcase%d/b8ff9049-9cbb-46b0-bcae-7aaa0253000%d.sec",
           TESTCASE, TESTCASE);
   ret = TEEC_DeployTa(infile_path, subdir, NULL);
   if (ret != TEEC_SUCCESS)
   {
      printf("Deploy ta outfile_path_not_exist failed. \n");
      return ret;
   } else
   {
      printf("Deploy ta outfile_path_not_exist succed. \n");
   }

   return ret;
}

void help_print(void)
{
   printf("Usage: \n \
    1.function_interface_testcase\n \
    2.sharemem_interface_testcase\n \
    3.multi_thread_testcase\n \
    4.exception_testcase\n \
    5.client_killed_testcase\n \
    6.TEEC_InitializeContext perform-test\n \
    7.TEEC_OpenSession perform-test\n \
    8.TEEC_InvokeCommand perform-test\n \
    9.RSA Sign test\n");
}

int main(int argc, char **argv)
{
   TEEC_Result ret;
   struct timeval start, end;
   gettimeofday(&start, NULL);
   int choice = -1;

   if (argc == 1 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help"))
   {
      help_print();
      return 1;
   }

#if 0
   char token[1024];
   int iret;
   iret =
      dbusmethodcall_fetch_jwt(
         token
      );
   if (iret != 0)
   {
      printf("Token fetching failed. \n");
      return 0;
   }
   printf("The fetched token: %s \n", token);

   ret =
      TEEC_SetJwt(
         token
      );
   if (ret != TEEC_SUCCESS)
   {
      printf("Token set failed. \n");
      return 0;
   }
   printf("Token set succed. \n");
#endif

#if 1
   ret =
         TEEC_UnsetJwt(
         );
   if (ret != TEEC_SUCCESS)
   {
      printf("Token unset failed. \n");
      return 0;
   }
   printf("Token unset succed. \n");
#endif

   char infile_path[1024];
   char *subdir = "testcase";
   memset(infile_path, 0, sizeof(infile_path));
   sprintf(infile_path,
           "/home/john/projects/tzc02/09/demo/ta/itrustee_sdk/output/testcase/testcase%d/b8ff9049-9cbb-46b0-bcae-7aaa0253000%d.sec",
           TESTCASE, TESTCASE);
   ret = TEEC_DeployTa(infile_path, subdir, NULL);
   if (ret != TEEC_SUCCESS)
   {
      printf("Deploy ta %d failed. \n", TESTCASE);
      return 0;
   } else
   {
      printf("Deploy ta %d succed. \n", TESTCASE);
   }

   /*
   for (int ita = 1; ita < 10; ita ++)
   {
      memset(infile_path, 0, sizeof(infile_path));
      sprintf(infile_path, "/home/john/projects/tzc02/09/demo/ta/itrustee_sdk/output/testcase/testcase%d/b8ff9049-9cbb-46b0-bcae-7aaa0253000%d.sec", ita, ita);
      ret = TEEC_DeployTa(infile_path, subdir, NULL);
      if (ret != TEEC_SUCCESS)
      {
         printf("Deploy ta %d failed. \n", ita);
         return 0;
      }
      else
      {
         printf("Deploy ta %d succed. \n", ita);
      }
   }
    */

   choice = atoi(argv[1]);

   switch (choice)
   {
      case 1:
         ret = testcase_1();
         break;
      case 2:
         ret = testcase_2();
         break;
      case 3:
         ret = testcase_3();
         break;
      case 4:
         ret = testcase_4();
         break;
      case 5:
         ret = testcase_5();
         break;
      case 6:
         ret = testcase_6();
         break;
      case 7:
         ret = testcase_7();
         break;
      case 8:
         ret = testcase_8();
         break;
      case 9:
         ret = testcase_9();
         break;
      case 10:
         ret = testcase_10();
         break;
      default:
         printf("Error: invalid choice!\n");
         help_print();
         ret = -1;
         break;
   }

   return ret;
}
