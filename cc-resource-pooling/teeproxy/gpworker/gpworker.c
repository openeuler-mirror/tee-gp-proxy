/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rsa-demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "tee_client_api.h"

#include "tzcp_dbus.h"
#include "threadpool.h"


int main(int argc, char *argv[])
{
   threadpool_t pool;
   pthread_mutex_t mutex_tcl;
   pthread_mutex_t mutex_tsl;
   tcl_t tcl;
   tsl_t tsl;

   if (argc < 2)
   {
      printf("There is no argument as a worker name. \n");
      return -1;
   }
   if (argc > 2)
   {
      printf("Only need one argument as a worker name. \n");
      return -1;
   }

   receive_methodcall(
         &pool,
         &mutex_tcl,
         &mutex_tsl,
         &tcl,
         &tsl,
         argv[1]
   );

   return 0;
}
