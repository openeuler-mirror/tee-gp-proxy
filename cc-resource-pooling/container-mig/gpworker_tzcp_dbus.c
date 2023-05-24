/*
 * Using low-level D-Bus C API code.
 * Written by 
 */

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>

#include "tzcp_dbus.h"

#ifdef GP_PROXY_WORKER

#include "threadpool.h"

#ifdef GP_WORKER

#include "tee_client_api.h"
#include "tee_client_list.h"

#endif
#endif

/**
 * Listens for signals on the bus
 */
void
receive_signal(void)
{
   DBusMessage *msg;
   DBusMessageIter args;
   DBusConnection *conn;
   DBusError err;
   int ret;
   char *sigvalue;

   printf("Listening for signals\n");

   // initialise the errors
   dbus_error_init(&err);

   // connect to the bus and check for errors
   conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Connection Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (NULL == conn)
   {
      exit(1);
   }

   // request our name on the bus and check for errors
   ret = dbus_bus_request_name(conn, "test.signal.sink", DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Name Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
   {
      exit(1);
   }

   // add a rule for which messages we want to see
   dbus_bus_add_match(conn, "type='signal',interface='test.signal.Type'", &err);
   // see signals from the given interface
   dbus_connection_flush(conn);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Match Error (%s)\n", err.message);
      exit(1);
   }
   // printf("Match rule sent\n");

   // loop listening for signals being emmitted
   while (true)
   {
      // non blocking read of the next available message
      dbus_connection_read_write(conn, 0);
      msg = dbus_connection_pop_message(conn);

      // loop again if we haven't read a message
      if (NULL == msg)
      {
         usleep(10000);
         continue;
      }

      // check if the message is a signal from the correct interface and with the correct name
      if (dbus_message_is_signal(msg, "test.signal.Type", "Test"))
      {

         // read the parameters
         if (!dbus_message_iter_init(msg, &args))
            fprintf(stderr, "Message Has No Parameters\n");
         else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
            fprintf(stderr, "Argument is not string!\n");
         else
            dbus_message_iter_get_basic(&args, &sigvalue);

         printf("Got Signal with value %s\n", sigvalue);
      }

      // free the message
      dbus_message_unref(msg);
   }
}


/**
 * Connect to the DBUS bus and send a broadcast signal
 */
void
send_signal(
      char *sigvalue
)
{
   DBusMessage *msg;
   DBusMessageIter args;
   DBusConnection *conn;
   DBusError err;
   int ret;
   dbus_uint32_t sigserial = 0;

   printf("Sending signal with value %s\n", sigvalue);

   // initialise the error value
   dbus_error_init(&err);

   // connect to the DBUS system bus, and check for errors
   conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Connection Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (NULL == conn)
   {
      exit(1);
   }

   // register our name on the bus, and check for errors
   ret = dbus_bus_request_name(conn, "test.signal.source", DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Name Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
   {
      exit(1);
   }

   // create a signal & check for errors
   msg = dbus_message_new_signal("/test/signal/Object", // object name of the signal
                                 "test.signal.Type", // interface name of the signal
                                 "Test"); // name of the signal
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      exit(1);
   }

   // append arguments onto signal
   dbus_message_iter_init_append(msg, &args);
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sigvalue))
   {
      fprintf(stderr, "Out Of Memory!\n");
      exit(1);
   }

   // send the message and flush the connection
   if (!dbus_connection_send(conn, msg, &sigserial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      exit(1);
   }
   dbus_connection_flush(conn);

   printf("Signal Sent\n");

   // free the message
   dbus_message_unref(msg);
}

int errno = -1;
int tcl_flag = 0;
uint32_t lt_session_id[128] = {0};
int32_t lt_fd[128] = {0};

// 将tcl_t写入文件
int store_context(tcl_t *tcl,TEEC_Context *context,tcn_t *tcnIns,int id,tsl_t *tsl) {
   char filename[20];
   sprintf(filename, "tcl_%d.bin", id);
   FILE *fp = fopen(filename, "wb");
   if (fp == NULL) {
      printf("Error opening file %s.\n", filename);
      return -1;
   }
   int ret = 0;
   ret = fwrite(&context->fd, sizeof(int32_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }
   printf("   context->fd                     = 0x %8.8x \n", context->fd);

   /* int32_t context_tapath_size = strlen((const char *)context->ta_path);
   ret = fwrite(&context_tapath_size, sizeof(int32_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }
   printf("   context->ta_path_size                     = %d \n", context_tapath_size);

   ret = fwrite(context->ta_path, context_tapath_size, 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }
   printf("   context->ta_path                     = %s \n", context->ta_path);

   printf("   session_list_prev           = 0x %16.16lx \n", context->session_list.prev);
   printf("   shrd_mem_list_next          = 0x %16.16lx \n", context->shrd_mem_list.next);
   printf("   shrd_mem_list_prev          = 0x %16.16lx \n", context->shrd_mem_list.prev);
   printf("   share_buffer_buffer         = 0x %16.16lx \n", context->share_buffer.buffer);
   printf("   share_buffer_buffer_barrier = 0x %16.16lx \n", context->share_buffer.buffer_barrier.__align);
   */

   ret = fwrite(&context->session_list, sizeof(struct ListNode), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   ret = fwrite(&context->shrd_mem_list, sizeof(struct ListNode), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   ret = fwrite(&context->share_buffer.buffer, sizeof(dbus_uint64_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   ret = fwrite(&context->share_buffer.buffer_barrier.__align, sizeof(dbus_int64_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   if(tsl->count == 0){
      printf("tcn clean  sessionid = 0x %8.8x  \n",id);
      tcn_t *lttcnTemp;
      lttcnTemp = tcnIns->prev;
      if (lttcnTemp != NULL)
      {
         lttcnTemp->next = tcnIns->next;
      }
      lttcnTemp = tcnIns->next;
      if (lttcnTemp != NULL)
      {
         lttcnTemp->prev = tcnIns->prev;
      }
      if (tcl->last == tcnIns)
      {
         tcl->last = tcnIns->prev;
      }
      if (tcl->first == tcnIns)
      {
         tcl->first = tcnIns->next;
      }
   }

/*   for(int i = 0; i < 128; i++)
   {
      if(lt_fd[i] == 0)
         lt_fd[i] = context->fd;
   }
   tcl->count = tcl->count - 1;*/

   fclose(fp);
   //printf("tzc %d\n",__LINE__);
   tcl_flag = 0;
   return 0;
}
// 读取tcl_t
int load_tcl(tcl_t *tcl,tcn_t *tcnIns,int id) {
   printf("load tcl start\n");
   char filename[20];
   sprintf(filename, "tcl_%d.bin", id);
   FILE *fp = fopen(filename, "rb");
   if (fp == NULL) {
      printf("Error opening file %s.\n", filename);
      return -1;
   }
   int ret = 0;

   ret = fread(&tcnIns->self->fd, sizeof(int32_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }
   printf("   context->fd                     = 0x %8.8x \n", tcnIns->self->fd);

/*   int32_t context_tapath_size;
   ret = fread(&context_tapath_size, sizeof(int32_t), 1, fp);
   printf("   context->ta_path_size                     = 0x %8.8x \n", context_tapath_size);

   ret = fread(&tcnIns->self->ta_path, context_tapath_size, 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }*/

   ret = fread(&tcnIns->self->session_list, sizeof(struct ListNode), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   ret = fread(&tcnIns->self->shrd_mem_list, sizeof(struct ListNode), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   ret = fread(&tcnIns->self->share_buffer.buffer, sizeof(dbus_uint64_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   ret = fread(&tcnIns->self->share_buffer.buffer_barrier.__align, sizeof(dbus_int64_t), 1, fp);
   if (ret != 1) {
      printf("Failed to write tcl_t count to file: %s\n", strerror(errno));
      return -1;
   }

   /*printf("   context->ta_path                     = %s \n", tcnIns->self->ta_path);
   printf("   session_list_prev           = 0x %16.16lx \n", tcnIns->self->session_list.prev);
   printf("   shrd_mem_list_next          = 0x %16.16lx \n", tcnIns->self->shrd_mem_list.next);
   printf("   shrd_mem_list_prev          = 0x %16.16lx \n", tcnIns->self->shrd_mem_list.prev);
   printf("   share_buffer_buffer         = 0x %16.16lx \n", tcnIns->self->share_buffer.buffer);
   printf("   share_buffer_buffer_barrier = 0x %16.16lx \n", tcnIns->self->share_buffer.buffer_barrier.__align);*/

   if (tcl->first == NULL)
   {
      tcnIns->next = NULL;
      tcnIns->prev = NULL;
      tcl->first = tcnIns;
      tcl->last = tcnIns;
      tcl->count = 1;
   } else
   {
      tcnIns->prev = tcl->last;
      tcnIns->next = NULL;
      tcl->last->next = tcnIns;
      tcl->last = tcnIns;
      tcl->count = tcl->count + 1;
   }

   struct timeval tvcreate;
   gettimeofday(&tvcreate, NULL);
   tcnIns->createtime = tvcreate;
   fclose(fp);
   tcl_flag = 1;
   if (remove(filename) != 0){
      printf("session %d remove_tcl error\n",id);
   }

   return 0;
}

// 将tsn写入文件
int store_tsl(tsl_t *tsl,tsn_t *tsnIns) {
     tsn_t *tsnTemp;
     tsnTemp = tsnIns->prev;
     if (tsnTemp != NULL)
     {
        tsnTemp->next = tsnIns->next;
     }
     tsnTemp = tsnIns->next;
     if (tsnTemp != NULL)
     {
        tsnTemp->prev = tsnIns->prev;
     }
     if (tsl->last == tsnIns)
     {
        tsl->last = tsnIns->prev;
     }
     if (tsl->first == tsnIns)
     {
        tsl->first = tsnIns->next;
     }
     tsl->count = tsl->count - 1;
     if(tsl->count == 0){
        tsl->first = NULL;
        tsl->last = NULL;
     }
     //free(sessionIns);
/*   for(int i = 0; i < 128; i++)
   {
      if(lt_session_id[i] == 0)
         lt_session_id[i] = tsnIns->self->session_id;
   }*/

   return 0;
}
// 读取tsl_t
int load_tsl(tsl_t *tsl,tsn_t *tsnIns,tcn_t *tcnIns,TEEC_Session *sessionIns,int id) {
   tsnIns->self = sessionIns;
   tsnIns->self->session_id = id;
   tsnIns->self->context = tcnIns->self;
   struct timeval tvcreate;
   gettimeofday(&tvcreate, NULL);
   tsnIns->createtime = tvcreate;
   if (tsl->first == NULL)
   {
      tsnIns->next = NULL;
      tsnIns->prev = NULL;
      tsl->first = tsnIns;
      tsl->last = tsnIns;
      tsl->count = 1;
   } else
   {
      tsnIns->prev = tsl->last;
      tsnIns->next = NULL;
      tsl->last->next = tsnIns;
      tsl->last = tsnIns;
      tsl->count = tsl->count + 1;
   }
   tsnIns = tsl->first;
   while(tsnIns != NULL){
      printf("load tsnIns->self->session_id =  0x %8.8x \n",tsnIns->self->session_id);
      printf("tsnIns->self = %p  \n",tsnIns->self);
      tsnIns = tsnIns->next;
   }
   //tsl->count = tsl->count + 1;

   printf("load_tsl successed 0x %8.8x\n",id);
   return 0;
}


#ifdef GP_PROXY_WORKER
/**
 * Server that exposes a method call and waits for it to be called
 */
void
receive_methodcall(
      threadpool_t *pool,
      pthread_mutex_t *mutex_tcl,
      pthread_mutex_t *mutex_tsl,
      tcl_t *tcl,
      tsl_t *tsl,
      char *workername
)
{
   DBusMessage *msg;
   DBusConnection *conn;
   DBusError err;
   int ret;
   dbus_bool_t bResult;

   threadpool_init(pool,
#ifdef GP_PROXY
         MAX_NUM_THREAD + 2
#endif
#ifdef GP_WORKER
                   MAX_NUM_THREAD, tcl, tsl
#endif
   );

#ifdef GP_WORKER
   pthread_mutex_init(mutex_tcl, NULL);
   pthread_mutex_init(mutex_tsl, NULL);
#endif

#ifdef GP_PROXY
   pthread_mutex_init(mutex_workerrec, NULL);
   pthread_cond_init(cond_notbusy, NULL);
   for (int iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
   {
      workerrec[iworker].busy = 0;
      workerrec[iworker].context_fd = 0;
      // workerrec[iworker].context_addr = 0;
      workerrec[iworker].context_addr = 0xffffffff;
      workerrec[iworker].sessionid_count = 0;
      workerrec[iworker].first = NULL;
      workerrec[iworker].last = NULL;
    }

    DBusMsgConn* thdfargs_stp = (DBusMsgConn*)malloc(sizeof(DBusMsgConn));
    thdfargs_stp->mutex_workerrec = mutex_workerrec;
    thdfargs_stp->workerrec = workerrec;
    threadpool_add_task(
       pool,
       session_timeout_process,
       thdfargs_stp
    );

    DBusMsgConn* thdfargs_ctp = (DBusMsgConn*)malloc(sizeof(DBusMsgConn));
    thdfargs_ctp->mutex_workerrec = mutex_workerrec;
    thdfargs_ctp->workerrec = workerrec;
    thdfargs_ctp->cond_notbusy = cond_notbusy;
    threadpool_add_task(
       pool,
       context_timeout_process,
       thdfargs_ctp
    );
#endif

   printf("%s is listening for method calls ... \n", workername);

   // initialise the error
   dbus_error_init(&err);

   dbus_threads_init_default();

   // connect to the bus and check for errors
   conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
   // conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Connection Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (NULL == conn)
   {
      fprintf(stderr, "Connection Null\n");
      exit(1);
   }

   char dbusname[1024];
   memset((char *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   int64_t workernum = 0;
   for (int iind = 0; iind < strlen(workername) - 6; iind++)
   {
      workernum = workernum +
                  (workername[strlen(workername) - 1 - iind] - '0') * pow(10, iind);
#if 0
      printf(
             "workername[%d] = %c. \n",
	     strlen(workername) - 1 - iind,
	     workername[strlen(workername) - 1 - iind]
	    );
#endif
   }
   // printf("The worker num is 0x %16.16lx. \n", workernum);
   // request our name on the bus and check for errors
   ret =
         dbus_bus_request_name(
               conn,
               // "test.method.server",
               dbusname,
               DBUS_NAME_FLAG_REPLACE_EXISTING,
               &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Name Error (%s)\n", err.message);
      dbus_error_free(&err);
   }
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
   {
      fprintf(stderr, "Not Primary Owner (%d)\n", ret);
      exit(1);
   }

   // loop, testing for new messages
   memset((char *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.Type", workername);
   while (true)
   {
      // non blocking read of the next available message
      dbus_connection_read_write(conn, 0);
      msg = dbus_connection_pop_message(conn);

      // loop again if we haven't got a message
      if (NULL == msg)
      {
         usleep(10000);
         continue;
      }

      // check this is a method call for the right interface & method
      bResult = dbus_message_is_method_call(
            msg,
            // "test.method.Type",
            dbusname,
            "TEEC_InitializeContext"
      );
      if (bResult == TRUE)
      {
         DBusMsgConn *thdfargs = (DBusMsgConn *) malloc(sizeof(DBusMsgConn));
         thdfargs->msg = msg;
         thdfargs->conn = conn;
#ifdef GP_PROXY
    thdfargs->mutex_workerrec = mutex_workerrec;
	 thdfargs->cond_notbusy = cond_notbusy;
	 thdfargs->workerrec = workerrec;
#endif
#ifdef GP_WORKER
         thdfargs->workernum = workernum;
         thdfargs->mutex_tcl = mutex_tcl;
         thdfargs->mutex_tsl = mutex_tsl;
         thdfargs->tcl = tcl;
         thdfargs->tsl = tsl;
#endif
         threadpool_add_task(
               pool,
               reply_to_method_call_teec_inicont,
               thdfargs
         );
      }

      // check this is a method call for the right interface & method
      bResult = dbus_message_is_method_call(
            msg,
            // "test.method.Type",
            dbusname,
            "TEEC_FinalizeContext"
      );
      if (bResult == TRUE)
      {
         DBusMsgConn *thdfargs = (DBusMsgConn *) malloc(sizeof(DBusMsgConn));
         thdfargs->msg = msg;
         thdfargs->conn = conn;
#ifdef GP_PROXY
    thdfargs->mutex_workerrec = mutex_workerrec;
	 thdfargs->cond_notbusy = cond_notbusy;
	 thdfargs->workerrec = workerrec;
#endif
#ifdef GP_WORKER
         thdfargs->workernum = workernum;
         thdfargs->mutex_tcl = mutex_tcl;
         thdfargs->mutex_tsl = mutex_tsl;
         thdfargs->tcl = tcl;
         thdfargs->tsl = tsl;
#endif
         threadpool_add_task(
               pool,
               reply_to_method_call_teec_fincont,
               thdfargs
         );
      }

      // check this is a method call for the right interface & method
      bResult = dbus_message_is_method_call(
            msg,
            // "test.method.Type",
            dbusname,
            "TEEC_OpenSession"
      );
      if (bResult == TRUE)
      {
         DBusMsgConn *thdfargs = (DBusMsgConn *) malloc(sizeof(DBusMsgConn));
         thdfargs->msg = msg;
         thdfargs->conn = conn;
#ifdef GP_PROXY
      thdfargs->mutex_workerrec = mutex_workerrec;
	   thdfargs->cond_notbusy = cond_notbusy;
	   thdfargs->workerrec = workerrec;
#endif
#ifdef GP_WORKER
         thdfargs->workernum = workernum;
         thdfargs->mutex_tcl = mutex_tcl;
         thdfargs->mutex_tsl = mutex_tsl;
         thdfargs->tcl = tcl;
         thdfargs->tsl = tsl;
#endif
         threadpool_add_task(
               pool,
               reply_to_method_call_teec_opensession,
               thdfargs
         );
      }

      // check this is a method call for the right interface & method
      bResult = dbus_message_is_method_call(
            msg,
            // "test.method.Type",
            dbusname,
            "TEEC_CloseSession"
      );
      if (bResult == TRUE)
      {
         DBusMsgConn *thdfargs = (DBusMsgConn *) malloc(sizeof(DBusMsgConn));
         thdfargs->msg = msg;
         thdfargs->conn = conn;
#ifdef GP_PROXY
      thdfargs->mutex_workerrec = mutex_workerrec;
	   thdfargs->cond_notbusy = cond_notbusy;
	   thdfargs->workerrec = workerrec;
#endif
#ifdef GP_WORKER
         thdfargs->workernum = workernum;
         thdfargs->mutex_tcl = mutex_tcl;
         thdfargs->mutex_tsl = mutex_tsl;
         thdfargs->tcl = tcl;
         thdfargs->tsl = tsl;
#endif
         threadpool_add_task(
               pool,
               reply_to_method_call_teec_closesession,
               thdfargs
         );
      }

      bResult = dbus_message_is_method_call(
            msg,
            // "test.method.Type",
            dbusname,
            "TEEC_InvokeCommand"
      );
      if (bResult == TRUE)
      {
         DBusMsgConn *thdfargs = (DBusMsgConn *) malloc(sizeof(DBusMsgConn));
         thdfargs->msg = msg;
         thdfargs->conn = conn;
#ifdef GP_PROXY
      thdfargs->mutex_workerrec = mutex_workerrec;
	   thdfargs->cond_notbusy = cond_notbusy;
	   thdfargs->workerrec = workerrec;
#endif
#ifdef GP_WORKER
         thdfargs->workernum = workernum;
         thdfargs->mutex_tcl = mutex_tcl;
         thdfargs->mutex_tsl = mutex_tsl;
         thdfargs->tcl = tcl;
         thdfargs->tsl = tsl;
#endif
         threadpool_add_task(
               pool,
               reply_to_method_call_teec_invokecommand,
               thdfargs
         );
      }

      // check this is a method call for the right interface & method
      bResult = dbus_message_is_method_call(
            msg,
            // "test.method.Type",
            dbusname,
            "Destroy"
      );
      if (bResult == TRUE)
      {
         reply_to_method_call_destroy_threadpool(
               msg,
               conn,
               pool
#ifdef GP_WORKER
               ,
               mutex_tcl,
               mutex_tsl
#endif

#ifdef GP_PROXY
       ,
	    mutex_workerrec,
	    cond_notbusy
#endif
         );
      }

      // free the message
      // dbus_message_unref(msg);

   } // end of the while true
} // end of the function
#endif



/**
 * Call a method on a remote object
 */
int32_t
method_call_teec_inicont(
      const char *workername,

      const uint8_t *name, size_t name_size,
      int32_t in_context_fd,
      const uint8_t *in_context_tapath, size_t in_context_tapath_size,
      uint64_t in_context_sessionlist_next,
      uint64_t in_context_sessionlist_prev,
      uint64_t in_context_shrdmemlist_next,
      uint64_t in_context_shrdmemlist_prev,
      uint64_t in_context_sharebuffer_buffer,
      int64_t in_context_sharebuffer_bufferbarrier,

      uint32_t *teecresult,
      int32_t *context_fd,
      uint8_t *context_tapath, size_t context_tapath_insize,
      uint64_t *context_sessionlist_next,
      uint64_t *context_sessionlist_prev,
      uint64_t *context_shrdmemlist_next,
      uint64_t *context_shrdmemlist_prev,
      uint64_t *context_sharebuffer_buffer,
      int64_t *context_sharebuffer_bufferbarrier,
      uint64_t *context_addr,
      uint32_t *context_tapath_outsize
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   int ret;
   int iType;
   unsigned char *context_tapath_temp = NULL;
   dbus_int32_t di32Temp;
   dbus_uint32_t dui32Temp;
   dbus_int64_t di64Temp;
   dbus_uint64_t dui64Temp;

   // initialiset the errors
   dbus_error_init(&err);

   dbus_threads_init_default();

   char dbusname[1024];
   if (conn == NULL)
   {
      // connect to the system bus and check for errors
      // conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
      conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Connection Error (%s)\n", err.message);
         dbus_error_free(&err);
      }
      if (NULL == conn)
      {
         return -1;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              workername,
              u64time,
              (long unsigned int) rand()
      );
      // request our name on the bus
      ret =
            dbus_bus_request_name(
                  conn,
                  dbusname,
                  DBUS_NAME_FLAG_REPLACE_EXISTING,
                  &err
            );
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Name Error (%s)\n", err.message);
         dbus_error_free(&err);
         dbus_connection_flush(conn);
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         return -1;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", workername);
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", workername);
   msg =
         dbus_message_new_method_call(
               // "test.method.server",      // target for the method call
               dbusname,
               // "/test/method/Object",     // object to call on
               objname,
               // "test.method.Type",        // interface to call on
               interfacename,
               "TEEC_InitializeContext"   // method name
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      dbus_connection_flush(conn);
      return -1;
   }

   // append arguments
   dbus_message_iter_init_append(msg, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   di32Temp = name_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (name_size > 0 && name != NULL)
   {
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &name
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }
   }

   di32Temp = in_context_fd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_context_tapath_size > 0 &&
       in_context_tapath != NULL &&
       strlen((const char *) in_context_tapath) > 0
         )
   {
      if (dbus_validate_utf8((const char *) in_context_tapath, &err) == true)
      {
         di32Temp = strlen((const char *) in_context_tapath);
      } else
      {
         di32Temp = 0;
      }
   } else
   {
      di32Temp = 0;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   // if (in_context_tapath_size > 0 && in_context_tapath != NULL)
   if (di32Temp > 0)
   {
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &in_context_tapath
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }
   }

   dui64Temp = in_context_sessionlist_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_sessionlist_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_shrdmemlist_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_shrdmemlist_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_sharebuffer_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di64Temp = in_context_sharebuffer_bufferbarrier;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT64,
               &di64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {  // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }
   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_connection_flush(conn);
   dbus_message_unref(msg);

   printf("\n");
   printf("Method Call Teec Init Contex Sent. \n");

   // block until we recieve a reply
   dbus_pending_call_block(pending);

   // get the reply message
   msg = dbus_pending_call_steal_reply(pending);
   if (NULL == msg)
   {
      fprintf(stderr, "Reply Null\n");
      return -1;
   }
   // free the pending message handle
   dbus_pending_call_unref(pending);

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *teecresult = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *context_fd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *context_tapath_outsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   if (*context_tapath_outsize > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &context_tapath_temp);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sessionlist_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sessionlist_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_shrdmemlist_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_shrdmemlist_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sharebuffer_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT64
         )
   {
      fprintf(stderr, "Argument is not INT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di64Temp
   );
   *context_sharebuffer_bufferbarrier = di64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_addr = dui64Temp;

   printf("Got Reply of Method Call Teec Init Contex: \n");
   printf("   teecresult                  = 0x %8.8x \n", *teecresult);
   printf("   fd                          = 0x %8.8x \n", (unsigned int) *context_fd);
   printf("   ta_path                     = %s \n", context_tapath_temp);
   printf("   ta_path_size                = %d \n", (int) *context_tapath_outsize);
#if 0
                                                                                                                           printf("   TEEC_Context session_list.next           = 0x %16.16lx \n",
                   *context_sessionlist_next
		   );
   printf("   TEEC_Context session_list.prev           = 0x %16.16lx \n",
                   *context_sessionlist_prev
		   );
   printf("   TEEC_Context shrd_mem_list.next          = 0x %16.16lx \n",
                   *context_shrdmemlist_next
		   );
   printf("   TEEC_Context shrd_mem_list.prev          = 0x %16.16lx \n",
                   *context_shrdmemlist_prev
		   );
   printf("   TEEC_Context share_buffer.buffer         = 0x %16.16lx \n",
                   *context_sharebuffer_buffer
		   );
   printf("   TEEC_Context share_buffer.buffer_barrier = 0x %16.16lx \n",
                   (long unsigned int)*context_sharebuffer_bufferbarrier
		   );
#endif
   printf("   context addr                = 0x %16.16lx \n",
          (long unsigned int) *context_addr
   );

   if (
         context_tapath_insize > *context_tapath_outsize &&
         *context_tapath_outsize > 0 &&
         context_tapath != NULL &&
         context_tapath_temp != NULL
         )
   {
      memcpy(context_tapath, context_tapath_temp, *context_tapath_outsize);
      *(context_tapath + *context_tapath_outsize) = 0;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *(context_tapath + 0) = 0;
   }

   // free msg
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return 0;
}


/**
 * Call a method on a remote object
 */
int32_t
method_call_teec_fincont(
      const char *workername,

      int32_t in_context_fd,
      const uint8_t *in_context_tapath, size_t in_context_tapath_size,
      uint64_t in_context_sessionlist_next,
      uint64_t in_context_sessionlist_prev,
      uint64_t in_context_shrdmemlist_next,
      uint64_t in_context_shrdmemlist_prev,
      uint64_t in_context_sharebuffer_buffer,
      int64_t in_context_sharebuffer_bufferbarrier,
      uint64_t in_context_addr,

      int32_t *context_fd,
      uint8_t *context_tapath, size_t context_tapath_insize,
      uint64_t *context_sessionlist_next,
      uint64_t *context_sessionlist_prev,
      uint64_t *context_shrdmemlist_next,
      uint64_t *context_shrdmemlist_prev,
      uint64_t *context_sharebuffer_buffer,
      int64_t *context_sharebuffer_bufferbarrier,
      uint32_t *context_tapath_outsize
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   int ret;
   int iType;
   unsigned char *context_tapath_temp = NULL;
   dbus_int32_t di32Temp;
   dbus_uint32_t dui32Temp;
   dbus_int64_t di64Temp;
   dbus_uint64_t dui64Temp;

   // initialiset the errors
   dbus_error_init(&err);

   char dbusname[1024];
   if (conn == NULL)
   {
      // connect to the system bus and check for errors
      conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Connection Error (%s)\n", err.message);
         dbus_error_free(&err);
      }
      if (NULL == conn)
      {
         return -1;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              workername,
              u64time,
              (long unsigned int) rand()
      );
      // request our name on the bus
      ret =
            dbus_bus_request_name(
                  conn,
                  dbusname,
                  DBUS_NAME_FLAG_REPLACE_EXISTING,
                  &err
            );
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Name Error (%s)\n", err.message);
         dbus_error_free(&err);
         dbus_connection_flush(conn);
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         return -1;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", workername);
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", workername);
   msg =
         dbus_message_new_method_call(
               // "test.method.server",      // target for the method call
               dbusname,
               // "/test/method/Object",     // object to call on
               objname,
               // "test.method.Type",        // interface to call on
               interfacename,
               "TEEC_FinalizeContext"
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      dbus_connection_flush(conn);
      return -1;
   }

   // append arguments
   dbus_message_iter_init_append(msg, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   di32Temp = in_context_fd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_context_tapath_size > 0 &&
       in_context_tapath != NULL &&
       strlen((const char *) in_context_tapath) > 0
         )
   {
      if (dbus_validate_utf8((const char *) in_context_tapath, &err) == true)
      {
         di32Temp = strlen((const char *) in_context_tapath);
      } else
      {
         di32Temp = 0;
      }
   } else
   {
      di32Temp = 0;
   }

   // fprintf(stderr, "in_context_tapath_size = %ld \n", in_context_tapath_size);
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   // if (in_context_tapath_size > 0 && in_context_tapath != NULL)
   if (di32Temp > 0)
   {
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &in_context_tapath
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }
   }

   dui64Temp = in_context_sessionlist_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_sessionlist_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_shrdmemlist_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_shrdmemlist_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_sharebuffer_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di64Temp = in_context_sharebuffer_bufferbarrier;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT64,
               &di64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_addr;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {  // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }
   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_connection_flush(conn);
   dbus_message_unref(msg);

   printf("\n");
   printf("Method Call Teec Fin Contex Sent. \n");

   // block until we recieve a reply
   dbus_pending_call_block(pending);

   // get the reply message
   msg = dbus_pending_call_steal_reply(pending);
   if (NULL == msg)
   {
      fprintf(stderr, "Reply Null\n");
      return -1;
   }
   // free the pending message handle
   dbus_pending_call_unref(pending);

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *context_fd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *context_tapath_outsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   if (*context_tapath_outsize > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &context_tapath_temp);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sessionlist_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sessionlist_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_shrdmemlist_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_shrdmemlist_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sharebuffer_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT64
         )
   {
      fprintf(stderr, "Argument is not INT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di64Temp
   );
   *context_sharebuffer_bufferbarrier = di64Temp;

   printf("Got Reply of Method Call Teec Fin Contex: \n");
   printf("   fd                          = 0x %8.8x \n", (unsigned int) *context_fd);
   printf("   ta_path                     = %s \n", context_tapath_temp);
   printf("   ta_path_size                = %d \n", (int) *context_tapath_outsize);
#if 0
                                                                                                                           printf("   TEEC_Context session_list.next           = 0x %16.16lx \n",
                   *context_sessionlist_next
		   );
   printf("   TEEC_Context session_list.prev           = 0x %16.16lx \n",
                   *context_sessionlist_prev
		   );
   printf("   TEEC_Context shrd_mem_list.next          = 0x %16.16lx \n",
                   *context_shrdmemlist_next
		   );
   printf("   TEEC_Context shrd_mem_list.prev          = 0x %16.16lx \n",
                   *context_shrdmemlist_prev
		   );
   printf("   TEEC_Context share_buffer.buffer         = 0x %16.16lx \n",
                   *context_sharebuffer_buffer
		   );
   printf("   TEEC_Context share_buffer.buffer_barrier = 0x %16.16lx \n",
                   (long unsigned int)*context_sharebuffer_bufferbarrier
		   );
#endif

   if (
         context_tapath_insize > *context_tapath_outsize &&
         *context_tapath_outsize > 0 &&
         context_tapath != NULL &&
         context_tapath_temp != NULL
         )
   {
      memcpy(context_tapath, context_tapath_temp, *context_tapath_outsize);
      *(context_tapath + *context_tapath_outsize) = 0;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *(context_tapath + 0) = 0;
   }

   // free msg
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return 0;
}


/**
 * Call a method on a remote object
 */
int32_t
method_call_teec_opensession(
      const char *workername,

      int32_t in_context_fd,
      const uint8_t *in_context_tapath,
      size_t in_context_tapath_size,
      uint64_t in_context_sessionlist_next,
      uint64_t in_context_sessionlist_prev,
      uint64_t in_context_shrdmemlist_next,
      uint64_t in_context_shrdmemlist_prev,
      uint64_t in_context_sharebuffer_buffer,
      int64_t in_context_sharebuffer_bufferbarrier,

      uint32_t in_destination_timelow,
      uint32_t in_destination_timemid,
      uint32_t in_destination_timehiandver,
      uint32_t *in_destination_clockseqandnode,
      int32_t in_destination_clockseqandnode_size,

      uint32_t in_connectionmethod,
      uint64_t in_connectiondata,

      uint32_t in_operation_started,
      uint32_t in_operation_paramtypes,

      uint64_t in_operation_param1_tmpref_buffer,
      uint32_t in_operation_param1_tmpref_size,
      uint64_t in_operation_param1_memref_parent,
      uint32_t in_operation_param1_memref_size,
      uint32_t in_operation_param1_memref_offset,
      uint32_t in_operation_param1_value_a,
      uint32_t in_operation_param1_value_b,
      int32_t in_operation_param1_ionref_ionsharefd,
      uint32_t in_operation_param1_ionref_ionsize,

      uint64_t in_operation_param2_tmpref_buffer,
      uint32_t in_operation_param2_tmpref_size,
      uint64_t in_operation_param2_memref_parent,
      uint32_t in_operation_param2_memref_size,
      uint32_t in_operation_param2_memref_offset,
      uint32_t in_operation_param2_value_a,
      uint32_t in_operation_param2_value_b,
      int32_t in_operation_param2_ionref_ionsharefd,
      uint32_t in_operation_param2_ionref_ionsize,

      uint64_t in_operation_param3_tmpref_buffer,
      uint32_t in_operation_param3_tmpref_size,
      uint64_t in_operation_param3_memref_parent,
      uint32_t in_operation_param3_memref_size,
      uint32_t in_operation_param3_memref_offset,
      uint32_t in_operation_param3_value_a,
      uint32_t in_operation_param3_value_b,
      int32_t in_operation_param3_ionref_ionsharefd,
      uint32_t in_operation_param3_ionref_ionsize,

      uint64_t in_operation_param4_tmpref_buffer,
      uint32_t in_operation_param4_tmpref_size,
      uint64_t in_operation_param4_memref_parent,
      uint32_t in_operation_param4_memref_size,
      uint32_t in_operation_param4_memref_offset,
      uint32_t in_operation_param4_value_a,
      uint32_t in_operation_param4_value_b,
      int32_t in_operation_param4_ionref_ionsharefd,
      uint32_t in_operation_param4_ionref_ionsize,

      uint64_t in_operation_session,
      int32_t in_operation_cancelflag,

      uint32_t in_returnorigin,

      uint64_t in_context_addr,


      uint32_t *teecresult,

      int32_t *context_fd,
      uint8_t *context_tapath,
      size_t context_tapath_size,
      uint32_t *context_tapath_outsize,
      uint64_t *context_sessionlist_next,
      uint64_t *context_sessionlist_prev,
      uint64_t *context_shrdmemlist_next,
      uint64_t *context_shrdmemlist_prev,
      uint64_t *context_sharebuffer_buffer,
      int64_t *context_sharebuffer_bufferbarrier,

      uint32_t *session_seesionid,
      uint32_t *session_serviceid_timelow,
      uint32_t *session_serviceid_timemid,
      uint32_t *session_serviceid_timehiandver,
      uint32_t *session_serviceid_clockseqandnode,
      int32_t session_serviceid_clockseqandnode_size,
      uint32_t *session_serviceid_clockseqandnode_outsize,
      uint32_t *session_opscnt,
      uint64_t *session_head_next,
      uint64_t *session_head_prev,
      uint64_t *session_context,

      uint32_t *operation_started,
      uint32_t *operation_paramtypes,

      uint64_t *operation_param1_tmpref_buffer,
      uint32_t *operation_param1_tmpref_size,
      uint64_t *operation_param1_memref_parent,
      uint32_t *operation_param1_memref_size,
      uint32_t *operation_param1_memref_offset,
      uint32_t *operation_param1_value_a,
      uint32_t *operation_param1_value_b,
      int32_t *operation_param1_ionref_ionsharefd,
      uint32_t *operation_param1_ionref_ionsize,

      uint64_t *operation_param2_tmpref_buffer,
      uint32_t *operation_param2_tmpref_size,
      uint64_t *operation_param2_memref_parent,
      uint32_t *operation_param2_memref_size,
      uint32_t *operation_param2_memref_offset,
      uint32_t *operation_param2_value_a,
      uint32_t *operation_param2_value_b,
      int32_t *operation_param2_ionref_ionsharefd,
      uint32_t *operation_param2_ionref_ionsize,

      uint64_t *operation_param3_tmpref_buffer,
      uint32_t *operation_param3_tmpref_size,
      uint64_t *operation_param3_memref_parent,
      uint32_t *operation_param3_memref_size,
      uint32_t *operation_param3_memref_offset,
      uint32_t *operation_param3_value_a,
      uint32_t *operation_param3_value_b,
      int32_t *operation_param3_ionref_ionsharefd,
      uint32_t *operation_param3_ionref_ionsize,

      uint64_t *operation_param4_tmpref_buffer,
      uint32_t *operation_param4_tmpref_size,
      uint64_t *operation_param4_memref_parent,
      uint32_t *operation_param4_memref_size,
      uint32_t *operation_param4_memref_offset,
      uint32_t *operation_param4_value_a,
      uint32_t *operation_param4_value_b,
      int32_t *operation_param4_ionref_ionsharefd,
      uint32_t *operation_param4_ionref_ionsize,

      uint64_t *operation_session,
      int32_t *operation_cancelflag,

      uint32_t *returnorigin
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   DBusMessageIter ArrayIter;
   int ret;
   int iType;
   unsigned char *context_tapath_temp = NULL;
   dbus_uint32_t *session_serviceid_clockseqandnode_temp = NULL;
   int session_serviceid_clockseqandnode_realsize;
   dbus_int32_t di32Temp;
   dbus_uint32_t dui32Temp;
   dbus_int64_t di64Temp;
   dbus_uint64_t dui64Temp;
   char buf[2];
   buf[0] = DBUS_TYPE_UINT32;
   buf[1] = '\0';

   // initialiset the errors
   dbus_error_init(&err);

   char dbusname[1024];
   if (conn == NULL)
   {
      // connect to the system bus and check for errors
      conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Connection Error (%s)\n", err.message);
         dbus_error_free(&err);
      }
      if (NULL == conn)
      {
         return -1;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              workername,
              u64time,
              (long unsigned int) rand()
      );

      // request our name on the bus
      ret =
            dbus_bus_request_name(
                  conn,
                  dbusname,
                  DBUS_NAME_FLAG_REPLACE_EXISTING,
                  &err
            );
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Name Error (%s)\n", err.message);
         dbus_error_free(&err);
         dbus_connection_flush(conn);
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         return -1;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", workername);
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", workername);
   msg =
         dbus_message_new_method_call(
               // "test.method.server",      // target for the method call
               dbusname,
               // "/test/method/Object",     // object to call on
               objname,
               // "test.method.Type",        // interface to call on
               interfacename,
               "TEEC_OpenSession"
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      dbus_connection_flush(conn);
      return -1;
   }

   // append arguments
   dbus_message_iter_init_append(msg, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   di32Temp = in_context_fd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_context_tapath_size > 0 &&
       in_context_tapath != NULL &&
       strlen((const char *) in_context_tapath) > 0
         )
   {
      if (dbus_validate_utf8((const char *) in_context_tapath, &err) == true)
      {
         di32Temp = strlen((const char *) in_context_tapath);
      } else
      {
         di32Temp = 0;
      }
   } else
   {
      di32Temp = 0;
   }

   // fprintf(stderr, "in_context_tapath_size = %ld \n", in_context_tapath_size);
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   // if (in_context_tapath_size > 0 && in_context_tapath != NULL)
   if (di32Temp > 0)
   {
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &in_context_tapath
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }
   }

   dui64Temp = in_context_sessionlist_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_sessionlist_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_shrdmemlist_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_shrdmemlist_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_sharebuffer_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di64Temp = in_context_sharebuffer_bufferbarrier;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT64,
               &di64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_destination_timelow;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_destination_timemid;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_destination_timehiandver;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_destination_clockseqandnode_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_destination_clockseqandnode_size > 0 &&
       in_destination_clockseqandnode != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_destination_clockseqandnode,
                  in_destination_clockseqandnode_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dui32Temp = in_connectionmethod;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_connectiondata;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }


   dui32Temp = in_operation_started;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_paramtypes;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param1_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param1_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param1_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param2_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param2_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param2_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param3_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param3_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param3_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param4_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param4_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param4_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_session;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_cancelflag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_returnorigin;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_context_addr;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   ///////////////////////////////////////////////////////////////////

   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {   // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_connection_flush(conn);
   dbus_message_unref(msg);

   printf("\n");
   printf("Method Call Teec Open Session Sent. \n");

   // block until we recieve a reply
   dbus_pending_call_block(pending);

   // get the reply message
   msg = dbus_pending_call_steal_reply(pending);
   if (NULL == msg)
   {
      fprintf(stderr, "Reply Null\n");
      return -1;
   }

   // free the pending message handle
   dbus_pending_call_unref(pending);

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *teecresult = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *context_fd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *context_tapath_outsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   if (*context_tapath_outsize > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &context_tapath_temp);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sessionlist_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sessionlist_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_shrdmemlist_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_shrdmemlist_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *context_sharebuffer_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT64
         )
   {
      fprintf(stderr, "Argument is not INT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di64Temp
   );
   *context_sharebuffer_bufferbarrier = di64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_seesionid = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timelow = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timemid = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timehiandver = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_clockseqandnode_outsize = dui32Temp;

   if (*session_serviceid_clockseqandnode_outsize > 0)
   {
      bResult =
            dbus_message_iter_next(
                  &structIter
            );

      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &session_serviceid_clockseqandnode_temp,
            &session_serviceid_clockseqandnode_realsize
      );
   }

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_opscnt = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_head_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_head_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_context = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_started = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_paramtypes = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param1_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param1_memref_parent = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param1_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param2_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param2_memref_parent = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param2_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param3_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param3_memref_parent = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param3_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param4_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param4_memref_parent = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param4_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_session = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_cancelflag = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *returnorigin = dui32Temp;

   printf("Got Reply of Method Call Teec Open Session: \n");
   printf("   teecresult                  = 0x %8.8x \n", *teecresult);
   printf("   fd                          = 0x %8.8x \n", (unsigned int) *context_fd);
   printf("   ta_path                     = %s \n", context_tapath_temp);
   printf("   ta_path_size                = %d \n", (int) *context_tapath_outsize);
   printf("   session_seesionid           = 0x %8.8x \n",
          *session_seesionid
   );
#if 0
                                                                                                                           printf("   TEEC_Context session_list.next                  = 0x %16.16lx \n",
           *context_sessionlist_next
    );
    printf("   TEEC_Context session_list.prev                  = 0x %16.16lx \n",
           *context_sessionlist_prev
    );
    printf("   TEEC_Context shrd_mem_list.next                 = 0x %16.16lx \n",
           *context_shrdmemlist_next
    );
    printf("   TEEC_Context shrd_mem_list.prev                 = 0x %16.16lx \n",
           *context_shrdmemlist_prev
    );
    printf("   TEEC_Context share_buffer.buffer                = 0x %16.16lx \n",
           *context_sharebuffer_buffer
    );
    printf("   TEEC_Context share_buffer.buffer_barrier        = 0x %16.16lx \n",
           (long unsigned int)*context_sharebuffer_bufferbarrier
    );

    printf("   TEEC_Session session_serviceid_timelow          = 0x %8.8x \n",
           *session_serviceid_timelow
    );
    printf("   TEEC_Session session_serviceid_timehiandver     = 0x %8.8x \n",
           *session_serviceid_timehiandver
    );

    printf("   TEEC_Session session_serviceid_clockseqandnode  = \n");
    if (*session_serviceid_clockseqandnode_outsize > 0 &&
        session_serviceid_clockseqandnode_temp != NULL)
    {
       printf("   ");
       for (int i = 0; i < session_serviceid_clockseqandnode_realsize; i++) {
          printf(" %2.2x",
                 session_serviceid_clockseqandnode_temp[i]
          );
       }
       printf("\n");
    }
    printf("   TEEC_Session            clockseqandnode_outsize = 0x %8.8x \n",
            *session_serviceid_clockseqandnode_outsize
    );

    printf("   TEEC_Session session_opscnt                     = 0x %8.8x \n",
           *session_opscnt
    );
    printf("   TEEC_Session session_head_next                  = 0x %16.16lx \n",
           *session_head_next
    );
    printf("   TEEC_Session session_head_prev                  = 0x %16.16lx \n",
           *session_head_prev
    );
    printf("   TEEC_Session session_context                    = 0x %16.16lx \n",
           *session_context
    );
    printf("   TEEC_Session operation_started                  = 0x %8.8x \n",
           *operation_started
    );
    printf("   TEEC_Session operation_paramtypes               = 0x %8.8x \n",
           *operation_paramtypes
    );

    printf("   TEEC_Session operation_param1_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param1_tmpref_buffer
    );
    printf("   TEEC_Session operation_param1_tmpref_size       = 0x %8.8x \n",
           *operation_param1_tmpref_size
    );
    printf("   TEEC_Session operation_param1_memref_parent     = 0x %16.16lx \n",
           *operation_param1_memref_parent
    );
    printf("   TEEC_Session operation_param1_memref_size       = 0x %8.8x \n",
           *operation_param1_memref_size
    );
    printf("   TEEC_Session operation_param1_memref_offse      = 0x %8.8x \n",
           *operation_param1_memref_offset
    );
    printf("   TEEC_Session operation_param1_value_a           = 0x %8.8x \n",
           *operation_param1_value_a
    );
    printf("   TEEC_Session operation_param1_value_b           = 0x %8.8x \n",
           *operation_param1_value_b
    );
    printf("   TEEC_Session operation_param1_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param1_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param1_ionref_ionsize    = 0x %8.8x \n",
           *operation_param1_ionref_ionsize
    );

    printf("   TEEC_Session operation_param2_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param2_tmpref_buffer
    );
    printf("   TEEC_Session operation_param2_tmpref_size       = 0x %8.8x \n",
           *operation_param2_tmpref_size
    );
    printf("   TEEC_Session operation_param2_memref_parent     = 0x %16.16lx \n",
           *operation_param2_memref_parent
    );
    printf("   TEEC_Session operation_param2_memref_size       = 0x %8.8x \n",
           *operation_param2_memref_size
    );
    printf("   TEEC_Session operation_param2_memref_offset     = 0x %8.8x \n",
           *operation_param2_memref_offset
    );
    printf("   TEEC_Session operation_param2_value_a           = 0x %8.8x \n",
           *operation_param2_value_a
    );
    printf("   TEEC_Session operation_param2_value_b           = 0x %8.8x \n",
           *operation_param2_value_b
    );
    printf("   TEEC_Session operation_param2_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param2_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param2_ionref_ionsize    = 0x %8.8x \n",
           *operation_param2_ionref_ionsize
    );

    printf("   TEEC_Session operation_param3_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param3_tmpref_buffer
    );
    printf("   TEEC_Session operation_param3_tmpref_size       = 0x %8.8x \n",
           *operation_param3_tmpref_size
    );
    printf("   TEEC_Session operation_param3_memref_parent     = 0x %16.16lx \n",
           *operation_param3_memref_parent
    );
    printf("   TEEC_Session operation_param3_memref_size       = 0x %8.8x \n",
           *operation_param3_memref_size
    );
    printf("   TEEC_Session operation_param3_memref_offset     = 0x %8.8x \n",
           *operation_param3_memref_offset
    );
    printf("   TEEC_Session operation_param3_value_a           = 0x %8.8x \n",
           *operation_param3_value_a
    );
    printf("   TEEC_Session operation_param3_value_b           = 0x %8.8x \n",
           *operation_param3_value_b
    );
    printf("   TEEC_Session operation_param3_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param3_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param3_ionref_ionsize    = 0x %8.8x \n",
           *operation_param3_ionref_ionsize
    );

    printf("   TEEC_Session operation_param4_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param4_tmpref_buffer
    );
    printf("   TEEC_Session operation_param4_tmpref_size       = 0x %8.8x \n",
           *operation_param4_tmpref_size
    );
    printf("   TEEC_Session operation_param4_memref_parent     = 0x %16.16lx \n",
           *operation_param4_memref_parent
    );
    printf("   TEEC_Session operation_param4_memref_size       = 0x %8.8x \n",
           *operation_param4_memref_size
    );
    printf("   TEEC_Session operation_param4_memref_offset     = 0x %8.8x \n",
           *operation_param4_memref_offset
    );
    printf("   TEEC_Session operation_param4_value_a           = 0x %8.8x \n",
           *operation_param4_value_a
    );
    printf("   TEEC_Session operation_param4_value_b           = 0x %8.8x \n",
           *operation_param4_value_b
    );
    printf("   TEEC_Session operation_param4_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param4_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param4_ionref_ionsize    = 0x %8.8x \n",
           *operation_param4_ionref_ionsize
    );

    printf("   TEEC_Session operation_session                  = 0x %16.16lx \n",
           *operation_session
    );
    printf("   TEEC_Session operation_cancelflag               = 0x %8.8x \n",
           (unsigned int)*operation_cancelflag
    );
    printf("   TEEC_Session returnorigin                       = 0x %8.8x \n",
           *returnorigin
    );
#endif

   if (context_tapath_size > *context_tapath_outsize)
   {
      memcpy(context_tapath, context_tapath_temp, *context_tapath_outsize);
      *(context_tapath + *context_tapath_outsize) = 0;
   } else
   {
      dbus_message_unref(msg);
      return -1;
   }

   if (session_serviceid_clockseqandnode_size >= session_serviceid_clockseqandnode_realsize &&
       session_serviceid_clockseqandnode_temp != NULL &&
       session_serviceid_clockseqandnode_realsize > 0
         )
   {
      for (int i = 0; i < session_serviceid_clockseqandnode_realsize; i++)
      {
         session_serviceid_clockseqandnode[i] =
               session_serviceid_clockseqandnode_temp[i];

      }
      *session_serviceid_clockseqandnode_outsize = session_serviceid_clockseqandnode_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *session_serviceid_clockseqandnode_outsize = 0;
   }

   // free msg
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return 0;
}


int32_t
method_call_teec_closesession(
      const char *workername,

      uint32_t in_session_seesionid,
      uint32_t in_session_serviceid_timelow,
      uint32_t in_session_serviceid_timemid,
      uint32_t in_session_serviceid_timehiandver,
      uint32_t *in_session_serviceid_clockseqandnode,
      int32_t in_session_serviceid_clockseqandnode_size,
      uint32_t in_session_opscnt,
      uint64_t in_session_head_next,
      uint64_t in_session_head_prev,
      uint64_t in_session_context,

      uint32_t *session_seesionid,
      uint32_t *session_serviceid_timelow,
      uint32_t *session_serviceid_timemid,
      uint32_t *session_serviceid_timehiandver,
      uint32_t *session_serviceid_clockseqandnode,
      int32_t session_serviceid_clockseqandnode_size,
      uint32_t *session_serviceid_clockseqandnode_outsize,
      uint32_t *session_opscnt,
      uint64_t *session_head_next,
      uint64_t *session_head_prev,
      uint64_t *session_context
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   DBusMessageIter ArrayIter;
   int ret;
   int iType;
   dbus_uint32_t *session_serviceid_clockseqandnode_temp = NULL;
   int session_serviceid_clockseqandnode_realsize;
   dbus_int32_t di32Temp;
   dbus_uint32_t dui32Temp;
   dbus_uint64_t dui64Temp;
   char buf[2];
   buf[0] = DBUS_TYPE_UINT32;
   buf[1] = '\0';

   // initialiset the errors
   dbus_error_init(&err);

   char dbusname[1024];
   if (conn == NULL)
   {
      // connect to the system bus and check for errors
      conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Connection Error (%s)\n", err.message);
         dbus_error_free(&err);
      }
      if (NULL == conn)
      {
         return -1;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              workername,
              u64time,
              (long unsigned int) rand()
      );
      // request our name on the bus
      ret =
            dbus_bus_request_name(
                  conn,
                  dbusname,
                  DBUS_NAME_FLAG_REPLACE_EXISTING,
                  &err
            );
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Name Error (%s)\n", err.message);
         dbus_error_free(&err);
         dbus_connection_flush(conn);
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         return -1;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", workername);
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", workername);
   msg =
         dbus_message_new_method_call(
               // "test.method.server",      // target for the method call
               dbusname,
               // "/test/method/Object",     // object to call on
               objname,
               // "test.method.Type",        // interface to call on
               interfacename,
               "TEEC_CloseSession"
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      dbus_connection_flush(conn);
      return -1;
   }

   // append arguments
   dbus_message_iter_init_append(msg, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   dui32Temp = in_session_seesionid;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_timelow;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_timemid;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_timehiandver;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_session_serviceid_clockseqandnode_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_session_serviceid_clockseqandnode_size > 0 &&
       in_session_serviceid_clockseqandnode != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_session_serviceid_clockseqandnode,
                  in_session_serviceid_clockseqandnode_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dui32Temp = in_session_opscnt;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }


   dui64Temp = in_session_head_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_session_head_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_session_context;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {   // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }
   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_connection_flush(conn);
   dbus_message_unref(msg);

   printf("\n");
   printf("Method Call Teec Close Session Sent. \n");

   // block until we recieve a reply
   dbus_pending_call_block(pending);

   // get the reply message
   msg = dbus_pending_call_steal_reply(pending);
   if (NULL == msg)
   {
      fprintf(stderr, "Reply Null\n");
      return -1;
   }

   // free the pending message handle
   dbus_pending_call_unref(pending);

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_seesionid = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timelow = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timemid = dui32Temp;


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timehiandver = dui32Temp;


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_clockseqandnode_outsize = dui32Temp;

   if (*session_serviceid_clockseqandnode_outsize > 0)
   {
      bResult =
            dbus_message_iter_next(
                  &structIter
            );

      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &session_serviceid_clockseqandnode_temp,
            &session_serviceid_clockseqandnode_realsize
      );
   }

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_opscnt = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_head_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_head_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_context = dui64Temp;


   printf("Got Reply of Method Call Teec Close Session: \n");
   printf("   session_seesionid           = 0x %8.8x \n",
          *session_seesionid
   );
#if 0
                                                                                                                           printf("   TEEC_Session session_serviceid_timelow          = 0x %8.8x \n",
           *session_serviceid_timelow
    );
    printf("   TEEC_Session session_serviceid_timemid          = 0x %8.8x \n",
           *session_serviceid_timemid
    );
    printf("   TEEC_Session session_serviceid_timehiandver     = 0x %8.8x \n",
           *session_serviceid_timehiandver
    );
    printf("   TEEC_Session session_serviceid_clockseqandnode  = \n");
    printf("   ");
    for (int i = 0; i < session_serviceid_clockseqandnode_realsize; i++) {
        printf(" %2.2x",
               session_serviceid_clockseqandnode_temp[i]
        );
    }
    printf("\n");
    printf("   TEEC_Session            clockseqandnode_outsize = 0x %8.8x \n",
           *session_serviceid_clockseqandnode_outsize
    );
    printf("   TEEC_Session session_opscnt                     = 0x %8.8x \n",
           *session_opscnt
    );
    printf("   TEEC_Session session_head_next                  = 0x %16.16lx \n",
           *session_head_next
    );
    printf("   TEEC_Session session_head_prev                  = 0x %16.16lx \n",
           *session_head_prev
    );
#endif
   printf("   session_context             = 0x %16.16lx \n",
          *session_context
   );

   if (session_serviceid_clockseqandnode_size >= session_serviceid_clockseqandnode_realsize &&
       session_serviceid_clockseqandnode_temp != NULL &&
       session_serviceid_clockseqandnode_realsize > 0
         )
   {
      memcpy(
            session_serviceid_clockseqandnode,
            session_serviceid_clockseqandnode_temp,
            session_serviceid_clockseqandnode_realsize * sizeof(uint32_t)
      );
      *session_serviceid_clockseqandnode_outsize = session_serviceid_clockseqandnode_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *session_serviceid_clockseqandnode_outsize = 0;
   }

   // free msg
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return 0;
}


int32_t
method_call_teec_invokecommand(
      const char *workername,

      uint32_t in_session_sessionid,
      uint32_t in_session_serviceid_timelow,
      uint32_t in_session_serviceid_timemid,
      uint32_t in_session_serviceid_timehiandver,
      uint32_t *in_session_serviceid_clockseqandnode,
      uint32_t in_session_serviceid_clockseqandnode_size,
      uint32_t in_session_opscnt,
      uint64_t in_session_head_next,
      uint64_t in_session_head_prev,
      uint64_t in_session_context,

      uint32_t commandid,

      uint32_t in_operation_started,
      uint32_t in_operation_paramtypes,

      uint64_t in_operation_param1_tmpref_buffer,
      uint32_t in_operation_param1_tmpref_size,
      uint64_t in_operation_param1_memref_parent,
      uint32_t in_operation_param1_memref_parent_flag,
      uint32_t in_operation_param1_memref_size,
      uint32_t in_operation_param1_memref_offset,
      uint32_t in_operation_param1_value_a,
      uint32_t in_operation_param1_value_b,
      int32_t in_operation_param1_ionref_ionsharefd,
      uint32_t in_operation_param1_ionref_ionsize,

      uint64_t in_operation_param2_tmpref_buffer,
      uint32_t in_operation_param2_tmpref_size,
      uint64_t in_operation_param2_memref_parent,
      uint32_t in_operation_param2_memref_parent_flag,
      uint32_t in_operation_param2_memref_size,
      uint32_t in_operation_param2_memref_offset,
      uint32_t in_operation_param2_value_a,
      uint32_t in_operation_param2_value_b,
      int32_t  in_operation_param2_ionref_ionsharefd,
      uint32_t in_operation_param2_ionref_ionsize,

      uint64_t in_operation_param3_tmpref_buffer,
      uint32_t in_operation_param3_tmpref_size,
      uint64_t in_operation_param3_memref_parent,
      uint32_t in_operation_param3_memref_parent_flag,
      uint32_t in_operation_param3_memref_size,
      uint32_t in_operation_param3_memref_offset,
      uint32_t in_operation_param3_value_a,
      uint32_t in_operation_param3_value_b,
      int32_t in_operation_param3_ionref_ionsharefd,
      uint32_t in_operation_param3_ionref_ionsize,

      uint64_t in_operation_param4_tmpref_buffer,
      uint32_t in_operation_param4_tmpref_size,
      uint64_t in_operation_param4_memref_parent,
      uint32_t in_operation_param4_memref_parent_flag,
      uint32_t in_operation_param4_memref_size,
      uint32_t in_operation_param4_memref_offset,
      uint32_t in_operation_param4_value_a,
      uint32_t in_operation_param4_value_b,
      int32_t in_operation_param4_ionref_ionsharefd,
      uint32_t in_operation_param4_ionref_ionsize,

      uint64_t in_operation_session,
      int32_t in_operation_cancelflag,

      uint32_t in_returnorigin,

      uint32_t *in_buffer1,
      uint32_t in_buffer1_size,
      uint32_t *in_buffer2,
      uint32_t in_buffer2_size,
      uint32_t *in_buffer3,
      uint32_t in_buffer3_size,
      uint32_t *in_buffer4,
      uint32_t in_buffer4_size,

      int32_t lt_flag,

      uint32_t *teecresult,

      uint32_t *session_sessionid,
      uint32_t *session_serviceid_timelow,
      uint32_t *session_serviceid_timemid,
      uint32_t *session_serviceid_timehiandver,
      uint32_t *session_serviceid_clockseqandnode,
      int32_t session_serviceid_clockseqandnode_size,
      uint32_t *session_serviceid_clockseqandnode_outsize,
      uint32_t *session_opscnt,
      uint64_t *session_head_next,
      uint64_t *session_head_prev,
      uint64_t *session_context,

      uint32_t *operation_started,
      uint32_t *operation_paramtypes,

      uint64_t *operation_param1_tmpref_buffer,
      uint32_t *operation_param1_tmpref_size,
      uint64_t *operation_param1_memref_parent,
      uint32_t *operation_param1_memref_parent_flag,
      uint32_t *operation_param1_memref_size,
      uint32_t *operation_param1_memref_offset,
      uint32_t *operation_param1_value_a,
      uint32_t *operation_param1_value_b,
      int32_t *operation_param1_ionref_ionsharefd,
      uint32_t *operation_param1_ionref_ionsize,

      uint64_t *operation_param2_tmpref_buffer,
      uint32_t *operation_param2_tmpref_size,
      uint64_t *operation_param2_memref_parent,
      uint32_t *operation_param2_memref_parent_flag,
      uint32_t *operation_param2_memref_size,
      uint32_t *operation_param2_memref_offset,
      uint32_t *operation_param2_value_a,
      uint32_t *operation_param2_value_b,
      int32_t *operation_param2_ionref_ionsharefd,
      uint32_t *operation_param2_ionref_ionsize,

      uint64_t *operation_param3_tmpref_buffer,
      uint32_t *operation_param3_tmpref_size,
      uint64_t *operation_param3_memref_parent,
      uint32_t *operation_param3_memref_parent_flag,
      uint32_t *operation_param3_memref_size,
      uint32_t *operation_param3_memref_offset,
      uint32_t *operation_param3_value_a,
      uint32_t *operation_param3_value_b,
      int32_t *operation_param3_ionref_ionsharefd,
      uint32_t *operation_param3_ionref_ionsize,

      uint64_t *operation_param4_tmpref_buffer,
      uint32_t *operation_param4_tmpref_size,
      uint64_t *operation_param4_memref_parent,
      uint32_t *operation_param4_memref_parent_flag,
      uint32_t *operation_param4_memref_size,
      uint32_t *operation_param4_memref_offset,
      uint32_t *operation_param4_value_a,
      uint32_t *operation_param4_value_b,
      int32_t *operation_param4_ionref_ionsharefd,
      uint32_t *operation_param4_ionref_ionsize,

      uint64_t *operation_session,
      int32_t *operation_cancelflag,

      uint32_t *returnorigin,

      uint32_t *buffer1,
      uint32_t buffer1_size,
      uint32_t *buffer1_outsize,
      uint32_t *buffer2,
      uint32_t buffer2_size,
      uint32_t *buffer2_outsize,
      uint32_t *buffer3,
      uint32_t buffer3_size,
      uint32_t *buffer3_outsize,
      uint32_t *buffer4,
      uint32_t buffer4_size,
      uint32_t *buffer4_outsize
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   DBusMessageIter ArrayIter;
   int ret;
   int iType;
   dbus_uint32_t *session_serviceid_clockseqandnode_temp = NULL;
   int session_serviceid_clockseqandnode_realsize;
   dbus_int32_t di32Temp;
   dbus_uint32_t dui32Temp;
   dbus_uint64_t dui64Temp;
   char buf[2];
   buf[0] = DBUS_TYPE_UINT32;
   buf[1] = '\0';

   dbus_uint32_t *buffer1_temp = NULL;
   int buffer1_realsize;
   dbus_uint32_t *buffer2_temp = NULL;
   int buffer2_realsize;
   dbus_uint32_t *buffer3_temp = NULL;
   int buffer3_realsize;
   dbus_uint32_t *buffer4_temp = NULL;
   int buffer4_realsize;


   // initialiset the errors
   dbus_error_init(&err);

   char dbusname[1024];
   if (conn == NULL)
   {
      // connect to the system bus and check for errors
      conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Connection Error (%s)\n", err.message);
         dbus_error_free(&err);
      }
      if (NULL == conn)
      {
         return -1;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              workername,
              u64time,
              (long unsigned int) rand()
      );
      // request our name on the bus
      ret =
            dbus_bus_request_name(
                  conn,
                  dbusname,
                  DBUS_NAME_FLAG_REPLACE_EXISTING,
                  &err
            );
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Name Error (%s)\n", err.message);
         dbus_error_free(&err);
         dbus_connection_flush(conn);
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         return -1;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", workername);
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", workername);
   msg =
         dbus_message_new_method_call(
               // "test.method.server",      // target for the method call
               dbusname,
               // "/test/method/Object",     // object to call on
               objname,
               // "test.method.Type",        // interface to call on
               interfacename,
               "TEEC_InvokeCommand"
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      dbus_connection_flush(conn);
      return -1;
   }


   // append arguments
   dbus_message_iter_init_append(msg, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );


   dui32Temp = in_session_sessionid;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_timelow;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_timemid;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_timehiandver;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_session_serviceid_clockseqandnode_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_session_serviceid_clockseqandnode_size > 0 &&
       in_session_serviceid_clockseqandnode != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_session_serviceid_clockseqandnode,
                  in_session_serviceid_clockseqandnode_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dui32Temp = in_session_opscnt;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_session_head_next;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_session_head_prev;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_session_context;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }


   dui32Temp = commandid;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }


   dui32Temp = in_operation_started;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_paramtypes;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param1_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param1_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_memref_parent_flag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param1_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param1_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param2_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param2_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_memref_parent_flag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param2_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param2_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param3_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param3_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_memref_parent_flag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param3_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param3_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param4_tmpref_buffer;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_tmpref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_param4_memref_parent;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_memref_parent_flag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_memref_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_memref_offset;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_value_a;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_value_b;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_param4_ionref_ionsharefd;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_operation_param4_ionref_ionsize;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui64Temp = in_operation_session;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &dui64Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   di32Temp = in_operation_cancelflag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_returnorigin;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dui32Temp = in_buffer1_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_buffer1_size > 0 &&
       in_buffer1 != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_buffer1,
                  in_buffer1_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dui32Temp = in_buffer2_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_buffer2_size > 0 &&
       in_buffer2 != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_buffer2,
                  in_buffer2_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dui32Temp = in_buffer3_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_buffer3_size > 0 &&
       in_buffer3 != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_buffer3,
                  in_buffer3_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dui32Temp = in_buffer4_size;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &dui32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   if (in_buffer4_size > 0 &&
       in_buffer4 != NULL)
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &in_buffer4,
                  in_buffer4_size
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return -1;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   di32Temp = lt_flag;
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &di32Temp
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   printf("Method Call Teec Invoke Command lt_flag %d  Sent. \n",lt_flag);

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {   // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }
   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return -1;
   }

   dbus_connection_flush(conn);
   dbus_message_unref(msg);

   printf("\n");
   printf("Method Call Teec Invoke Command Sent. \n");

   /////////////////////////////////////////////////////////////////////////////////////

   // block until we recieve a reply
   dbus_pending_call_block(pending);

   // get the reply message
   msg = dbus_pending_call_steal_reply(pending);
   if (NULL == msg)
   {
      fprintf(stderr, "Reply Null\n");
      return -1;
   }

   // free the pending message handle
   dbus_pending_call_unref(pending);

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );


   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *teecresult = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_sessionid = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timelow = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timemid = dui32Temp;


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_message_unref(msg);
      return -1;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_timehiandver = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_serviceid_clockseqandnode_outsize = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   if (*session_serviceid_clockseqandnode_outsize > 0)
   {

      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter
      );

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &session_serviceid_clockseqandnode_temp,
            &session_serviceid_clockseqandnode_realsize
      );
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *session_opscnt = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_head_next = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_head_prev = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *session_context = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_started = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_paramtypes = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param1_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param1_memref_parent = dui64Temp;

   bResult = dbus_message_iter_next(&structIter);
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_memref_parent_flag = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param1_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param1_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param2_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param2_memref_parent = dui64Temp;

   bResult = dbus_message_iter_next(&structIter);
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_memref_parent_flag = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param2_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param2_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param3_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param3_memref_parent = dui64Temp;

   bResult = dbus_message_iter_next(&structIter);
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_memref_parent_flag = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param3_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param3_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param4_tmpref_buffer = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_tmpref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_param4_memref_parent = dui64Temp;

   bResult = dbus_message_iter_next(&structIter);
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_memref_parent_flag = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_memref_size = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_memref_offset = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_value_a = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_value_b = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_param4_ionref_ionsharefd = di32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *operation_param4_ionref_ionsize = dui32Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui64Temp
   );
   *operation_session = dui64Temp;

   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &di32Temp
   );
   *operation_cancelflag = di32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *returnorigin = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *buffer1_outsize = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   if (*buffer1_outsize > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter
      );

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &buffer1_temp,
            &buffer1_realsize
      );
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *buffer2_outsize = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   if (*buffer2_outsize > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter
      );

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &buffer2_temp,
            &buffer2_realsize
      );
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *buffer3_outsize = dui32Temp;
   bResult =
         dbus_message_iter_next(
               &structIter
         );

   if (*buffer3_outsize > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter
      );

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &buffer3_temp,
            &buffer3_realsize
      );
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_message_unref(msg);
      return -1;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &dui32Temp
   );
   *buffer4_outsize = dui32Temp;

   if (*buffer4_outsize > 0)
   {
      bResult =
            dbus_message_iter_next(
                  &structIter
            );

      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter
      );

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32.\n");
         dbus_message_unref(msg);
         return -1;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &buffer4_temp,
            &buffer4_realsize
      );
   }


   printf("Got Reply of Method Call Teec Invoke Command: \n");
   printf("   teecresult                  = 0x %8.8x \n",
          *teecresult);
   printf("   session_seesionid           = 0x %8.8x \n",
          *session_sessionid
   );
#if 0
                                                                                                                           printf("   TEEC_Session session_serviceid_timelow          = 0x %8.8x \n",
           *session_serviceid_timelow
    );
    printf("   TEEC_Session session_serviceid_timemid          = 0x %8.8x \n",
           *session_serviceid_timemid
    );
    printf("   TEEC_Session session_serviceid_timehiandver     = 0x %8.8x \n",
           *session_serviceid_timehiandver
    );
    printf("   TEEC_Session session_serviceid_clockseqandnode  = \n");
    if ( *session_serviceid_clockseqandnode_outsize > 0 &&
         session_serviceid_clockseqandnode_temp != NULL
       )
    {
       for (int i = 0; i < session_serviceid_clockseqandnode_realsize; i++) {
          printf(" %2.2x",
                 session_serviceid_clockseqandnode_temp[i]
          );
       }
       printf("\n");
    }
    printf("   TEEC_Session            clockseqandnode_outsize = 0x %8.8x \n",
           *session_serviceid_clockseqandnode_outsize
    );
    printf("   TEEC_Session session_opscnt                     = 0x %8.8x \n",
           *session_opscnt
    );
    printf("   TEEC_Session session_head_next                  = 0x %16.16lx \n",
           *session_head_next
    );
    printf("   TEEC_Session session_head_prev                  = 0x %16.16lx \n",
           *session_head_prev
    );
    printf("   TEEC_Session session_context                    = 0x %16.16lx \n",
           *session_context
    );
    printf("   TEEC_Session session_context                    = 0x %16.16lx \n",
           *session_context
    );
    printf("   TEEC_Session operation_started                  = 0x %8.8x \n",
           *operation_started
    );
    printf("   TEEC_Session operation_paramtypes               = 0x %8.8x \n",
           *operation_paramtypes
    );
    printf("   TEEC_Session operation_param1_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param1_tmpref_buffer
    );
    printf("   TEEC_Session operation_param1_tmpref_size       = 0x %8.8x \n",
           *operation_param1_tmpref_size
    );
    printf("   TEEC_Session operation_param1_memref_parent     = 0x %16.16lx \n",
           *operation_param1_memref_parent
    );
    printf("   TEEC_Session operation_param1_memref_size       = 0x %8.8x \n",
           *operation_param1_memref_size
    );
    printf("   TEEC_Session operation_param1_memref_offse      = 0x %8.8x \n",
           *operation_param1_memref_offset
    );
    printf("   TEEC_Session operation_param1_value_a           = 0x %8.8x \n",
           *operation_param1_value_a
    );
    printf("   TEEC_Session operation_param1_value_b           = 0x %8.8x \n",
           *operation_param1_value_b
    );
    printf("   TEEC_Session operation_param1_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param1_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param1_ionref_ionsize    = 0x %8.8x \n",
           *operation_param1_ionref_ionsize
    );

    printf("   TEEC_Session operation_param2_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param2_tmpref_buffer
    );
    printf("   TEEC_Session operation_param2_tmpref_size       = 0x %8.8x \n",
           *operation_param2_tmpref_size
    );
    printf("   TEEC_Session operation_param2_memref_parent     = 0x %16.16lx \n",
           *operation_param2_memref_parent
    );
    printf("   TEEC_Session operation_param2_memref_size       = 0x %8.8x \n",
           *operation_param2_memref_size
    );
    printf("   TEEC_Session operation_param2_memref_offset     = 0x %8.8x \n",
           *operation_param2_memref_offset
    );
    printf("   TEEC_Session operation_param2_value_a           = 0x %8.8x \n",
           *operation_param2_value_a
    );
    printf("   TEEC_Session operation_param2_value_b           = 0x %8.8x \n",
           *operation_param2_value_b
    );
    printf("   TEEC_Session operation_param2_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param2_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param2_ionref_ionsize    = 0x %8.8x \n",
           *operation_param2_ionref_ionsize
    );

    printf("   TEEC_Session operation_param3_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param3_tmpref_buffer
    );
    printf("   TEEC_Session operation_param3_tmpref_size       = 0x %8.8x \n",
           *operation_param3_tmpref_size
    );
    printf("   TEEC_Session operation_param3_memref_parent     = 0x %16.16lx \n",
           *operation_param3_memref_parent
    );
    printf("   TEEC_Session operation_param3_memref_size       = 0x %8.8x \n",
           *operation_param3_memref_size
    );
    printf("   TEEC_Session operation_param3_memref_offset     = 0x %8.8x \n",
           *operation_param3_memref_offset
    );
    printf("   TEEC_Session operation_param3_value_a           = 0x %8.8x \n",
           *operation_param3_value_a
    );
    printf("   TEEC_Session operation_param3_value_b           = 0x %8.8x \n",
           *operation_param3_value_b
    );
    printf("   TEEC_Session operation_param3_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param3_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param3_ionref_ionsize    = 0x %8.8x \n",
           *operation_param3_ionref_ionsize
    );

    printf("   TEEC_Session operation_param4_tmpref_buffer     = 0x %16.16lx \n",
           *operation_param4_tmpref_buffer
    );
    printf("   TEEC_Session operation_param4_tmpref_size       = 0x %8.8x \n",
           *operation_param4_tmpref_size
    );
    printf("   TEEC_Session operation_param4_memref_parent     = 0x %16.16lx \n",
           *operation_param4_memref_parent
    );
    printf("   TEEC_Session operation_param4_memref_size       = 0x %8.8x \n",
           *operation_param4_memref_size
    );
    printf("   TEEC_Session operation_param4_memref_offset     = 0x %8.8x \n",
           *operation_param4_memref_offset
    );
    printf("   TEEC_Session operation_param4_value_a           = 0x %8.8x \n",
           *operation_param4_value_a
    );
    printf("   TEEC_Session operation_param4_value_b           = 0x %8.8x \n",
           *operation_param4_value_b
    );
    printf("   TEEC_Session operation_param4_ionref_ionsharefd = 0x %8.8x \n",
           (unsigned int)*operation_param4_ionref_ionsharefd
    );
    printf("   TEEC_Session operation_param4_ionref_ionsize    = 0x %8.8x \n",
           *operation_param4_ionref_ionsize
    );

    printf("   TEEC_Session operation_session                  = 0x %16.16lx \n",
           *operation_session
    );
    printf("   TEEC_Session operation_cancelflag               = 0x %8.8x \n",
           (unsigned int)*operation_cancelflag
    );
    printf("   returnorigin                                    = 0x %8.8x \n",
           *returnorigin
    );

    printf("   buffer1                                         = \n");
    if (buffer1_temp != NULL)
    {
       for (int i = 0; i < buffer1_realsize; i++) {
          printf(" %2.2x",
                 buffer1_temp[i]
          );
       }
       printf("\n");
    }
    printf("   buffer1_outsize                                 = 0x %8.8x \n",
           *buffer1_outsize
    );

    printf("   buffer2                                         = \n");
    if (buffer2_temp != NULL)
    {
       for (int i = 0; i < buffer2_realsize; i++) {
          printf(" %2.2x",
                 buffer2_temp[i]
          );
       }
       printf("\n");
    }
    printf("   buffer2_outsize                                 = 0x %8.8x \n",
           *buffer2_outsize
    );

    printf("   buffer3                                         = \n");
    if (buffer3_temp != NULL)
    {
       for (int i = 0; i < buffer3_realsize; i++) {
          printf(" %2.2x",
                 buffer3_temp[i]
          );
       }
       printf("\n");
    }
    printf("   buffer3_outsize                                 = 0x %8.8x \n",
           *buffer3_outsize
    );

    if (buffer4_temp != NULL)
    {
       printf("   buffer4                                         = \n");
       for (int i = 0; i < buffer4_realsize; i++) {
          printf(" %2.2x",
                 buffer4_temp[i]
          );
       }
       printf("\n");
    }
    printf("   buffer4_outsize                                 = 0x %8.8x \n",
           *buffer4_outsize
    );
#endif

   if (session_serviceid_clockseqandnode_size >= session_serviceid_clockseqandnode_realsize &&
       session_serviceid_clockseqandnode != NULL &&
       session_serviceid_clockseqandnode_temp != NULL &&
       session_serviceid_clockseqandnode_realsize > 0
         )
   {
      memcpy(
            session_serviceid_clockseqandnode,
            session_serviceid_clockseqandnode_temp,
            session_serviceid_clockseqandnode_realsize * sizeof(uint32_t)
      );
      *session_serviceid_clockseqandnode_outsize = session_serviceid_clockseqandnode_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *session_serviceid_clockseqandnode_outsize = 0;
   }

   if (buffer1_size >= (uint32_t) buffer1_realsize &&
       buffer1 != NULL &&
       buffer1_temp != NULL &&
       buffer1_realsize > 0
         )
   {
      memcpy(
            buffer1,
            buffer1_temp,
            buffer1_realsize * sizeof(uint32_t)
      );
      *buffer1_outsize = buffer1_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *buffer1_outsize = 0;
   }

   if (buffer2_size >= (uint32_t) buffer2_realsize &&
       buffer2 != NULL &&
       buffer2_temp != NULL &&
       buffer2_realsize > 0
         )
   {
      memcpy(
            buffer2,
            buffer2_temp,
            buffer2_realsize * sizeof(uint32_t)
      );
      *buffer2_outsize = buffer2_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *buffer2_outsize = 0;
   }

   if (buffer3_size >= (uint32_t) buffer3_realsize &&
       buffer3 != NULL &&
       buffer3_temp != NULL &&
       buffer3_realsize > 0
         )
   {
      memcpy(
            buffer3,
            buffer3_temp,
            buffer3_realsize * sizeof(uint32_t)
      );
      *buffer3_outsize = buffer3_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *buffer3_outsize = 0;
   }

   if (buffer4_size >= (uint32_t) buffer4_realsize &&
       buffer4 != NULL &&
       buffer4_temp != NULL &&
       buffer4_realsize > 0
         )
   {
      memcpy(
            buffer4,
            buffer4_temp,
            buffer4_realsize * sizeof(uint32_t)
      );
      *buffer4_outsize = buffer4_realsize;
   } else
   {
      // dbus_message_unref(msg);
      // return -1;
      *buffer4_outsize = 0;
   }


   // free msg
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return 0;
}


/**
 * Call a method on a remote object
 */
void
method_call_destroy_threadpool(
      const char *workername
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   // DBusConnection* conn;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   int ret;
   int iType;
   unsigned char name[] = "threadpool";
   unsigned char *charp;
   dbus_uint32_t retcode;

   // initialiset the errors
   dbus_error_init(&err);

   char dbusname[1024];
   if (conn == NULL)
   {
      // connect to the system bus and check for errors
      conn = dbus_bus_get_private(DBUS_BUS_SESSION, &err);
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Connection Error (%s)\n", err.message);
         dbus_error_free(&err);
      }
      if (NULL == conn)
      {
         return;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              workername,
              u64time,
              (long unsigned int) rand()
      );
      // request our name on the bus
      ret =
            dbus_bus_request_name(
                  conn,
                  dbusname,
                  DBUS_NAME_FLAG_REPLACE_EXISTING,
                  &err
            );
      if (dbus_error_is_set(&err))
      {
         fprintf(stderr, "Name Error (%s)\n", err.message);
         dbus_error_free(&err);
         dbus_connection_flush(conn);
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         return;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", workername);
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", workername);
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", workername);
   msg =
         dbus_message_new_method_call(
               // "test.method.server",   // target for the method call
               dbusname,
               // "/test/method/Object",  // object to call on
               objname,
               // "test.method.Type",     // interface to call on
               interfacename,
               "Destroy"                  // method name
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      dbus_connection_flush(conn);
      return;
   }


   // append arguments
   dbus_message_iter_init_append(msg, &args);

   charp = name;
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &charp))
   {
      fprintf(stderr, "Out Of Memory!\n");
      exit(1);
   }

   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {  // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      exit(1);
   }
   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      exit(1);
   }
   dbus_connection_flush(conn);

   printf("\n");
   printf("Method Call Destroy Threadpool Sent. \n");

   // free message
   dbus_message_unref(msg);

   // block until we recieve a reply
   dbus_pending_call_block(pending);

   // get the reply message
   msg = dbus_pending_call_steal_reply(pending);
   if (NULL == msg)
   {
      fprintf(stderr, "Reply Null\n");
      exit(1);
   }
   // free the pending message handle
   dbus_pending_call_unref(pending);

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      exit(1);
   }

   iType =
         dbus_message_iter_get_arg_type(
               &args
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      exit(1);
   }
   dbus_message_iter_get_basic(
         &args,
         &retcode
   );

   printf("Got Reply of Method Call Destroy Threadpool: \n");
   printf("   retcode                     = 0x%8x \n", retcode);

   // free reply
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);
}


#ifdef GP_PROXY_WORKER

void *
reply_to_method_call_teec_inicont(
      // DBusMessage* msg,
      // DBusConnection* conn
      void *thdfargs
)
{
   DBusMsgConn *DBusMCP;
   DBusMessage *msg;
   DBusConnection *conn;
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   int iType;
   unsigned char *charp;
   // char* param = "";
   unsigned char *name = NULL;
   dbus_int32_t name_size;
   dbus_int32_t in_fd;
   unsigned char *in_ta_path = NULL;
   dbus_int32_t in_ta_path_size;
   dbus_uint64_t in_session_list_next;
   dbus_uint64_t in_session_list_prev;
   dbus_uint64_t in_shrd_mem_list_next;
   dbus_uint64_t in_shrd_mem_list_prev;
   dbus_uint64_t in_share_buffer_buffer;
   dbus_int64_t in_share_buffer_buffer_barrier;
   dbus_uint32_t teecresult;
   dbus_int32_t fd;
   // unsigned char ta_path[] = "/vendor/bin/rsa_demo_ta";
   // dbus_int32_t  ta_path_size = strlen((const char *)ta_path);
   unsigned char *ta_path = NULL;
   dbus_int32_t ta_path_size = 0;
   dbus_uint64_t session_list_next;
   dbus_uint64_t session_list_prev;
   dbus_uint64_t shrd_mem_list_next;
   dbus_uint64_t shrd_mem_list_prev;
   dbus_uint64_t share_buffer_buffer;
   dbus_int64_t share_buffer_buffer_barrier;
   dbus_uint64_t context_addr;
   dbus_uint32_t serial = 0;

#ifdef GP_PROXY
   pthread_mutex_t * mutex_workerrec;
   pthread_cond_t  * cond_notbusy;
   wr_t * workerrec;
#endif

#ifdef GP_WORKER
   pthread_mutex_t *mutex_tcl;
   pthread_mutex_t *mutex_tsl;
   tcl_t *tcl;
   tsl_t *tsl;
#endif

   DBusMCP = (DBusMsgConn *) thdfargs;
   msg = DBusMCP->msg;
   conn = DBusMCP->conn;
#ifdef GP_PROXY
   mutex_workerrec = DBusMCP->mutex_workerrec;
   cond_notbusy = DBusMCP->cond_notbusy;
   workerrec = DBusMCP->workerrec;
#endif
#ifdef GP_WORKER
   mutex_tcl = DBusMCP->mutex_tcl;
   mutex_tsl = DBusMCP->mutex_tsl;
   tcl = DBusMCP->tcl;
   tsl = DBusMCP->tsl;
#endif

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &name_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (name_size > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &name);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_fd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_ta_path_size
   );

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   // fprintf(stderr, "Debug in_ta_path_size = %d \n", in_ta_path_size);
   if (in_ta_path_size > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &in_ta_path);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_list_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_list_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_shrd_mem_list_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_shrd_mem_list_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_share_buffer_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT64
         )
   {
      fprintf(stderr, "Argument is not INT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_share_buffer_buffer_barrier);

   printf("Received method call Teec Initialize Context: \n");
   printf("   in name                     = %s \n", name);
   printf("   in name_size                = %d \n", name_size);
   printf("   in_fd                       = 0x %8.8x \n", in_fd);
   printf("   in_ta_path                  = %s \n", in_ta_path);
   printf("   in_ta_path_size             = %d \n", in_ta_path_size);
#if 0
   printf("   in_session_list_next           = 0x %16.16lx \n", in_session_list_next);
   printf("   in_session_list_prev           = 0x %16.16lx \n", in_session_list_prev);
   printf("   in_shrd_mem_list_next          = 0x %16.16lx \n", in_shrd_mem_list_next);
   printf("   in_shrd_mem_list_prev          = 0x %16.16lx \n", in_shrd_mem_list_prev);
   printf("   in_share_buffer_buffer         = 0x %16.16lx \n", in_share_buffer_buffer);
   printf("   in_share_buffer_buffer_barrier = 0x %16.16lx \n", in_share_buffer_buffer_barrier);
#endif

#ifdef GP_WORKER
   ////////////////////////////////////////////////////////////////////////////////////////////////
   TEEC_Context *contextIns = (TEEC_Context *) malloc(sizeof(TEEC_Context));

   TEEC_Result result;

   contextIns->fd = in_fd;
   contextIns->ta_path = in_ta_path;
   contextIns->session_list.next = (struct ListNode *) in_session_list_next;
   contextIns->session_list.prev = (struct ListNode *) in_session_list_prev;
   contextIns->shrd_mem_list.next = (struct ListNode *) in_shrd_mem_list_next;
   contextIns->shrd_mem_list.prev = (struct ListNode *) in_shrd_mem_list_prev;
   contextIns->share_buffer.buffer = (void *) in_share_buffer_buffer;
   contextIns->share_buffer.buffer_barrier.__align = (long long int) in_share_buffer_buffer_barrier;
   // typedef struct {
   //        volatile int __val[4*sizeof(long)/sizeof(int)];
   //        } sem_t;
   //
   // typedef union
   //        {
   //          char __size[__SIZEOF_SEM_T];
   //            long long int __align;
   //            } sem_t;
   struct timeval start, end;
   gettimeofday(&start, NULL);
   result = TEEC_InitializeContext(NULL, contextIns);
   gettimeofday(&end, NULL);
   uint32_t cost = 0;
   cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);
   if (result != TEEC_SUCCESS)
   {
      printf("Teec InitilizeContext Failed.\n");
      printf("   teecresult                  = 0x %8.8x.\n", result);

      teecresult = result;
      fd = 0;
      ta_path_size = 0;
      ta_path = NULL;
      charp = ta_path;
      session_list_next = 0;
      session_list_prev = 0;
      shrd_mem_list_next = 0;
      shrd_mem_list_prev = 0;
      share_buffer_buffer = 0;
      share_buffer_buffer_barrier = 0;
      context_addr = 0;
   } else
   {
      printf("Teec InitilizeContext Succed, cost time: %ld us \n", cost);

      tcn_t *tcnIns = (tcn_t *) malloc(sizeof(tcn_t));
      tcnIns->self = contextIns;
      struct timeval tvcreate;
      gettimeofday(&tvcreate, NULL);
      tcnIns->createtime = tvcreate;

      pthread_mutex_lock(mutex_tcl);
      if (tcl->first == NULL)
      {
         tcnIns->next = NULL;
         tcnIns->prev = NULL;
         tcl->first = tcnIns;
         tcl->last = tcnIns;
         tcl->count = 1;
      } else
      {
         tcnIns->prev = tcl->last;
         tcnIns->next = NULL;
         tcl->last->next = tcnIns;
         tcl->last = tcnIns;
         tcl->count = tcl->count + 1;
      }
      pthread_mutex_unlock(mutex_tcl);

      teecresult = result;
      fd = contextIns->fd;
      if (contextIns->ta_path != NULL)
      {
         ta_path_size = strlen((const char *) contextIns->ta_path);
      } else
      {
         ta_path_size = 0;
      }
      ta_path = contextIns->ta_path;
      charp = ta_path;
      session_list_next = (dbus_uint64_t) contextIns->session_list.next;
      session_list_prev = (dbus_uint64_t) contextIns->session_list.prev;
      shrd_mem_list_next = (dbus_uint64_t) contextIns->shrd_mem_list.next;
      shrd_mem_list_prev = (dbus_uint64_t) contextIns->shrd_mem_list.prev;
      share_buffer_buffer = (dbus_uint64_t) contextIns->share_buffer.buffer;
      share_buffer_buffer_barrier = contextIns->share_buffer.buffer_barrier.__align;

      // context_addr = (dbus_uint64_t)contextIns;
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      context_addr = (dbus_uint64_t) DBusMCP->workernum
                     + u64time
                     + (long unsigned int) rand();

      printf("   context fd                  = 0x %8.8x \n", contextIns->fd);
      printf("   context address             = 0x %16.16lx \n", context_addr);
   }

   // TEEC_FinalizeContext(&contextIns);
   // printf("Teec FinalizedContext.\n");
   ////////////////////////////////////////////////////////////////////////////////////////////////
#else
   ta_path = (unsigned char *)malloc(1024 * sizeof(char));
    ta_path_size = 1024;
    memset((char *)ta_path, 0, 1024);
    uint32_t context_tapath_outsize;

    char workername[1024];
    memset((char *)workername, 0, 1024);
    int ifound = 0;
    int iworker;
    for( ; ; )
    {
	 pthread_mutex_lock(mutex_workerrec);
    for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
	 {
      if (workerrec[iworker].busy == 0)
      {
         sprintf(workername, "%s%d", "gpworker", iworker);
         workerrec[iworker].busy = 1;
	      ifound = 1;
	      break;
      }
	 }
    if (ifound == 0)
    {
	     pthread_cond_wait(cond_notbusy, mutex_workerrec);
	 }
	 pthread_mutex_unlock(mutex_workerrec);

    if (ifound == 1)
    {
	   break;
	 }
    }

    method_call_teec_inicont(
		workername,

		name,
		name_size,
                in_fd,
                in_ta_path,
		in_ta_path_size,
                in_session_list_next,
                in_session_list_prev,
                in_shrd_mem_list_next,
                in_shrd_mem_list_prev,
                in_share_buffer_buffer,
                in_share_buffer_buffer_barrier,


		&teecresult,

                &fd,
                ta_path,
	  	ta_path_size,
                &session_list_next,
                &session_list_prev,
                &shrd_mem_list_next,
                &shrd_mem_list_prev,
                &share_buffer_buffer,
                &share_buffer_buffer_barrier,
                &context_addr,

                &context_tapath_outsize
               );

    if (teecresult == 0)
    {
       pthread_mutex_lock(mutex_workerrec);
       workerrec[iworker].context_fd = fd;
       workerrec[iworker].context_addr = context_addr;
       workerrec[iworker].first = NULL;
       workerrec[iworker].last = NULL;
       workerrec[iworker].sessionid_count = 0;
       struct timeval tvcreate;
       gettimeofday(&tvcreate, NULL);
       workerrec[iworker].context_createtime = tvcreate;
       pthread_mutex_unlock(mutex_workerrec);
    }
    else
    {
       workerrec[iworker].busy = 0;
    }

    if (ta_path_size >= context_tapath_outsize) {
       ta_path_size = context_tapath_outsize;
       charp = ta_path;
    }
    else
    {
       ta_path_size = 0;
       charp = NULL;
    }

   ////////////////////////////////////////////////////////////////////////////////////////////////
#endif

   // create a reply from the message
   reply = dbus_message_new_method_return(msg);

#if 0
   teecresult = 0;
   fd = 0x04;
   charp = ta_path;
   session_list_next = 0xea3500a8;
   session_list_prev = 0xea3500a8;
   shrd_mem_list_next = 0xea3500b8;
   shrd_mem_list_prev = 0xea3500b8;
   share_buffer_buffer = 0;
   share_buffer_buffer_barrier = 0xdd901c10;
#endif

   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &teecresult
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &fd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   DBusError err;
   // initialise the errors
   dbus_error_init(&err);

   if (ta_path_size > 0 &&
       charp != NULL &&
       strlen((const char *) charp) > 0
         )
   {
      if (dbus_validate_utf8((const char *) charp, &err) == true)
      {
         ta_path_size = strlen((const char *) charp);
      } else
      {
         ta_path_size = 0;
      }
   } else
   {
      ta_path_size = 0;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &ta_path_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (ta_path_size > 0)
   {
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &charp
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_message_unref(reply);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &session_list_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &session_list_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &shrd_mem_list_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &shrd_mem_list_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &share_buffer_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT64,
               &share_buffer_buffer_barrier
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &context_addr
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send the reply && flush the connection
   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   // dbus_connection_close(conn);
   // dbus_connection_unref(conn);

   free(thdfargs);

   // sleep(2);

#if 0
  #ifdef GP_WORKER

#else
   if (ta_path == NULL)
   {
      free(ta_path);
   }
#endif
#endif

   return NULL;
}


void *
reply_to_method_call_teec_fincont(
      void *thdfargs
)
{
   DBusMsgConn *DBusMCP;
   DBusMessage *msg;
   DBusConnection *conn;
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   int iType;
   unsigned char *charp;
   // char* param = "";
   dbus_int32_t in_fd;
   unsigned char *in_ta_path = NULL;
   dbus_int32_t in_ta_path_size;
   dbus_uint64_t in_session_list_next;
   dbus_uint64_t in_session_list_prev;
   dbus_uint64_t in_shrd_mem_list_next;
   dbus_uint64_t in_shrd_mem_list_prev;
   dbus_uint64_t in_share_buffer_buffer;
   dbus_int64_t in_share_buffer_buffer_barrier;
   dbus_uint64_t in_context_addr;

   dbus_int32_t fd;
   dbus_int32_t ta_path_size = 0;
   dbus_uint64_t session_list_next;
   dbus_uint64_t session_list_prev;
   dbus_uint64_t shrd_mem_list_next;
   dbus_uint64_t shrd_mem_list_prev;
   dbus_uint64_t share_buffer_buffer;
   dbus_int64_t share_buffer_buffer_barrier;
   dbus_uint32_t serial = 0;

#ifdef GP_PROXY
                                                                                                                           pthread_mutex_t * mutex_workerrec;
   pthread_cond_t  * cond_notbusy;
   wr_t * workerrec;
#endif

#ifdef GP_WORKER
   pthread_mutex_t *mutex_tcl;
   tcl_t *tcl;
   tsl_t *tsl;
#endif

   DBusMCP = (DBusMsgConn *) thdfargs;
   msg = DBusMCP->msg;
   conn = DBusMCP->conn;
#ifdef GP_PROXY
                                                                                                                           mutex_workerrec = DBusMCP->mutex_workerrec;
   cond_notbusy = DBusMCP->cond_notbusy;
   workerrec = DBusMCP->workerrec;
#endif
#ifdef GP_WORKER
   mutex_tcl = DBusMCP->mutex_tcl;
   tcl = DBusMCP->tcl;
   tsl = DBusMCP->tsl;
#endif

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_fd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_ta_path_size
   );

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   // fprintf(stderr, "Debug in_ta_path_size = %d \n", in_ta_path_size);
   if (in_ta_path_size > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &in_ta_path);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_list_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_list_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_shrd_mem_list_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_shrd_mem_list_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_share_buffer_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT64
         )
   {
      fprintf(stderr, "Argument is not INT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_share_buffer_buffer_barrier);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_context_addr);

   printf("Received method call Teec Finalize Context: \n");
   printf("   in_fd                       = 0x %8.8x \n", in_fd);
   printf("   in_ta_path_size             = %d \n", in_ta_path_size);

   DBusError err;
   dbus_error_init(&err);
   if (in_ta_path_size > 0 && in_ta_path != NULL && dbus_validate_path((const char *) in_ta_path, &err) == true)
   {
      printf("   in_ta_path                  = %s \n", in_ta_path);
   }
#if 0
                                                                                                                           printf("   in_session_list_next           = 0x %16.16lx \n", in_session_list_next);
   printf("   in_session_list_prev           = 0x %16.16lx \n", in_session_list_prev);
   printf("   in_shrd_mem_list_next          = 0x %16.16lx \n", in_shrd_mem_list_next);
   printf("   in_shrd_mem_list_prev          = 0x %16.16lx \n", in_shrd_mem_list_prev);
   printf("   in_share_buffer_buffer         = 0x %16.16lx \n", in_share_buffer_buffer);
   printf("   in_share_buffer_buffer_barrier = 0x %16.16lx \n", in_share_buffer_buffer_barrier);
#endif
   printf("   in_context_addr             = 0x %16.16lx \n", in_context_addr);


   unsigned char *ta_path = NULL;
#ifdef GP_WORKER
   ////////////////////////////////////////////////////////////////////////////////////////////////
   TEEC_Context *contextIns;
   tcn_t *tcnIns;
   TEEC_Result result;

   contextIns = NULL;
   pthread_mutex_lock(mutex_tcl);
   if (tcl->first != NULL)
   {
      tcnIns = tcl->first;
      do
      {
         if (tcnIns->self->fd == in_fd)
         {
            contextIns = tcnIns->self;
            break;
         }
         tcnIns = tcnIns->next;
      } while (tcnIns != NULL);
   }
   pthread_mutex_unlock(mutex_tcl);

   if (contextIns == NULL)
   {
      if (tcl->first == NULL)
      {
         printf("The teec context list is null. \n");
         // teecresult = TEEC_ERROR_CONTEXT_LIST_NULL;
      } else
      {
         printf("Can't find the teec context. \n");
         // teecresult = TEEC_ERROR_NO_CONTEXT_MATCH;
      }

      fd = 0;
      ta_path_size = 0;
      charp = NULL;
      session_list_prev = 0;
      shrd_mem_list_next = 0;
      shrd_mem_list_prev = 0;
      share_buffer_buffer = 0;
      share_buffer_buffer_barrier = 0;
   } else
   {
      // contextIns.fd = in_fd;
      contextIns->ta_path = in_ta_path;
      contextIns->session_list.next = (struct ListNode *) in_session_list_next;
      contextIns->session_list.prev = (struct ListNode *) in_session_list_prev;
      contextIns->shrd_mem_list.next = (struct ListNode *) in_shrd_mem_list_next;
      contextIns->shrd_mem_list.prev = (struct ListNode *) in_shrd_mem_list_prev;
      contextIns->share_buffer.buffer = (void *) in_share_buffer_buffer;
      contextIns->share_buffer.buffer_barrier.__align = (long long int) in_share_buffer_buffer_barrier;
      // typedef struct {
      //        volatile int __val[4*sizeof(long)/sizeof(int)];
      //        } sem_t;
      //
      // typedef union
      //        {
      //          char __size[__SIZEOF_SEM_T];
      //            long long int __align;
      //            } sem_t;

      struct timeval start, end;
      gettimeofday(&start, NULL);
      TEEC_FinalizeContext(contextIns);
      gettimeofday(&end, NULL);
      uint32_t cost = 0;
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);

      printf("Teec FinalizeContext executed, cost time: %ld us \n", cost);

      fd = contextIns->fd;
      if (contextIns->ta_path != NULL)
      {
         ta_path_size = strlen((const char *) contextIns->ta_path);
         ta_path = contextIns->ta_path;
      } else
      {
         ta_path_size = 0;
         ta_path = NULL;
      }
      charp = ta_path;
      session_list_next = (dbus_uint64_t) contextIns->session_list.next;
      session_list_prev = (dbus_uint64_t) contextIns->session_list.prev;
      shrd_mem_list_next = (dbus_uint64_t) contextIns->shrd_mem_list.next;
      shrd_mem_list_prev = (dbus_uint64_t) contextIns->shrd_mem_list.prev;
      share_buffer_buffer = (dbus_uint64_t) contextIns->share_buffer.buffer;
      share_buffer_buffer_barrier = contextIns->share_buffer.buffer_barrier.__align;

      tcn_t *tcnTemp;
      tcnTemp = tcnIns->prev;
      if (tcnTemp != NULL)
      {
         tcnTemp->next = tcnIns->next;
      }
      tcnTemp = tcnIns->next;
      if (tcnTemp != NULL)
      {
         tcnTemp->prev = tcnIns->prev;
      }
      pthread_mutex_lock(mutex_tcl);
      if (tcl->last == tcnIns)
      {
         tcl->last = tcnIns->prev;
      }
      if (tcl->first == tcnIns)
      {
         tcl->first = tcnIns->next;
      }
      tcl->count = tcl->count - 1;
      pthread_mutex_unlock(mutex_tcl);
      free(contextIns);
      free(tcnIns);
   }
   ////////////////////////////////////////////////////////////////////////////////////////////////
#else
                                                                                                                           ta_path = (unsigned char *)malloc(1024 * sizeof(char));
    ta_path_size = 1024;
    memset((char *)ta_path, 0, 1024);
    uint32_t context_tapath_outsize;

    char workername[1024];
    memset((char *)workername, 0, 1024);
    int ifound = 0;
    int iworker;

    pthread_mutex_lock(mutex_workerrec);
    for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
    {
       if (workerrec[iworker].context_fd == in_fd &&
           workerrec[iworker].context_addr == in_context_addr
          )
       {
          sprintf(workername, "%s%d", "gpworker", iworker);
	  ifound = 1;
	  break;
       }
    }
    pthread_mutex_unlock(mutex_workerrec);

    if (ifound == 0)
    {
       printf("Can't find the worker for the context. \n");

       // teecresult = 0xAAAA0017;

       fd = 0;
       ta_path_size = 0;
       charp = NULL;
       session_list_prev = 0;
       shrd_mem_list_next = 0;
       shrd_mem_list_prev = 0;
       share_buffer_buffer = 0;
       share_buffer_buffer_barrier = 0;
    }
    else
   {
    pthread_mutex_unlock(mutex_workerrec);
    sin_t * sinIns = NULL;
    sin_t * sinInsPrev = NULL;
    sinIns = workerrec[iworker].last;
    if (sinIns != NULL)
    {
       dbus_uint32_t in_session_seesionid;
       dbus_uint32_t in_session_serviceid_timelow = 0;
       dbus_uint32_t in_session_serviceid_timemid = 0;
       dbus_uint32_t in_session_serviceid_timehiandver = 0;
       dbus_uint32_t in_session_serviceid_clockseqandnode_size = 8;
       dbus_uint32_t in_session_serviceid_clockseqandnode[8];
       dbus_uint32_t in_session_opscnt = 0;
       dbus_uint64_t in_session_head_next = 0;
       dbus_uint64_t in_session_head_prev = 0;
       dbus_uint64_t in_session_context;

       dbus_uint32_t seesionid;
       dbus_uint32_t serviceid_timelow;
       dbus_uint32_t serviceid_timemid;
       dbus_uint32_t serviceid_timehiandver;
       dbus_uint32_t * serviceid_clockseqandnode;
       int           serviceid_clockseqandnode_realsize;
       dbus_uint32_t opscnt;
       dbus_uint64_t head_next;
       dbus_uint64_t head_prev;
       dbus_uint64_t context;

       for ( ; ; )
       {
          in_session_seesionid = sinIns->session_id;
          in_session_context = workerrec[iworker].context_addr;

          pthread_mutex_unlock(mutex_workerrec);

	  for (int iind = 0; iind < 8; iind++)
	  {
             in_session_serviceid_clockseqandnode[iind] = 0;
          }

	  uint32_t serviceid_clockseqandnode_outsize_temp;
          serviceid_clockseqandnode_realsize = 8;
          serviceid_clockseqandnode =
             (dbus_uint32_t *)malloc(
                serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
             );

          printf("\nMethod call teec closesession. (Called by Proxy before fin context) \n");

      	  method_call_teec_closesession(
             workername,

             in_session_seesionid,
             in_session_serviceid_timelow,
             in_session_serviceid_timemid,
             in_session_serviceid_timehiandver,
             in_session_serviceid_clockseqandnode,
             in_session_serviceid_clockseqandnode_size,
             in_session_opscnt,
             in_session_head_next,
             in_session_head_prev,
             in_session_context,

             &seesionid,
             &serviceid_timelow,
             &serviceid_timemid,
             &serviceid_timehiandver,
             serviceid_clockseqandnode,
             serviceid_clockseqandnode_realsize,
             &serviceid_clockseqandnode_outsize_temp,
             &opscnt,
             &head_next,
             &head_prev,
             &context
          );

          if (serviceid_clockseqandnode != NULL) {
             free(serviceid_clockseqandnode);
	  }

     	  pthread_mutex_lock(mutex_workerrec);

          sinInsPrev = sinIns->prev;
	  free(sinIns);
	  if (sinInsPrev == NULL)
          // if (sinIns == workerrec[iworker].first)
          {
	     // free(sinIns);
             break;
          }
          sinIns = sinInsPrev;
       }
    }
    pthread_mutex_unlock(mutex_workerrec);

    method_call_teec_fincont(
		workername,

                in_fd,
                in_ta_path,
		in_ta_path_size,
                in_session_list_next,
                in_session_list_prev,
                in_shrd_mem_list_next,
                in_shrd_mem_list_prev,
                in_share_buffer_buffer,
                in_share_buffer_buffer_barrier,
		in_context_addr,

                &fd,
                ta_path,
	  	ta_path_size,
                &session_list_next,
                &session_list_prev,
                &shrd_mem_list_next,
                &shrd_mem_list_prev,
                &share_buffer_buffer,
                &share_buffer_buffer_barrier,

                &context_tapath_outsize
               );

    pthread_mutex_lock(mutex_workerrec);
    workerrec[iworker].busy = 0;
    pthread_cond_signal(cond_notbusy);
    workerrec[iworker].context_fd = 0;
    workerrec[iworker].context_addr = 0xffffffff;
    workerrec[iworker].sessionid_count = 0;
    workerrec[iworker].first = NULL;
    workerrec[iworker].last = NULL;
    pthread_mutex_unlock(mutex_workerrec);

    if (ta_path_size >= context_tapath_outsize) {
      ta_path_size = context_tapath_outsize;
      charp = ta_path;
    }
    else
    {
      ta_path_size = 0;
      charp = NULL;
    }

   } // end of else found == 1
   ////////////////////////////////////////////////////////////////////////////////////////////////

#endif

   // create a reply from the message
   reply = dbus_message_new_method_return(msg);

   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &fd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   // DBusError err;
   // initialise the errors
   // dbus_error_init(&err);

   if (ta_path_size > 0 &&
       charp != NULL
      // && strlen((const char *) charp) > 0
         )
   {
      // if (dbus_validate_utf8((const char *) charp, &err) == true)
      if (dbus_validate_path((const char *) charp, &err) == true)
      {
         ta_path_size = strlen((const char *) charp);
      } else
      {
         ta_path_size = 0;
      }
   } else
   {
      ta_path_size = 0;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &ta_path_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   fprintf(stderr, "%s %d: reply fincont, tapath size = %d \n", __FILE__, __LINE__, ta_path_size);
   if (ta_path_size > 0)
   {
      fprintf(stderr, "%s %d: reply fincont, tapath = %s \n", __FILE__, __LINE__, charp);

      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &charp
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_message_unref(reply);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &session_list_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &session_list_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &shrd_mem_list_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &shrd_mem_list_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &share_buffer_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT64,
               &share_buffer_buffer_barrier
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send the reply && flush the connection
   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   // dbus_connection_close(conn);
   // dbus_connection_unref(conn);
   free(thdfargs);

   // sleep(2);

#if 0
                                                                                                                           #ifdef GP_WORKER

#else
   if (ta_path == NULL)
   {
      free(ta_path);
   }
#endif
#endif

   return NULL;
}


void *
reply_to_method_call_teec_opensession(
      void *thdfargs
)
{
   DBusMsgConn *DBusMCP;
   DBusMessage *msg;
   DBusConnection *conn;
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   DBusMessageIter ArrayIter;
   int iType;
   unsigned char *charp;
   char buf[2];
   buf[0] = DBUS_TYPE_UINT32;
   buf[1] = '\0';

   // char* param = "";
   dbus_int32_t in_fd;
   unsigned char *in_ta_path = NULL;
   dbus_int32_t in_ta_path_size;
   dbus_uint64_t in_session_list_next;
   dbus_uint64_t in_session_list_prev;
   dbus_uint64_t in_shrd_mem_list_next;
   dbus_uint64_t in_shrd_mem_list_prev;
   dbus_uint64_t in_share_buffer_buffer;
   dbus_int64_t in_share_buffer_buffer_barrier;
   dbus_uint32_t teecresult;
   dbus_int32_t fd;

   dbus_uint32_t in_destination_timelow;
   dbus_uint32_t in_destination_timemid;
   dbus_uint32_t in_destination_timehiandver;

   dbus_uint32_t in_connectionmethod;
   dbus_uint64_t in_connectiondata;
   dbus_uint32_t in_operation_started;
   dbus_uint32_t in_operation_paramtypes;
   dbus_int32_t in_destination_clockseqandnode_size;
   int in_destination_clockseqandnode_realsize;
   dbus_uint32_t *in_destination_clockseqandnode;

   dbus_uint64_t in_operation_param1_tmpref_buffer;
   dbus_uint32_t in_operation_param1_tmpref_size;
   dbus_uint64_t in_operation_param1_memref_parent;
   dbus_uint32_t in_operation_param1_memref_size;
   dbus_uint32_t in_operation_param1_memref_offset;
   dbus_uint32_t in_operation_param1_value_a;
   dbus_uint32_t in_operation_param1_value_b;
   dbus_int32_t in_operation_param1_ionref_ionsharefd;
   dbus_uint32_t in_operation_param1_ionref_ionsize;

   dbus_uint64_t in_operation_param2_tmpref_buffer;
   dbus_uint32_t in_operation_param2_tmpref_size;
   dbus_uint64_t in_operation_param2_memref_parent;
   dbus_uint32_t in_operation_param2_memref_size;
   dbus_uint32_t in_operation_param2_memref_offset;
   dbus_uint32_t in_operation_param2_value_a;
   dbus_uint32_t in_operation_param2_value_b;
   dbus_int32_t in_operation_param2_ionref_ionsharefd;
   dbus_uint32_t in_operation_param2_ionref_ionsize;

   dbus_uint64_t in_operation_param3_tmpref_buffer;
   dbus_uint32_t in_operation_param3_tmpref_size;
   dbus_uint64_t in_operation_param3_memref_parent;
   dbus_uint32_t in_operation_param3_memref_size;
   dbus_uint32_t in_operation_param3_memref_offset;
   dbus_uint32_t in_operation_param3_value_a;
   dbus_uint32_t in_operation_param3_value_b;
   dbus_int32_t in_operation_param3_ionref_ionsharefd;
   dbus_uint32_t in_operation_param3_ionref_ionsize;

   dbus_uint64_t in_operation_param4_tmpref_buffer;
   dbus_uint32_t in_operation_param4_tmpref_size;
   dbus_uint64_t in_operation_param4_memref_parent;
   dbus_uint32_t in_operation_param4_memref_size;
   dbus_uint32_t in_operation_param4_memref_offset;
   dbus_uint32_t in_operation_param4_value_a;
   dbus_uint32_t in_operation_param4_value_b;
   dbus_int32_t in_operation_param4_ionref_ionsharefd;
   dbus_uint32_t in_operation_param4_ionref_ionsize;

   dbus_uint64_t in_operation_session;
   dbus_int32_t in_operation_cancelflag;
   dbus_uint32_t in_returnorigin;

   dbus_uint64_t in_context_addr;

   // unsigned char ta_path[] = "/vendor/bin/rsa_demo_ta";
   // dbus_int32_t  ta_path_size = strlen((const char *)ta_path);
   unsigned char *ta_path;
   dbus_int32_t ta_path_size;
   dbus_uint64_t session_list_next;
   dbus_uint64_t session_list_prev;
   dbus_uint64_t shrd_mem_list_next;
   dbus_uint64_t shrd_mem_list_prev;
   dbus_uint64_t share_buffer_buffer;
   dbus_int64_t share_buffer_buffer_barrier;

   dbus_uint32_t seesionid;
   dbus_uint32_t serviceid_timelow;
   dbus_uint32_t serviceid_timemid;
   dbus_uint32_t serviceid_timehiandver;
   dbus_uint32_t *serviceid_clockseqandnode;
   int serviceid_clockseqandnode_realsize;
   dbus_int32_t serviceid_clockseqandnode_outsize;
   dbus_uint32_t opscnt;
   dbus_uint64_t head_next;
   dbus_uint64_t head_prev;
   dbus_uint64_t context;

   dbus_uint32_t started;
   dbus_uint32_t paramtypes;

   dbus_uint64_t operation_param1_tmpref_buffer;
   dbus_uint32_t operation_param1_tmpref_size;
   dbus_uint64_t operation_param1_memref_parent;
   dbus_uint32_t operation_param1_memref_size;
   dbus_uint32_t operation_param1_memref_offset;
   dbus_uint32_t operation_param1_value_a;
   dbus_uint32_t operation_param1_value_b;
   dbus_int32_t operation_param1_ionref_ionsharefd;
   dbus_uint32_t operation_param1_ionref_ionsize;

   dbus_uint64_t operation_param2_tmpref_buffer;
   dbus_uint32_t operation_param2_tmpref_size;
   dbus_uint64_t operation_param2_memref_parent;
   dbus_uint32_t operation_param2_memref_size;
   dbus_uint32_t operation_param2_memref_offset;
   dbus_uint32_t operation_param2_value_a;
   dbus_uint32_t operation_param2_value_b;
   dbus_int32_t operation_param2_ionref_ionsharefd;
   dbus_uint32_t operation_param2_ionref_ionsize;

   dbus_uint64_t operation_param3_tmpref_buffer;
   dbus_uint32_t operation_param3_tmpref_size;
   dbus_uint64_t operation_param3_memref_parent;
   dbus_uint32_t operation_param3_memref_size;
   dbus_uint32_t operation_param3_memref_offset;
   dbus_uint32_t operation_param3_value_a;
   dbus_uint32_t operation_param3_value_b;
   dbus_int32_t operation_param3_ionref_ionsharefd;
   dbus_uint32_t operation_param3_ionref_ionsize;

   dbus_uint64_t operation_param4_tmpref_buffer;
   dbus_uint32_t operation_param4_tmpref_size;
   dbus_uint64_t operation_param4_memref_parent;
   dbus_uint32_t operation_param4_memref_size;
   dbus_uint32_t operation_param4_memref_offset;
   dbus_uint32_t operation_param4_value_a;
   dbus_uint32_t operation_param4_value_b;
   dbus_int32_t operation_param4_ionref_ionsharefd;
   dbus_uint32_t operation_param4_ionref_ionsize;

   dbus_uint64_t operation_session;
   dbus_int32_t operation_cancelflag;
   dbus_uint32_t returnorigin;
   dbus_uint32_t serial = 0;

#ifdef GP_PROXY
                                                                                                                           pthread_mutex_t * mutex_workerrec;
   wr_t * workerrec;
#endif

#ifdef GP_WORKER
   pthread_mutex_t *mutex_tcl;
   pthread_mutex_t *mutex_tsl;
   tcl_t *tcl;
   tsl_t *tsl;
#endif

   DBusMCP = (DBusMsgConn *) thdfargs;
   msg = DBusMCP->msg;
   conn = DBusMCP->conn;
#ifdef GP_PROXY
                                                                                                                           mutex_workerrec = DBusMCP->mutex_workerrec;
   workerrec = DBusMCP->workerrec;
#endif
#ifdef GP_WORKER
   mutex_tcl = DBusMCP->mutex_tcl;
   mutex_tsl = DBusMCP->mutex_tsl;
   tcl = DBusMCP->tcl;
   tsl = DBusMCP->tsl;
#endif

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_get_basic(
         &structIter,
         &in_fd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_ta_path_size
   );

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   // fprintf(stderr, "Debug in_ta_path_size = %d \n", in_ta_path_size);
   if (in_ta_path_size > 0)
   {
      iType =
            dbus_message_iter_get_arg_type(
                  &structIter
            );
      if (
            iType != DBUS_TYPE_STRING
            )
      {
         fprintf(stderr, "Argument is not STRING.\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &in_ta_path);

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_list_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_list_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_shrd_mem_list_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_shrd_mem_list_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_share_buffer_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT64
         )
   {
      fprintf(stderr, "Argument is not INT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_share_buffer_buffer_barrier);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_destination_timelow);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_destination_timemid);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_destination_timehiandver);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_destination_clockseqandnode_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (in_destination_clockseqandnode_size > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_destination_clockseqandnode,
            &in_destination_clockseqandnode_realsize
      );

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_get_basic(
         &structIter,
         &in_connectionmethod);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_connectiondata);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_started);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_paramtypes);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_tmpref_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_parent);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_size);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_value_a);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_value_b);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_tmpref_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_parent);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_value_a);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_value_b);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_tmpref_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_parent);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_value_a);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_value_b);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_tmpref_buffer);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_parent);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_size);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_value_a);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_value_b);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_session);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_cancelflag);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_returnorigin);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_context_addr);

   printf("Received method call Teec Open Session: \n");
   printf("   in_fd                       = 0x %8.8x \n", in_fd);
   printf("   in_ta_path                  = %s \n", in_ta_path);
   printf("   in_ta_path_size             = %d \n", in_ta_path_size);
#if 0
                                                                                                                           printf("   in_session_list_next                  = 0x %16.16lx \n", in_session_list_next);
    printf("   in_session_list_prev                  = 0x %16.16lx \n", in_session_list_prev);
    printf("   in_shrd_mem_list_next                 = 0x %16.16lx \n", in_shrd_mem_list_next);
    printf("   in_shrd_mem_list_prev                 = 0x %16.16lx \n", in_shrd_mem_list_prev);
    printf("   in_share_buffer_buffer                = 0x %16.16lx \n", in_share_buffer_buffer);
    printf("   in_share_buffer_buffer_barrier        = 0x %16.16lx \n", in_share_buffer_buffer_barrier);

    printf("   in_destination_timelow                = 0x %8.8x \n", in_destination_timelow);
    printf("   in_destination_timemid                = 0x %8.8x \n", in_destination_timemid);
    printf("   in_destination_timehiandver           = 0x %8.8x \n", in_destination_timehiandver);
    if ( in_destination_clockseqandnode_realsize > 0 )
    {
       printf("   in_destination_clockseqandnode        = \n");
       printf("   ");
       for (int i = 0; i < in_destination_clockseqandnode_realsize; i++) {
          printf(" %8.8x", in_destination_clockseqandnode[i]);
       }
       printf("\n");
    }
    else
    {
       printf("   in_destination_clockseqandnode addr   = 0x %16.16lx \n",
	      (long unsigned int)in_destination_clockseqandnode
	     );
    }
    printf("   in_destination_clockseqandnode_size   = 0x %8.8x \n", in_destination_clockseqandnode_size);

    printf("   in_connectionmethod                   = 0x %8.8x \n", in_connectionmethod);
    printf("   in_connectiondata                     = 0x %16.16lx \n", in_connectiondata);

    printf("   in_operation_started                  = 0x %8.8x \n", in_operation_started);
    printf("   in_operation_paramtypes               = 0x %8.8x \n", in_operation_paramtypes);

    printf("   in_operation_param1_tmpref_buffer     = 0x %16.16lx \n", in_operation_param1_tmpref_buffer);
    printf("   in_operation_param1_tmpref_size       = 0x %8.8x \n", in_operation_param1_tmpref_size);
    printf("   in_operation_param1_memref_parent     = 0x %16.16lx \n", in_operation_param1_memref_parent);
    printf("   in_operation_param1_memref_size       = 0x %8.8x \n", in_operation_param1_memref_size);
    printf("   in_operation_param1_memref_offset     = 0x %8.8x \n", in_operation_param1_memref_offset);
    printf("   in_operation_param1_value_a           = 0x %8.8x \n", in_operation_param1_value_a);
    printf("   in_operation_param1_value_b           = 0x %8.8x \n", in_operation_param1_value_b);
    printf("   in_operation_param1_ionref_ionsharefd = 0x %8.8x \n",
		    in_operation_param1_ionref_ionsharefd);
    printf("   in_operation_param1_ionref_ionsize    = 0x %8.8x \n", in_operation_param1_ionref_ionsize);

    printf("   in_operation_param2_tmpref_buffer     = 0x %16.16lx \n", in_operation_param2_tmpref_buffer);
    printf("   in_operation_param2_tmpref_size       = 0x %8.8x \n", in_operation_param2_tmpref_size);
    printf("   in_operation_param2_memref_parent     = 0x %16.16lx \n", in_operation_param2_memref_parent);
    printf("   in_operation_param2_memref_size       = 0x %8.8x \n", in_operation_param2_memref_size);
    printf("   in_operation_param2_memref_offset     = 0x %8.8x \n", in_operation_param2_memref_offset);
    printf("   in_operation_param2_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
    printf("   in_operation_param2_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
    printf("   in_operation_param2_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
    printf("   in_operation_param2_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

    printf("   in_operation_param3_tmpref_buffer     = 0x %16.16lx \n", in_operation_param3_tmpref_buffer);
    printf("   in_operation_param3_tmpref_size       = 0x %8.8x \n", in_operation_param3_tmpref_size);
    printf("   in_operation_param3_memref_parent     = 0x %16.16lx \n", in_operation_param3_memref_parent);
    printf("   in_operation_param3_memref_size       = 0x %8.8x \n", in_operation_param3_memref_size);
    printf("   in_operation_param3_memref_offset     = 0x %8.8x \n", in_operation_param3_memref_offset);
    printf("   in_operation_param3_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
    printf("   in_operation_param3_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
    printf("   in_operation_param3_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
    printf("   in_operation_param3_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

    printf("   in_operation_param4_tmpref_buffer     = 0x %16.16lx \n", in_operation_param4_tmpref_buffer);
    printf("   in_operation_param4_tmpref_size       = 0x %8.8x \n", in_operation_param4_tmpref_size);
    printf("   in_operation_param4_memref_parent     = 0x %16.16lx \n", in_operation_param4_memref_parent);
    printf("   in_operation_param4_memref_size       = 0x %8.8x \n", in_operation_param4_memref_size);
    printf("   in_operation_param4_memref_offset     = 0x %8.8x \n", in_operation_param4_memref_offset);
    printf("   in_operation_param4_value_a           = 0x %8.8x \n", in_operation_param4_value_a);
    printf("   in_operation_param4_value_b           = 0x %8.8x \n", in_operation_param4_value_b);
    printf("   in_operation_param4_ionref_ionsharefd = 0x %8.8x \n", in_operation_param4_ionref_ionsharefd);
    printf("   in_operation_param4_ionref_ionsize    = 0x %8.8x \n", in_operation_param4_ionref_ionsize);

    printf("   in_operation_session                  = 0x %16.16lx \n", in_operation_session);
    printf("   in_operation_cancelflag               = 0x %8.8x \n", in_operation_cancelflag);

    printf("   in_returnorigin                       = 0x %8.8x \n", in_returnorigin);
#endif
   printf("   in_context_addr             = 0x %16.16lx \n", in_context_addr);

#ifdef GP_WORKER
   ////////////////////////////////////////////////////////////////////////////////////////////////

   TEEC_Context *contextIns;
   tcn_t *tcnIns;

   TEEC_UUID destinationIns;
   void *in_connectiondata_temp;
   TEEC_Operation operationIns;
   uint32_t origin;
   TEEC_Result result;

   contextIns = NULL;
   pthread_mutex_lock(mutex_tcl);
   if (tcl->first != NULL)
   {
      tcnIns = tcl->first;
      do
      {
         if (tcnIns->self->fd == in_fd)
         {
            contextIns = tcnIns->self;
            break;
         }
         tcnIns = tcnIns->next;
      } while (tcnIns != NULL);
   }
   pthread_mutex_unlock(mutex_tcl);

   if (contextIns == NULL)
   {
      if (tcl->first == NULL)
      {
         printf("The teec context list is null. \n");
         teecresult = TEEC_ERROR_CONTEXT_LIST_NULL;
      } else
      {
         printf("Can't find the teec context. \n");
         teecresult = TEEC_ERROR_NO_CONTEXT_MATCH;
      }

      fd = 0;
      ta_path_size = 0;
      ta_path = NULL;
      charp = ta_path;
      session_list_next = 0;
      session_list_prev = 0;
      shrd_mem_list_next = 0;
      shrd_mem_list_prev = 0;
      share_buffer_buffer = 0;
      share_buffer_buffer_barrier = 0;

      seesionid = 0;
      serviceid_timelow = 0;
      serviceid_timemid = 0;
      serviceid_timehiandver = 0;
      serviceid_clockseqandnode_realsize = 0;
      serviceid_clockseqandnode = NULL;
      serviceid_clockseqandnode_outsize = 0;
      opscnt = 0;
      head_next = 0;
      head_prev = 0;
      context = 0;

      started = 0;
      paramtypes = 0;

      operation_param1_tmpref_buffer = 0;
      operation_param1_tmpref_size = 0;
      operation_param1_memref_parent = 0;
      operation_param1_memref_size = 0;
      operation_param1_memref_offset = 0;
      operation_param1_value_a = 0;
      operation_param1_value_b = 0;
      operation_param1_ionref_ionsharefd = 0;
      operation_param1_ionref_ionsize = 0;

      operation_param2_tmpref_buffer = 0;
      operation_param2_tmpref_size = 0;
      operation_param2_memref_parent = 0;
      operation_param2_memref_size = 0;
      operation_param2_memref_offset = 0;
      operation_param2_value_a = 0;
      operation_param2_value_b = 0;
      operation_param2_ionref_ionsharefd = 0;
      operation_param2_ionref_ionsize = 0;

      operation_param3_tmpref_buffer = 0;
      operation_param3_tmpref_size = 0;
      operation_param3_memref_parent = 0;
      operation_param3_memref_size = 0;
      operation_param3_memref_offset = 0;
      operation_param3_value_a = 0;
      operation_param3_value_b = 0;
      operation_param3_ionref_ionsharefd = 0;
      operation_param3_ionref_ionsize = 0;

      operation_param4_tmpref_buffer = 0;
      operation_param4_tmpref_size = 0;
      operation_param4_memref_parent = 0;
      operation_param4_memref_size = 0;
      operation_param4_memref_offset = 0;
      operation_param4_value_a = 0;
      operation_param4_value_b = 0;
      operation_param4_ionref_ionsharefd = 0;
      operation_param4_ionref_ionsize = 0;

      operation_session = 0;
      operation_cancelflag = 0;

      returnorigin = 0;
   } else
   {
      TEEC_Session *sessionIns = (TEEC_Session *) malloc(sizeof(TEEC_Session));

      // contextIns->fd = in_fd;
      contextIns->ta_path = in_ta_path;
      // typedef struct {
      //        volatile int __val[4*sizeof(long)/sizeof(int)];
      //        } sem_t;
      //
      // typedef union
      //        {
      //          char __size[__SIZEOF_SEM_T];
      //            long long int __align;
      //            } sem_t;

      destinationIns.timeLow = in_destination_timelow;
      destinationIns.timeMid = in_destination_timemid;
      destinationIns.timeHiAndVersion = in_destination_timehiandver;
      for (int i = 0;
           i < in_destination_clockseqandnode_size;
           i++)
      {
         destinationIns.clockSeqAndNode[i] = in_destination_clockseqandnode[i];
      }

      in_connectiondata_temp = (void *) in_connectiondata;
      // in_connectiondata_temp = NULL;


      memset(&operationIns, 0, sizeof(operationIns));
      operationIns.started = in_operation_started;
      operationIns.paramTypes = in_operation_paramtypes;

      origin = in_returnorigin;

      struct timeval start, end;
      gettimeofday(&start, NULL);
      result =
            TEEC_OpenSession(
                  contextIns,
                  sessionIns,
                  &destinationIns,
                  in_connectionmethod,
                  in_connectiondata_temp, // NULL
                  &operationIns,
                  &origin
            );
      gettimeofday(&end, NULL);
      uint32_t cost = 0;
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);

      if (result != TEEC_SUCCESS)
      {
         printf("Teec OpenSession Failed. \n");
         printf("   teecresult                  = 0x %8.8x.\n", result);

         teecresult = result;

         fd = 0;
         ta_path_size = 0;
         ta_path = NULL;
         charp = ta_path;
         session_list_next = 0;
         session_list_prev = 0;
         shrd_mem_list_next = 0;
         shrd_mem_list_prev = 0;
         share_buffer_buffer = 0;
         share_buffer_buffer_barrier = 0;

         seesionid = 0;
         serviceid_timelow = 0;
         serviceid_timemid = 0;
         serviceid_timehiandver = 0;
         serviceid_clockseqandnode_realsize = 0;
         serviceid_clockseqandnode = NULL;
         serviceid_clockseqandnode_outsize = 0;
         opscnt = 0;
         head_next = 0;
         head_prev = 0;
         context = 0;

         started = 0;
         paramtypes = 0;

         operation_param1_tmpref_buffer = 0;
         operation_param1_tmpref_size = 0;
         operation_param1_memref_parent = 0;
         operation_param1_memref_size = 0;
         operation_param1_memref_offset = 0;
         operation_param1_value_a = 0;
         operation_param1_value_b = 0;
         operation_param1_ionref_ionsharefd = 0;
         operation_param1_ionref_ionsize = 0;

         operation_param2_tmpref_buffer = 0;
         operation_param2_tmpref_size = 0;
         operation_param2_memref_parent = 0;
         operation_param2_memref_size = 0;
         operation_param2_memref_offset = 0;
         operation_param2_value_a = 0;
         operation_param2_value_b = 0;
         operation_param2_ionref_ionsharefd = 0;
         operation_param2_ionref_ionsize = 0;

         operation_param3_tmpref_buffer = 0;
         operation_param3_tmpref_size = 0;
         operation_param3_memref_parent = 0;
         operation_param3_memref_size = 0;
         operation_param3_memref_offset = 0;
         operation_param3_value_a = 0;
         operation_param3_value_b = 0;
         operation_param3_ionref_ionsharefd = 0;
         operation_param3_ionref_ionsize = 0;

         operation_param4_tmpref_buffer = 0;
         operation_param4_tmpref_size = 0;
         operation_param4_memref_parent = 0;
         operation_param4_memref_size = 0;
         operation_param4_memref_offset = 0;
         operation_param4_value_a = 0;
         operation_param4_value_b = 0;
         operation_param4_ionref_ionsharefd = 0;
         operation_param4_ionref_ionsize = 0;

         operation_session = 0;
         operation_cancelflag = 0;

         returnorigin = 0;
      } else
      {
         printf("Teec OpenSession Succed, cost time: %ld us \n", cost);

         tsn_t *tsnIns = (tsn_t *) malloc(sizeof(tsn_t));
         tsnIns->self = sessionIns;
         struct timeval tvcreate;
         gettimeofday(&tvcreate, NULL);
         tsnIns->createtime = tvcreate;
         pthread_mutex_lock(mutex_tsl);
         if (tsl->first == NULL)
         {
            tsnIns->next = NULL;
            tsnIns->prev = NULL;
            tsl->first = tsnIns;
            tsl->last = tsnIns;
            tsl->count = 1;
         } else
         {
            tsnIns->prev = tsl->last;
            tsnIns->next = NULL;
            tsl->last->next = tsnIns;
            tsl->last = tsnIns;
            tsl->count = tsl->count + 1;
         }
         pthread_mutex_unlock(mutex_tsl);

         teecresult = result;

         fd = contextIns->fd;
         if (contextIns->ta_path != NULL)
         {
            ta_path_size = strlen((const char *) contextIns->ta_path);
         } else
         {
            ta_path_size = 0;
         }
         ta_path = contextIns->ta_path;
         charp = ta_path;
         session_list_next = (dbus_uint64_t) contextIns->session_list.next;
         session_list_prev = (dbus_uint64_t) contextIns->session_list.prev;
         shrd_mem_list_next = (dbus_uint64_t) contextIns->shrd_mem_list.next;
         shrd_mem_list_prev = (dbus_uint64_t) contextIns->shrd_mem_list.prev;
         share_buffer_buffer = (dbus_uint64_t) contextIns->share_buffer.buffer;
         share_buffer_buffer_barrier = contextIns->share_buffer.buffer_barrier.__align;

         seesionid = sessionIns->session_id;
         serviceid_timelow = sessionIns->service_id.timeLow;
         serviceid_timemid = sessionIns->service_id.timeMid;
         serviceid_timehiandver = sessionIns->service_id.timeHiAndVersion;
         if (sessionIns->service_id.clockSeqAndNode != NULL)
         {
            serviceid_clockseqandnode_realsize = 8;
            serviceid_clockseqandnode =
                  (dbus_uint32_t *) malloc(
                        serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
                  );
            for (int iind = 0; iind < 8; iind++)
            {
               uint8_t u8Temp;
               u8Temp = sessionIns->service_id.clockSeqAndNode[iind];
               serviceid_clockseqandnode[iind] = (dbus_uint32_t) u8Temp;
            }
            serviceid_clockseqandnode_outsize = 8;
         } else
         {
            serviceid_clockseqandnode_realsize = 0;
            serviceid_clockseqandnode = NULL;
            serviceid_clockseqandnode_outsize = 0;
         }
         opscnt = sessionIns->ops_cnt;
         head_next = (dbus_uint64_t) sessionIns->head.next;
         head_prev = (dbus_uint64_t) sessionIns->head.prev;
         context = (dbus_uint64_t) sessionIns->context;

         started = operationIns.started;
         paramtypes = operationIns.paramTypes;

         operation_param1_tmpref_buffer = (dbus_uint64_t) operationIns.params[0].tmpref.buffer;
         operation_param1_tmpref_size = operationIns.params[0].tmpref.size;
         operation_param1_memref_parent = (dbus_uint64_t) operationIns.params[0].memref.parent;
         operation_param1_memref_size = operationIns.params[0].memref.size;
         operation_param1_memref_offset = operationIns.params[0].memref.offset;
         operation_param1_value_a = operationIns.params[0].value.a;
         operation_param1_value_b = operationIns.params[0].value.b;
         operation_param1_ionref_ionsharefd = operationIns.params[0].ionref.ion_share_fd;
         operation_param1_ionref_ionsize = operationIns.params[0].ionref.ion_size;

         operation_param2_tmpref_buffer = (dbus_uint64_t) operationIns.params[1].tmpref.buffer;
         operation_param2_tmpref_size = operationIns.params[1].tmpref.size;
         operation_param2_memref_parent = (dbus_uint64_t) operationIns.params[1].memref.parent;
         operation_param2_memref_size = operationIns.params[1].memref.size;
         operation_param2_memref_offset = operationIns.params[1].memref.offset;
         operation_param2_value_a = operationIns.params[1].value.a;
         operation_param2_value_b = operationIns.params[1].value.b;
         operation_param2_ionref_ionsharefd = operationIns.params[1].ionref.ion_share_fd;
         operation_param2_ionref_ionsize = operationIns.params[1].ionref.ion_size;

         operation_param3_tmpref_buffer = (dbus_uint64_t) operationIns.params[2].tmpref.buffer;
         operation_param3_tmpref_size = operationIns.params[2].tmpref.size;
         operation_param3_memref_parent = (dbus_uint64_t) operationIns.params[2].memref.parent;
         operation_param3_memref_size = operationIns.params[2].memref.size;
         operation_param3_memref_offset = operationIns.params[2].memref.offset;
         operation_param3_value_a = operationIns.params[2].value.a;
         operation_param3_value_b = operationIns.params[2].value.b;
         operation_param3_ionref_ionsharefd = operationIns.params[2].ionref.ion_share_fd;
         operation_param3_ionref_ionsize = operationIns.params[2].ionref.ion_size;

         operation_param4_tmpref_buffer = (dbus_uint64_t) operationIns.params[3].tmpref.buffer;
         operation_param4_tmpref_size = operationIns.params[3].tmpref.size;
         operation_param4_memref_parent = (dbus_uint64_t) operationIns.params[3].memref.parent;
         operation_param4_memref_size = operationIns.params[3].memref.size;
         operation_param4_memref_offset = operationIns.params[3].memref.offset;
         operation_param4_value_a = operationIns.params[3].value.a;
         operation_param4_value_b = operationIns.params[3].value.b;
         operation_param4_ionref_ionsharefd = operationIns.params[3].ionref.ion_share_fd;
         operation_param4_ionref_ionsize = operationIns.params[3].ionref.ion_size;

         operation_session = (dbus_uint64_t) operationIns.session;
         operation_cancelflag = operationIns.cancel_flag;

         returnorigin = origin;

         printf("   ret sessionid               = 0x %8.8x \n", seesionid);
         printf("   ret context                 = 0x %16.16lx \n", context);

#if 0
                                                                                                                                 printf("Call TEEC_CloseSession inputs: \n");
       printf("   session_seesionid                        = 0x %8.8x \n", sessionIns->session_id);
       printf("   session_serviceid_timelow                = 0x %8.8x \n", sessionIns->service_id.timeLow);
       printf("   session_serviceid_timemid                = 0x %4.4x \n", sessionIns->service_id.timeMid);
       printf("   session_serviceid_timehiandver           = 0x %4.4x \n",
              sessionIns->service_id.timeHiAndVersion);
       printf("   session_serviceid_clockseqandnode        = \n");
       printf("   ");
       for (int i = 0; i < 8; i++) {
          printf(" %2.2x", sessionIns->service_id.clockSeqAndNode[i]);
       }
       printf("\n");
       printf("   session_opscnt                           = 0x %8.8x \n", sessionIns->ops_cnt);
       printf("   session_head_next                        = 0x %16.16lx \n", sessionIns->head.next);
       printf("   session_head_prev                        = 0x %16.16lx \n", sessionIns->head.prev);
       printf("   session_context                          = 0x %16.16lx \n", sessionIns->context);

       // TEEC_CloseSession(sessionIns);
       // printf("Teec CloseSession. \n");
#endif
      }
   }
   ////////////////////////////////////////////////////////////////////////////////////////////////
#else
                                                                                                                           ta_path = (unsigned char *)malloc(1024 * sizeof(char));
    ta_path_size = 1024;
    memset((char *)ta_path, 0, 1024);
    uint32_t context_tapath_outsize;
    uint32_t serviceid_clockseqandnode_outsize_temp;
    uint32_t returnorigin_temp;
    serviceid_clockseqandnode_realsize = 8;
    serviceid_clockseqandnode =
       (dbus_uint32_t *)malloc(
                               serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
			      );

    char workername[1024];
    memset((char *)workername, 0, 1024);
    int ifound = 0;
    int iworker;

    pthread_mutex_lock(mutex_workerrec);
    for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
    {
       if (workerrec[iworker].context_fd == in_fd &&
           workerrec[iworker].context_addr == in_context_addr
          )
       {
          sprintf(workername, "%s%d", "gpworker", iworker);
	  ifound = 1;
	  break;
       }
    }
    pthread_mutex_unlock(mutex_workerrec);

    if (ifound == 0)
    {
       printf("Can't find the woker for the context. \n");

       teecresult = 0xAAAA0017;

       fd = 0x0;
       ta_path = NULL;
       charp = ta_path;
       session_list_next = 0x0;
       session_list_prev = 0x0;
       shrd_mem_list_next = 0x0;
       shrd_mem_list_prev = 0x0;
       share_buffer_buffer = 0;
       share_buffer_buffer_barrier = 0x0;

       seesionid = 0x0;
       serviceid_timelow = 0x0;
       serviceid_timemid = 0x0;
       serviceid_timehiandver = 0x0;
       serviceid_clockseqandnode_realsize = 0;
       serviceid_clockseqandnode =
	  (dbus_uint32_t *)malloc(
             serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
	  );
       for (int i = 0; i < serviceid_clockseqandnode_realsize ; i++) {
          serviceid_clockseqandnode[i] = 0x0;
       }
       serviceid_clockseqandnode_outsize = 0;
       opscnt = 0x0;
       head_next = 0x0;
       head_prev = 0x0;
       context = 0x0;

       started = 0x0;
       paramtypes = 0x0;

       operation_param1_tmpref_buffer = 0x0;
       operation_param1_tmpref_size = 0x0;
       operation_param1_memref_parent = 0x0;
       operation_param1_memref_size = 0x0;
       operation_param1_memref_offset = 0x0;
       operation_param1_value_a = 0x0;
       operation_param1_value_b = 0x0;
       operation_param1_ionref_ionsharefd = 0x0;
       operation_param1_ionref_ionsize = 0x0;

       operation_param2_tmpref_buffer = 0x0;
       operation_param2_tmpref_size = 0x0;
       operation_param2_memref_parent = 0x0;
       operation_param2_memref_size = 0x0;
       operation_param2_memref_offset = 0x0;
       operation_param2_value_a = 0x0;
       operation_param2_value_b = 0x0;
       operation_param2_ionref_ionsharefd = 0x0;
       operation_param2_ionref_ionsize = 0x0;

       operation_param3_tmpref_buffer = 0x0;
       operation_param3_tmpref_size = 0x0;
       operation_param3_memref_parent = 0x0;
       operation_param3_memref_size = 0x0;
       operation_param3_memref_offset = 0x0;
       operation_param3_value_a = 0x0;
       operation_param3_value_b = 0x0;
       operation_param3_ionref_ionsharefd = 0x0;
       operation_param3_ionref_ionsize = 0x0;

       operation_param4_tmpref_buffer = 0x0;
       operation_param4_tmpref_size = 0x0;
       operation_param4_memref_parent = 0x0;
       operation_param4_memref_size = 0x0;
       operation_param4_memref_offset = 0x0;
       operation_param4_value_a = 0x0;
       operation_param4_value_b = 0x0;
       operation_param4_ionref_ionsharefd = 0x0;
       operation_param4_ionref_ionsize = 0x0;

       operation_session = 0x0;
       operation_cancelflag = 0x0;

       returnorigin = 0x0;
    }
    else
   {
    method_call_teec_opensession(
       workername,

       in_fd,
       in_ta_path,
       in_ta_path_size,
       in_session_list_next,
       in_session_list_prev,
       in_shrd_mem_list_next,
       in_shrd_mem_list_prev,
       in_share_buffer_buffer,
       in_share_buffer_buffer_barrier,

       in_destination_timelow,
       in_destination_timemid,
       in_destination_timehiandver,
       in_destination_clockseqandnode,
       in_destination_clockseqandnode_realsize,

       in_connectionmethod,
       in_connectiondata,

       in_operation_started,
       in_operation_paramtypes,

       in_operation_param1_tmpref_buffer,
       in_operation_param1_tmpref_size,
       in_operation_param1_memref_parent,
       in_operation_param1_memref_size,
       in_operation_param1_memref_offset,
       in_operation_param1_value_a,
       in_operation_param1_value_b,
       in_operation_param1_ionref_ionsharefd,
       in_operation_param1_ionref_ionsize,

       in_operation_param2_tmpref_buffer,
       in_operation_param2_tmpref_size,
       in_operation_param2_memref_parent,
       in_operation_param2_memref_size,
       in_operation_param2_memref_offset,
       in_operation_param2_value_a,
       in_operation_param2_value_b,
       in_operation_param2_ionref_ionsharefd,
       in_operation_param2_ionref_ionsize,

       in_operation_param3_tmpref_buffer,
       in_operation_param3_tmpref_size,
       in_operation_param3_memref_parent,
       in_operation_param3_memref_size,
       in_operation_param3_memref_offset,
       in_operation_param3_value_a,
       in_operation_param3_value_b,
       in_operation_param3_ionref_ionsharefd,
       in_operation_param3_ionref_ionsize,

       in_operation_param4_tmpref_buffer,
       in_operation_param4_tmpref_size,
       in_operation_param4_memref_parent,
       in_operation_param4_memref_size,
       in_operation_param4_memref_offset,
       in_operation_param4_value_a,
       in_operation_param4_value_b,
       in_operation_param4_ionref_ionsharefd,
       in_operation_param4_ionref_ionsize,

       in_operation_session,
       in_operation_cancelflag,

       in_returnorigin,

       in_context_addr,


       &teecresult,

       &fd,
       ta_path,
       ta_path_size,
       &context_tapath_outsize,
       &session_list_next,
       &session_list_prev,
       &shrd_mem_list_next,
       &shrd_mem_list_prev,
       &share_buffer_buffer,
       &share_buffer_buffer_barrier,

       &seesionid,
       &serviceid_timelow,
       &serviceid_timemid,
       &serviceid_timehiandver,
       serviceid_clockseqandnode,
       serviceid_clockseqandnode_realsize,
       &serviceid_clockseqandnode_outsize_temp,
       &opscnt,
       &head_next,
       &head_prev,
       &context,

       &started,
       &paramtypes,

       &operation_param1_tmpref_buffer,
       &operation_param1_tmpref_size,
       &operation_param1_memref_parent,
       &operation_param1_memref_size,
       &operation_param1_memref_offset,
       &operation_param1_value_a,
       &operation_param1_value_b,
       &operation_param1_ionref_ionsharefd,
       &operation_param1_ionref_ionsize,

       &operation_param2_tmpref_buffer,
       &operation_param2_tmpref_size,
       &operation_param2_memref_parent,
       &operation_param2_memref_size,
       &operation_param2_memref_offset,
       &operation_param2_value_a,
       &operation_param2_value_b,
       &operation_param2_ionref_ionsharefd,
       &operation_param2_ionref_ionsize,

       &operation_param3_tmpref_buffer,
       &operation_param3_tmpref_size,
       &operation_param3_memref_parent,
       &operation_param3_memref_size,
       &operation_param3_memref_offset,
       &operation_param3_value_a,
       &operation_param3_value_b,
       &operation_param3_ionref_ionsharefd,
       &operation_param3_ionref_ionsize,

       &operation_param4_tmpref_buffer,
       &operation_param4_tmpref_size,
       &operation_param4_memref_parent,
       &operation_param4_memref_size,
       &operation_param4_memref_offset,
       &operation_param4_value_a,
       &operation_param4_value_b,
       &operation_param4_ionref_ionsharefd,
       &operation_param4_ionref_ionsize,

       &operation_session,
       &operation_cancelflag,

       &returnorigin_temp
    );

    if (teecresult == 0) {
       pthread_mutex_lock(mutex_workerrec);

       sin_t * sinIns = (sin_t *)malloc(sizeof(sin_t));
       sinIns->session_id = seesionid;
       struct timeval tvcreate;
       gettimeofday(&tvcreate, NULL);
       sinIns->session_createtime = tvcreate;
       if (workerrec[iworker].first == NULL)
       {
          sinIns->next = NULL;
          sinIns->prev = NULL;
          workerrec[iworker].first = sinIns;
          workerrec[iworker].last = sinIns;
          workerrec[iworker].sessionid_count = 1;
       }
       else
       {
          sinIns->prev = workerrec[iworker].last;
          sinIns->next = NULL;
          workerrec[iworker].last->next = sinIns;
          workerrec[iworker].last = sinIns;
          workerrec[iworker].sessionid_count =
             workerrec[iworker].sessionid_count + 1;
       }
       pthread_mutex_unlock(mutex_workerrec);
    }

    serviceid_clockseqandnode_outsize =
       serviceid_clockseqandnode_outsize_temp;
    returnorigin = returnorigin_temp;

    if (ta_path_size >= context_tapath_outsize) {
       ta_path_size = context_tapath_outsize;
       charp = ta_path;
    }
    else
    {
       ta_path_size = 0;
       charp = NULL;
    }

    if (
	serviceid_clockseqandnode_realsize >= serviceid_clockseqandnode_outsize &&
	8 >= serviceid_clockseqandnode_outsize
       )
    {
       serviceid_clockseqandnode_realsize = serviceid_clockseqandnode_outsize;
    }
    else
    {
       serviceid_clockseqandnode_realsize = 0;
       serviceid_clockseqandnode_outsize = 0;
    }

  } // end of else found == 1

    ////////////////////////////////////////////////////////////////////////////////////////////////
#endif


   // create a reply from the message
   reply = dbus_message_new_method_return(msg);

   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &teecresult
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &fd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   DBusError err;
   // initialise the errors
   dbus_error_init(&err);

   if (ta_path_size > 0 &&
       charp != NULL &&
       strlen((const char *) charp) > 0
         )
   {
      if (dbus_validate_utf8((const char *) charp, &err) == true)
      {
         ta_path_size = strlen((const char *) charp);
      } else
      {
         ta_path_size = 0;
      }
   } else
   {
      ta_path_size = 0;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &ta_path_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (ta_path_size > 0)
   {
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &charp
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_message_unref(reply);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &session_list_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &session_list_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &shrd_mem_list_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &shrd_mem_list_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &share_buffer_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT64,
               &share_buffer_buffer_barrier
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &seesionid
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timelow
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timemid
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timehiandver
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_clockseqandnode_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (serviceid_clockseqandnode_outsize > 0 &&
       serviceid_clockseqandnode != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &serviceid_clockseqandnode,
                  serviceid_clockseqandnode_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &opscnt
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &head_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &head_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &context
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &started
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &paramtypes
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param1_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param1_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param1_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param2_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param2_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param2_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param3_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param3_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param3_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param4_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param4_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param4_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_session
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_cancelflag
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &returnorigin
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send the reply && flush the connection
   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_connection_flush(conn);
   dbus_message_unref(msg);
   // dbus_connection_close(conn);
   // dbus_connection_unref(conn);
   free(thdfargs);

   // sleep(2);

#if 0
                                                                                                                           #ifdef GP_WORKER

#else
   if (ta_path == NULL)
   {
      free(ta_path);
   }
   if (serviceid_clockseqandnode == NULL)
   {
      free(serviceid_clockseqandnode);
   }
#endif
#endif

   return NULL;
}


void *
reply_to_method_call_teec_closesession(
      void *thdfargs
)
{
   DBusMsgConn *DBusMCP;
   DBusMessage *msg;
   DBusConnection *conn;
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   DBusMessageIter ArrayIter;
   int iType;
   char buf[2];
   buf[0] = DBUS_TYPE_UINT32;
   buf[1] = '\0';

   dbus_uint32_t in_session_seesionid;
   dbus_uint32_t in_session_serviceid_timelow;
   dbus_uint32_t in_session_serviceid_timemid;
   dbus_uint32_t in_session_serviceid_timehiandver;
   dbus_uint32_t in_session_serviceid_clockseqandnode_size;
   dbus_uint32_t *in_session_serviceid_clockseqandnode;
   int in_session_serviceid_clockseqandnode_realsize;
   dbus_uint32_t in_session_opscnt;
   dbus_uint64_t in_session_head_next;
   dbus_uint64_t in_session_head_prev;
   dbus_uint64_t in_session_context;

   dbus_uint32_t seesionid;
   dbus_uint32_t serviceid_timelow;
   dbus_uint32_t serviceid_timemid;
   dbus_uint32_t serviceid_timehiandver;
   dbus_uint32_t *serviceid_clockseqandnode;
   int serviceid_clockseqandnode_realsize;
   dbus_int32_t serviceid_clockseqandnode_outsize;
   dbus_uint32_t opscnt;
   dbus_uint64_t head_next;
   dbus_uint64_t head_prev;
   dbus_uint64_t context;

   dbus_uint32_t serial = 0;

#ifdef GP_PROXY
                                                                                                                           pthread_mutex_t * mutex_workerrec;
    wr_t * workerrec;
#endif

#ifdef GP_WORKER
   pthread_mutex_t *mutex_tcl;
   pthread_mutex_t *mutex_tsl;
   tcl_t *tcl;
   tsl_t *tsl;
#endif

   DBusMCP = (DBusMsgConn *) thdfargs;
   msg = DBusMCP->msg;
   conn = DBusMCP->conn;
#ifdef GP_PROXY
                                                                                                                           mutex_workerrec = DBusMCP->mutex_workerrec;
    workerrec = DBusMCP->workerrec;
#endif
#ifdef GP_WORKER
   mutex_tcl = DBusMCP->mutex_tcl;
   mutex_tsl = DBusMCP->mutex_tsl;
   tcl = DBusMCP->tcl;
   tsl = DBusMCP->tsl;
#endif

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_get_basic(
         &structIter,
         &in_session_seesionid);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_timelow
   );

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_timemid);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_timehiandver);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_clockseqandnode_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (in_session_serviceid_clockseqandnode_size > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_session_serviceid_clockseqandnode,
            &in_session_serviceid_clockseqandnode_realsize
      );

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_get_basic(
         &structIter,
         &in_session_opscnt);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_head_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_head_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_context);

   printf("Received method call Teec Close Session: \n");
   printf("   in_session_seesionid        = 0x %8.8x \n", in_session_seesionid);
#if 0
                                                                                                                           printf("   in_session_serviceid_timelow                = 0x %8.8x \n", in_session_serviceid_timelow);
    printf("   in_session_serviceid_timemid                = 0x %8.8x \n", in_session_serviceid_timemid);
    printf("   in_session_serviceid_timehiandver           = 0x %8.8x \n",
           in_session_serviceid_timehiandver);
    printf("   in_session_serviceid_clockseqandnode        = \n");
    printf("   ");
    for (int i = 0; i < in_session_serviceid_clockseqandnode_realsize; i++) {
        printf(" %8.8x", in_session_serviceid_clockseqandnode[i]);
    }
    printf("\n");
    printf("   in_session_serviceid_clockseqandnode_size   = 0x %8.8x \n",
	   in_session_serviceid_clockseqandnode_size);
    printf("   in_session_opscnt                           = 0x %8.8x \n", in_session_opscnt);
    printf("   in_session_head_next                        = 0x %16.16lx \n", in_session_head_next);
    printf("   in_session_head_prev                        = 0x %16.16lx \n", in_session_head_prev);
#endif
   printf("   in_session_context          = 0x %16.16lx \n", in_session_context);


#ifdef GP_WORKER
   ////////////////////////////////////////////////////////////////////////////////////////////////

   TEEC_Session *sessionIns;
   tsn_t *tsnIns;

   sessionIns = NULL;
   pthread_mutex_lock(mutex_tsl);
   if (tsl->first != NULL)
   {
      tsnIns = tsl->first;
      do
      {
         if (tsnIns->self->session_id == in_session_seesionid)
         {
            sessionIns = tsnIns->self;
            break;
         }
         tsnIns = tsnIns->next;
      } while (tsnIns != NULL);
   }
   pthread_mutex_unlock(mutex_tsl);

   if (sessionIns == NULL)
   {
      if (tsl->first == NULL)
      {
         printf("The teec session list is null. \n");
         // teecresult = TEEC_ERROR_SESSION_LIST_NULL;
      } else
      {
         printf("Can't find the teec session. \n");
         // teecresult = TEEC_ERROR_NO_SESSION_MATCH;
      }

      seesionid = 0x0;
      serviceid_timelow = 0x0;
      serviceid_timemid = 0x0;
      serviceid_timehiandver = 0x0;
      opscnt = 0x0;
      head_next = 0x0;
      head_prev = 0x0;
      context = 0x0;

      serviceid_clockseqandnode_realsize = 8;
      serviceid_clockseqandnode =
            (dbus_uint32_t *) malloc(
                  serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
            );
      for (int i = 0; i < serviceid_clockseqandnode_realsize; i++)
      {
         serviceid_clockseqandnode[i] = 0x0;
      }
      serviceid_clockseqandnode_outsize = 8;
   } else
   {
      sessionIns->session_id = in_session_seesionid;
#if 0
                                                                                                                              sessionIns->service_id.timeLow = in_session_serviceid_timelow;
    sessionIns->service_id.timeMid = in_session_serviceid_timemid;
    sessionIns->service_id.timeHiAndVersion = in_session_serviceid_timehiandver;
    if ( in_session_serviceid_clockseqandnode_realsize <= 8 &&
         in_session_serviceid_clockseqandnode_realsize > 0 &&
         in_session_serviceid_clockseqandnode != NULL
       )
    {
       for (int i = 0; i < in_session_serviceid_clockseqandnode_realsize; i++) {
          sessionIns->service_id.clockSeqAndNode[i] =
	     (uint8_t)(in_session_serviceid_clockseqandnode[i] & 0x000000ff);
       }
    }
    else
    {
       for (int i = 0; i < 8; i++) {
          sessionIns->service_id.clockSeqAndNode[i] = 0;
       }
    }
    sessionIns->ops_cnt = in_session_opscnt;
    sessionIns->head.next = (struct ListNode *)in_session_head_next;
    sessionIns->head.prev = (struct ListNode *)in_session_head_prev;
    // sessionIns->context = (TEEC_Context *)in_session_context;
#endif

#if 0
                                                                                                                              printf("Call TEEC_CloseSession inputs: \n");
    printf("   session_seesionid                        = 0x %8.8x \n", sessionIns->session_id);
    printf("   session_serviceid_timelow                = 0x %8.8x \n", sessionIns->service_id.timeLow);
    printf("   session_serviceid_timemid                = 0x %4.4x \n", sessionIns->service_id.timeMid);
    printf("   session_serviceid_timehiandver           = 0x %4.4x \n",
           sessionIns->service_id.timeHiAndVersion);
    printf("   session_serviceid_clockseqandnode        = \n");
    printf("   ");
    for (int i = 0; i < 8; i++) {
       printf(" %2.2x", sessionIns->service_id.clockSeqAndNode[i]);
    }
    printf("\n");
    printf("   session_opscnt                           = 0x %8.8x \n", sessionIns->ops_cnt);
    printf("   session_head_next                        = 0x %16.16lx \n", sessionIns->head.next);
    printf("   session_head_prev                        = 0x %16.16lx \n", sessionIns->head.prev);
    printf("   session_context                          = 0x %16.16lx \n", sessionIns->context);
#endif
      struct timeval start, end;
      gettimeofday(&start, NULL);
      TEEC_CloseSession(
            sessionIns
      );
      gettimeofday(&end, NULL);
      uint32_t cost = 0;
      cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);

      printf("Teec CloseSession executed, cost time: %ld us \n", cost);

      seesionid = sessionIns->session_id;
      serviceid_timelow = sessionIns->service_id.timeLow;
      serviceid_timemid = sessionIns->service_id.timeMid;
      serviceid_timehiandver = sessionIns->service_id.timeHiAndVersion;
#if 0
                                                                                                                              printf("   in_session_serviceid_clockseqandnode        = \n");
    printf("   ");
    for (int i = 0; i < 8; i++) {
        printf(" %2.2x", in_session_serviceid_clockseqandnode[i]);
    }
    printf("\n");
#endif
      if (sessionIns->service_id.clockSeqAndNode != NULL)
      {
         serviceid_clockseqandnode_realsize = 8;
         serviceid_clockseqandnode =
               (dbus_uint32_t *) malloc(
                     serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
               );
         for (int iind = 0; iind < 8; iind++)
         {
            uint8_t u8Temp;
            u8Temp = sessionIns->service_id.clockSeqAndNode[iind];
            serviceid_clockseqandnode[iind] = (dbus_uint32_t) u8Temp;
         }
         serviceid_clockseqandnode_outsize = 8;
      } else
      {
         serviceid_clockseqandnode_realsize = 0;
         serviceid_clockseqandnode = NULL;
         serviceid_clockseqandnode_outsize = 0;
      }
      opscnt = sessionIns->ops_cnt;
      head_next = (dbus_uint64_t) sessionIns->head.next;
      head_prev = (dbus_uint64_t) sessionIns->head.prev;
      context = (dbus_uint64_t) sessionIns->context;

      printf("   ret sessionid               = 0x %8.8x \n", seesionid);
      printf("   ret context                 = 0x %16.16lx \n", context);

      tsn_t *tsnTemp;
      tsnTemp = tsnIns->prev;
      if (tsnTemp != NULL)
      {
         tsnTemp->next = tsnIns->next;
      }
      tsnTemp = tsnIns->next;
      if (tsnTemp != NULL)
      {
         tsnTemp->prev = tsnIns->prev;
      }
      pthread_mutex_lock(mutex_tsl);
      if (tsl->last == tsnIns)
      {
         tsl->last = tsnIns->prev;
      }
      if (tsl->first == tsnIns)
      {
         tsl->first = tsnIns->next;
      }
      tsl->count = tsl->count - 1;
      pthread_mutex_unlock(mutex_tsl);
      free(sessionIns);
      free(tsnIns);
   }
   ////////////////////////////////////////////////////////////////////////////////////////////////
#else

                                                                                                                           uint32_t serviceid_clockseqandnode_outsize_temp;
    serviceid_clockseqandnode_realsize = 8;
    serviceid_clockseqandnode =
            (dbus_uint32_t *)malloc(
                    serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
            );

    char workername[1024];
    memset((char *)workername, 0, 1024);
    // sprintf(workername, "%s", "gpworker1");
    int ifound = 0;
    int iworker;
    sin_t * sinIns;

    pthread_mutex_lock(mutex_workerrec);
    for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
    {
       if (workerrec[iworker].context_addr == in_session_context)
       {
          sinIns = NULL;
          if (workerrec[iworker].first != NULL)
          {
             sinIns = workerrec[iworker].first;
             do
             {
	        if (sinIns->session_id == in_session_seesionid)
	        {
                   sprintf(workername, "%s%d", "gpworker", iworker);
	           ifound = 1;
                   break;
	        }
	        sinIns = sinIns->next;
             }while (sinIns != NULL);


	     if ( ifound == 1 )
             {
                break;
             }
          }
       }
    }
    pthread_mutex_unlock(mutex_workerrec);


    if (ifound == 0)
    {
       printf("Can't find the worker for the session and the context. \n");

       seesionid = 0x0;
       serviceid_timelow = 0x0;
       serviceid_timemid = 0x0;
       serviceid_timehiandver = 0x0;
       opscnt = 0x0;
       head_next = 0x0;
       head_prev = 0x0;
       context = 0x0;

       serviceid_clockseqandnode_realsize = 8;
       serviceid_clockseqandnode =
          (dbus_uint32_t *)malloc(
             serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
          );
       for (int i = 0; i < serviceid_clockseqandnode_realsize ; i++) {
          serviceid_clockseqandnode[i] = 0x0;
       }
       serviceid_clockseqandnode_outsize = 8;
    }
   else
   {
    method_call_teec_closesession(
       workername,

       in_session_seesionid,
       in_session_serviceid_timelow,
       in_session_serviceid_timemid,
       in_session_serviceid_timehiandver,
       in_session_serviceid_clockseqandnode,
       in_session_serviceid_clockseqandnode_realsize,
       in_session_opscnt,
       in_session_head_next,
       in_session_head_prev,
       in_session_context,

       &seesionid,
       &serviceid_timelow,
       &serviceid_timemid,
       &serviceid_timehiandver,
       serviceid_clockseqandnode,
       serviceid_clockseqandnode_realsize,
       &serviceid_clockseqandnode_outsize_temp,
       &opscnt,
       &head_next,
       &head_prev,
       &context
    );

    pthread_mutex_lock(mutex_workerrec);
    sin_t * sinTemp;
    sinTemp = sinIns->prev;
    if (sinTemp != NULL)
    {
      sinTemp->next = sinIns->next;
    }
    sinTemp = sinIns->next;
    if (sinTemp != NULL)
    {
      sinTemp->prev = sinIns->prev;
    }
    if (workerrec[iworker].last == sinIns)
    {
       workerrec[iworker].last = sinIns->prev;
    }
    if (workerrec[iworker].first == sinIns)
    {
       workerrec[iworker].first = sinIns->next;
    }
    free(sinIns);
    workerrec[iworker].sessionid_count =
       workerrec[iworker].sessionid_count - 1;
    pthread_mutex_unlock(mutex_workerrec);

    serviceid_clockseqandnode_outsize = serviceid_clockseqandnode_outsize_temp;

    if (
	serviceid_clockseqandnode_realsize >= serviceid_clockseqandnode_outsize &&
	8 >= serviceid_clockseqandnode_outsize
       )
    {
       serviceid_clockseqandnode_realsize = serviceid_clockseqandnode_outsize;
    }
    else
    {
       serviceid_clockseqandnode_realsize = 0;
       serviceid_clockseqandnode_outsize = 0;
    }

   }// end of else found == 1
#endif


   // create a reply from the message
   reply = dbus_message_new_method_return(msg);

   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &seesionid
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timelow
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timemid
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timehiandver
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_clockseqandnode_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (serviceid_clockseqandnode_outsize > 0 &&
       serviceid_clockseqandnode != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &serviceid_clockseqandnode,
                  serviceid_clockseqandnode_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &opscnt
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &head_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &head_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &context
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send the reply && flush the connection
   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_connection_flush(conn);
   dbus_message_unref(msg);
   // dbus_connection_close(conn);
   // dbus_connection_unref(conn);
   free(thdfargs);

   // sleep(2);

   return NULL;
}


void *
reply_to_method_call_teec_invokecommand(
      void *thdfargs
)
{
   DBusMsgConn *DBusMCP;
   DBusMessage *msg;
   DBusConnection *conn;
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   DBusMessageIter structIter;
   DBusMessageIter ArrayIter;
   int iType;
   char buf[2];
   buf[0] = DBUS_TYPE_UINT32;
   buf[1] = '\0';

   dbus_uint32_t in_session_sessionid;
   dbus_uint32_t in_session_serviceid_timelow;
   dbus_uint32_t in_session_serviceid_timemid;
   dbus_uint32_t in_session_serviceid_timehiandver;
   dbus_uint32_t in_session_serviceid_clockseqandnode_size;
   dbus_uint32_t *in_session_serviceid_clockseqandnode;
   int in_session_serviceid_clockseqandnode_realsize;
   dbus_uint32_t in_session_opscnt;
   dbus_uint64_t in_session_head_next;
   dbus_uint64_t in_session_head_prev;
   dbus_uint64_t in_session_context;

   dbus_uint32_t in_commandid;

   dbus_uint32_t in_operation_started;
   dbus_uint32_t in_operation_paramtypes;

   dbus_uint64_t in_operation_param1_tmpref_buffer;
   dbus_uint32_t in_operation_param1_tmpref_size;
   dbus_uint64_t in_operation_param1_memref_parent;
   dbus_uint32_t in_operation_param1_memref_parent_flag;
   dbus_uint32_t in_operation_param1_memref_size;
   dbus_uint32_t in_operation_param1_memref_offset;
   dbus_uint32_t in_operation_param1_value_a;
   dbus_uint32_t in_operation_param1_value_b;
   dbus_int32_t in_operation_param1_ionref_ionsharefd;
   dbus_uint32_t in_operation_param1_ionref_ionsize;

   dbus_uint64_t in_operation_param2_tmpref_buffer;
   dbus_uint32_t in_operation_param2_tmpref_size;
   dbus_uint64_t in_operation_param2_memref_parent;
   dbus_uint32_t in_operation_param2_memref_parent_flag;
   dbus_uint32_t in_operation_param2_memref_size;
   dbus_uint32_t in_operation_param2_memref_offset;
   dbus_uint32_t in_operation_param2_value_a;
   dbus_uint32_t in_operation_param2_value_b;
   dbus_int32_t in_operation_param2_ionref_ionsharefd;
   dbus_uint32_t in_operation_param2_ionref_ionsize;

   dbus_uint64_t in_operation_param3_tmpref_buffer;
   dbus_uint32_t in_operation_param3_tmpref_size;
   dbus_uint64_t in_operation_param3_memref_parent;
   dbus_uint32_t in_operation_param3_memref_parent_flag;
   dbus_uint32_t in_operation_param3_memref_size;
   dbus_uint32_t in_operation_param3_memref_offset;
   dbus_uint32_t in_operation_param3_value_a;
   dbus_uint32_t in_operation_param3_value_b;
   dbus_int32_t in_operation_param3_ionref_ionsharefd;
   dbus_uint32_t in_operation_param3_ionref_ionsize;

   dbus_uint64_t in_operation_param4_tmpref_buffer;
   dbus_uint32_t in_operation_param4_tmpref_size;
   dbus_uint64_t in_operation_param4_memref_parent;
   dbus_uint32_t in_operation_param4_memref_parent_flag;
   dbus_uint32_t in_operation_param4_memref_size;
   dbus_uint32_t in_operation_param4_memref_offset;
   dbus_uint32_t in_operation_param4_value_a;
   dbus_uint32_t in_operation_param4_value_b;
   dbus_int32_t in_operation_param4_ionref_ionsharefd;
   dbus_uint32_t in_operation_param4_ionref_ionsize;

   dbus_uint64_t in_operation_session;
   dbus_int32_t in_operation_cancelflag;

   dbus_uint32_t in_returnorigin;

   dbus_uint32_t in_buffer1_size;
   dbus_uint32_t *in_buffer1;
   int in_buffer1_realsize;
   dbus_uint32_t in_buffer2_size;
   dbus_uint32_t *in_buffer2;
   int in_buffer2_realsize;
   dbus_uint32_t in_buffer3_size;
   dbus_uint32_t *in_buffer3;
   int in_buffer3_realsize;
   dbus_uint32_t in_buffer4_size;
   dbus_uint32_t *in_buffer4;
   int in_buffer4_realsize;

   dbus_int32_t lt_flag;

   dbus_uint32_t teecresult;

   dbus_uint32_t sessionid;
   dbus_uint32_t serviceid_timelow;
   dbus_uint32_t serviceid_timemid;
   dbus_uint32_t serviceid_timehiandver;
   dbus_uint32_t *serviceid_clockseqandnode;
   int serviceid_clockseqandnode_realsize;
   dbus_uint32_t serviceid_clockseqandnode_outsize;
   dbus_uint32_t opscnt;
   dbus_uint64_t head_next;
   dbus_uint64_t head_prev;
   dbus_uint64_t context;

   dbus_uint32_t started;
   dbus_uint32_t paramtypes;

   dbus_uint64_t operation_param1_tmpref_buffer;
   dbus_uint32_t operation_param1_tmpref_size;
   dbus_uint64_t operation_param1_memref_parent;
   dbus_uint32_t operation_param1_memref_parent_flag;
   dbus_uint32_t operation_param1_memref_size;
   dbus_uint32_t operation_param1_memref_offset;
   dbus_uint32_t operation_param1_value_a;
   dbus_uint32_t operation_param1_value_b;
   dbus_int32_t  operation_param1_ionref_ionsharefd;
   dbus_uint32_t operation_param1_ionref_ionsize;

   dbus_uint64_t operation_param2_tmpref_buffer;
   dbus_uint32_t operation_param2_tmpref_size;
   dbus_uint64_t operation_param2_memref_parent;
   dbus_uint32_t operation_param2_memref_parent_flag;
   dbus_uint32_t operation_param2_memref_size;
   dbus_uint32_t operation_param2_memref_offset;
   dbus_uint32_t operation_param2_value_a;
   dbus_uint32_t operation_param2_value_b;
   dbus_int32_t operation_param2_ionref_ionsharefd;
   dbus_uint32_t operation_param2_ionref_ionsize;

   dbus_uint64_t operation_param3_tmpref_buffer;
   dbus_uint32_t operation_param3_tmpref_size;
   dbus_uint64_t operation_param3_memref_parent;
   dbus_uint32_t operation_param3_memref_parent_flag;
   dbus_uint32_t operation_param3_memref_size;
   dbus_uint32_t operation_param3_memref_offset;
   dbus_uint32_t operation_param3_value_a;
   dbus_uint32_t operation_param3_value_b;
   dbus_int32_t operation_param3_ionref_ionsharefd;
   dbus_uint32_t operation_param3_ionref_ionsize;

   dbus_uint64_t operation_param4_tmpref_buffer;
   dbus_uint32_t operation_param4_tmpref_size;
   dbus_uint64_t operation_param4_memref_parent;
   dbus_uint32_t operation_param4_memref_parent_flag;
   dbus_uint32_t operation_param4_memref_size;
   dbus_uint32_t operation_param4_memref_offset;
   dbus_uint32_t operation_param4_value_a;
   dbus_uint32_t operation_param4_value_b;
   dbus_int32_t operation_param4_ionref_ionsharefd;
   dbus_uint32_t operation_param4_ionref_ionsize;

   dbus_uint64_t operation_session;
   dbus_int32_t operation_cancelflag;

   dbus_uint32_t returnorigin;

   dbus_uint32_t *buffer1;
   int buffer1_realsize;
   dbus_uint32_t buffer1_outsize;
   dbus_uint32_t *buffer2;
   int buffer2_realsize;
   dbus_uint32_t buffer2_outsize;
   dbus_uint32_t *buffer3;
   int buffer3_realsize;
   dbus_uint32_t buffer3_outsize;
   dbus_uint32_t *buffer4;
   int buffer4_realsize;
   dbus_uint32_t buffer4_outsize;

   dbus_uint32_t serial = 0;

#ifdef GP_PROXY
   pthread_mutex_t * mutex_workerrec;
   wr_t * workerrec;
#endif

#ifdef GP_WORKER
   pthread_mutex_t *mutex_tcl;
   pthread_mutex_t *mutex_tsl;
   tcl_t *tcl;
   tsl_t *tsl;
#endif

   DBusMCP = (DBusMsgConn *) thdfargs;
   msg = DBusMCP->msg;
   conn = DBusMCP->conn;
#ifdef GP_PROXY
    mutex_workerrec = DBusMCP->mutex_workerrec;
    workerrec = DBusMCP->workerrec;
#endif
#ifdef GP_WORKER
   mutex_tcl = DBusMCP->mutex_tcl;
   mutex_tsl = DBusMCP->mutex_tsl;
   tcl = DBusMCP->tcl;
   tsl = DBusMCP->tsl;
#endif

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_recurse(
         &args,
         &structIter
   );


   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_sessionid);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_timelow
   );

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_timemid);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_timehiandver);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_serviceid_clockseqandnode_size);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (in_session_serviceid_clockseqandnode_size > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_session_serviceid_clockseqandnode,
            &in_session_serviceid_clockseqandnode_realsize
      );

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_iter_get_basic(
         &structIter,
         &in_session_opscnt);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_head_next);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_head_prev);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_session_context);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }


   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_commandid);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }


   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_started);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_paramtypes);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_tmpref_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_tmpref_size);

   bResult = dbus_message_iter_next(&structIter);
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT64)
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_parent);

   bResult = dbus_message_iter_next(&structIter);
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32. \n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_parent_flag);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_size);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_value_a);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_value_b);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param1_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_tmpref_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_parent);

   bResult = dbus_message_iter_next(&structIter);
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32. \n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_parent_flag);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_value_a);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_value_b);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param2_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_tmpref_buffer);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_parent);

   bResult = dbus_message_iter_next(&structIter);
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32. \n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_parent_flag);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_value_a);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_value_b);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param3_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_tmpref_buffer);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_tmpref_size);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_parent);

   bResult = dbus_message_iter_next(&structIter);
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType = dbus_message_iter_get_arg_type(&structIter);
   if (iType != DBUS_TYPE_UINT32)
   {
      fprintf(stderr, "Argument is not UINT32. \n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_parent_flag);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_size);


   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_memref_offset);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_value_a);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_value_b);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_ionref_ionsharefd);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_param4_ionref_ionsize);

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT64
         )
   {
      fprintf(stderr, "Argument is not UINT64.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_session);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_operation_cancelflag);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_returnorigin);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }


   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_buffer1_size);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (in_buffer1_size > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_buffer1,
            &in_buffer1_realsize
      );
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_buffer2_size);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (in_buffer2_size > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_buffer2,
            &in_buffer2_realsize
      );

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_buffer3_size);
   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (in_buffer3_size > 0)
   {
      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_buffer3,
            &in_buffer3_realsize
      );

      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
   }

   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not INT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &in_buffer4_size);

   if (in_buffer4_size > 0)
   {
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments!\n");
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }

      dbus_message_iter_recurse(
            &structIter,
            &ArrayIter);

      iType =
            dbus_message_iter_get_arg_type(
                  &ArrayIter
            );
      if (
            iType != DBUS_TYPE_UINT32
            )
      {
         fprintf(stderr, "Argument is not UINT32, line %d. \n", __LINE__);
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         free(thdfargs);
         return NULL;
      }
      dbus_message_iter_get_fixed_array(
            &ArrayIter,
            &in_buffer4,
            &in_buffer4_realsize
      );
   }

   bResult =
         dbus_message_iter_next(
               &structIter
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has too few arguments!\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   iType =
         dbus_message_iter_get_arg_type(
               &structIter
         );
   if (
         iType != DBUS_TYPE_INT32
         )
   {
      fprintf(stderr, "Argument is not UINT32.\n");
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &lt_flag);

   printf("Received method call TEEC_InvokeCommand: \n");
   printf("   lt_flag        = %d \n", lt_flag);
   printf("   in_session_sessionid        = 0x %8.8x \n", in_session_sessionid);
#if 0
                                                                                                                           printf("   in_session_serviceid_timelow          = 0x %8.8x \n", in_session_serviceid_timelow);
    printf("   in_session_serviceid_timemid          = 0x %8.8x \n", in_session_serviceid_timemid);
    printf("   in_session_serviceid_timehiandver     = 0x %8.8x \n",
           in_session_serviceid_timehiandver);
    printf("   in_session_serviceid_clockseqandnode  = \n");
    printf("   ");
    for (int i = 0; i < in_session_serviceid_clockseqandnode_realsize; i++) {
        printf(" %2.2x", in_session_serviceid_clockseqandnode[i]);
    }
    printf("\n");
    printf("   in serviceid_clockseqandnode_size     = 0x %8.8x \n",
	   in_session_serviceid_clockseqandnode_size);
    printf("   in_session_opscnt                     = 0x %8.8x \n", in_session_opscnt);
    printf("   in_session_head_next                  = 0x %16.16lx \n", in_session_head_next);
    printf("   in_session_head_prev                  = 0x %16.16lx \n", in_session_head_prev);
#endif
   printf("   in_session_context          = 0x %16.16lx \n", in_session_context);
#if 0
                                                                                                                           printf("   commandid                             = 0x %8.8x \n", in_commandid);

    printf("   in_operation_started                  = 0x %8.8x \n", in_operation_started);
    printf("   in_operation_paramtypes               = 0x %8.8x \n", in_operation_paramtypes);

    printf("   in_operation_param1_tmpref_buffer     = 0x %16.16lx \n", in_operation_param1_tmpref_buffer);
    printf("   in_operation_param1_tmpref_size       = 0x %8.8x \n", in_operation_param1_tmpref_size);
    printf("   in_operation_param1_memref_parent     = 0x %16.16lx \n", in_operation_param1_memref_parent);
    printf("   in_operation_param1_memref_size       = 0x %8.8x \n", in_operation_param1_memref_size);
    printf("   in_operation_param1_memref_offset     = 0x %8.8x \n", in_operation_param1_memref_offset);
    printf("   in_operation_param1_value_a           = 0x %8.8x \n", in_operation_param1_value_a);
    printf("   in_operation_param1_value_b           = 0x %8.8x \n", in_operation_param1_value_b);
    printf("   in_operation_param1_ionref_ionsharefd = 0x %8.8x \n",in_operation_param2_ionref_ionsharefd);
    printf("   in_operation_param1_ionref_ionsize    = 0x %8.8x \n", in_operation_param2_ionref_ionsize);

    printf("   in_operation_param2_tmpref_buffer     = 0x %16.16lx \n", in_operation_param2_tmpref_buffer);
    printf("   in_operation_param2_tmpref_size       = 0x %8.8x \n", in_operation_param2_tmpref_size);
    printf("   in_operation_param2_memref_parent     = 0x %16.16lx \n", in_operation_param2_memref_parent);
    printf("   in_operation_param2_memref_size       = 0x %8.8x \n", in_operation_param2_memref_size);
    printf("   in_operation_param2_memref_offset     = 0x %8.8x \n", in_operation_param2_memref_offset);
    printf("   in_operation_param2_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
    printf("   in_operation_param2_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
    printf("   in_operation_param2_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
    printf("   in_operation_param2_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

    printf("   in_operation_param3_tmpref_buffer     = 0x %16.16lx \n", in_operation_param3_tmpref_buffer);
    printf("   in_operation_param3_tmpref_size       = 0x %8.8x \n", in_operation_param3_tmpref_size);
    printf("   in_operation_param3_memref_parent     = 0x %16.16lx \n", in_operation_param3_memref_parent);
    printf("   in_operation_param3_memref_size       = 0x %8.8x \n", in_operation_param3_memref_size);
    printf("   in_operation_param3_memref_offset     = 0x %8.8x \n", in_operation_param3_memref_offset);
    printf("   in_operation_param3_value_a           = 0x %8.8x \n", in_operation_param3_value_a);
    printf("   in_operation_param3_value_b           = 0x %8.8x \n", in_operation_param3_value_b);
    printf("   in_operation_param3_ionref_ionsharefd = 0x %8.8x \n", in_operation_param3_ionref_ionsharefd);
    printf("   in_operation_param3_ionref_ionsize    = 0x %8.8x \n", in_operation_param3_ionref_ionsize);

    printf("   in_operation_param4_tmpref_buffer     = 0x %16.16lx \n", in_operation_param4_tmpref_buffer);
    printf("   in_operation_param4_tmpref_size       = 0x %8.8x \n", in_operation_param4_tmpref_size);
    printf("   in_operation_param4_memref_parent     = 0x %16.16lx \n", in_operation_param4_memref_parent);
    printf("   in_operation_param4_memref_size       = 0x %8.8x \n", in_operation_param4_memref_size);
    printf("   in_operation_param4_memref_offset     = 0x %8.8x \n", in_operation_param4_memref_offset);
    printf("   in_operation_param4_value_a           = 0x %8.8x \n", in_operation_param4_value_a);
    printf("   in_operation_param4_value_b           = 0x %8.8x \n", in_operation_param4_value_b);
    printf("   in_operation_param4_ionref_ionsharefd = 0x %8.8x \n", in_operation_param4_ionref_ionsharefd);
    printf("   in_operation_param4_ionref_ionsize    = 0x %8.8x \n", in_operation_param4_ionref_ionsize);

    printf("   in_operation_session                  = 0x %16.16lx \n", in_operation_session);
    printf("   in_operation_cancelflag               = 0x %8.8x \n", in_operation_cancelflag);

    printf("   in_returnorigin                       = 0x %8.8x \n", in_returnorigin);

    printf("   in_buffer1                            = \n");
    if (in_buffer1_size > 0) {
       printf("   ");
       for (int i = 0; i < in_buffer1_realsize; i++) {
          printf(" %2.2x", in_buffer1[i]);
       }
       printf("\n");
    }
#endif

#if 0
                                                                                                                           printf("   in_buffer1_size                       = 0x %8.8x \n",
	   in_buffer1_size);
#endif

#if 0
                                                                                                                           printf("   in_buffer2                            = \n");
    if (in_buffer2_size > 0) {
       printf("   ");
       for (int i = 0; i < in_buffer2_realsize; i++) {
          printf(" %2.2x", in_buffer2[i]);
       }
       printf("\n");
    }
    printf("   in_buffer2_size                       = 0x %8.8x \n",
	   in_buffer2_size);

    printf("   in_buffer3                            = \n");
    if (in_buffer3_size > 0) {
       printf("   ");
       for (int i = 0; i < in_buffer3_realsize; i++) {
          printf(" %2.2x", in_buffer3[i]);
       }
       printf("\n");
    }
    printf("   in_buffer3_size                       = 0x %8.8x \n",
	   in_buffer3_size);

    printf("   in_buffer4                            = \n");
    if (in_buffer4_size > 0) {
       printf("   ");
       for (int i = 0; i < in_buffer4_realsize; i++) {
          printf(" %2.2x", in_buffer4[i]);
       }
       printf("\n");
    }
    printf("   in_buffer4_size                       = 0x %8.8x \n",
	   in_buffer4_size);
#endif

#ifdef GP_WORKER
   //////////////////////////////////////////////////////////////////////////////////////////////////////
   //////////////////////////////////////////////////////////////////////////////////////////////////////
   //////////////////////////////////////////////////////////////////////////////////////////////////////
   TEEC_Session *sessionIns;
   TEEC_Session *sessionIns_temp= (TEEC_Session *) malloc(sizeof(TEEC_Session));
   tsn_t *tsnIns_temp = (tsn_t *) malloc(sizeof(tsn_t));
   tsn_t *tsnIns;
   sessionIns = NULL;

   TEEC_Context *contextIns;
   TEEC_Context *contextIns_temp = (TEEC_Context *) malloc(sizeof(TEEC_Context));

   tcn_t *tcnIns_temp = (tcn_t *) malloc(sizeof(tcn_t));
   tcnIns_temp->self = contextIns_temp;
   tcn_t *tcnIns;
   contextIns = NULL;


   if(lt_flag == 1){
      struct timeval ltstart, ltend;
      gettimeofday(&ltstart, NULL);
      pthread_mutex_lock(mutex_tcl);
      pthread_mutex_lock(mutex_tsl);
      //if(tcl_flag == 0)
      //{
      if(load_tcl(tcl,tcnIns_temp,in_session_sessionid) != 0){
            printf("session 0x %8.8x load_tcl error\n",in_session_sessionid);
         }
      //}
      //tcnIns_temp->self->ta_path =
      if(load_tsl(tsl,tsnIns_temp,tcnIns_temp,sessionIns_temp,in_session_sessionid) != 0){
         printf("session 0x %8.8x load_tsl error\n",in_session_sessionid);
      }
      pthread_mutex_unlock(mutex_tsl);
      pthread_mutex_unlock(mutex_tcl);
      gettimeofday(&ltend, NULL);
      int zi64Time = (ltend.tv_sec - ltstart.tv_sec) * 1000000 +
                     (ltend.tv_usec - ltstart.tv_usec);
      printf("gpworker huifu  xxxxxx  used time: %ld us. \n", zi64Time);
   }

   pthread_mutex_lock(mutex_tsl);
   tsnIns = tsl->first;
   printf("tsl count = %d\n",tsl->count);
   printf("session_id =  0x %8.8x \n",in_session_sessionid);
   while(tsnIns != NULL){
      printf("tsnIns->self->session_id =  0x %8.8x \n",tsnIns->self->session_id);
      printf("tsnIns->self = %p  \n",tsnIns->self);
      tsnIns = tsnIns->next;
   }
   if (tsl->first != NULL)
   {
      tsnIns = tsl->first;
      do
      {
         printf("in find tsnIns->self->session_id =  0x %8.8x \n",tsnIns->self->session_id);
         if (tsnIns->self->session_id == in_session_sessionid)
         {
            sessionIns = tsnIns->self;
            break;
         }
         tsnIns = tsnIns->next;
         //printf("tsnIns->self->session_id =  0x %8.8x \n",tsnIns->self->session_id);
      } while (tsnIns != NULL);
   }
   pthread_mutex_unlock(mutex_tsl);


   if (sessionIns != NULL)
   {
      pthread_mutex_lock(mutex_tcl);
      if (tcl->first != NULL)
      {
         tcnIns = tcl->first;
         do
         {
            contextIns = tcnIns->self;
            if (contextIns == sessionIns->context)
            {
               printf("find tcnIns->self =  0x %8.8x \n",tcnIns->self);
               break;
            }
            tcnIns = tcnIns->next;
         } while (tcnIns != NULL);
      }
      pthread_mutex_unlock(mutex_tcl);
   }

   if (sessionIns == NULL || contextIns == NULL)
   {
      if (sessionIns == NULL)
      {
         if (tsl->first == NULL)
         {
            printf("The teec session list is null. \n");
            teecresult = TEEC_ERROR_SESSION_LIST_NULL;
         } else
         {
            printf("Can't find the teec session. \n");

            teecresult = TEEC_ERROR_NO_SESSION_MATCH;
         }
      }

      if (contextIns == NULL)
      {
         if (tcl->first == NULL)
         {
            printf("The teec context list is null. \n");
            teecresult = TEEC_ERROR_CONTEXT_LIST_NULL;
         } else
         {
            printf("Can't find the teec context. \n");
            teecresult = TEEC_ERROR_NO_CONTEXT_MATCH;
         }
      }

      sessionid = 0;
      serviceid_timelow = 0;
      serviceid_timemid = 0;
      serviceid_timehiandver = 0;
      serviceid_clockseqandnode_realsize = 0;
      serviceid_clockseqandnode = NULL;
      serviceid_clockseqandnode_outsize = 0;
      opscnt = 0;
      head_next = 0;
      head_prev = 0;
      context = 0;

      started = 0;
      paramtypes = 0;

      operation_param1_tmpref_buffer = 0;
      operation_param1_tmpref_size = 0;
      operation_param1_memref_parent = 0;
      operation_param1_memref_parent_flag = 0;
      operation_param1_memref_size = 0;
      operation_param1_memref_offset = 0;
      operation_param1_value_a = 0;
      operation_param1_value_b = 0;
      operation_param1_ionref_ionsharefd = 0;
      operation_param1_ionref_ionsize = 0;

      operation_param2_tmpref_buffer = 0;
      operation_param2_tmpref_size = 0;
      operation_param2_memref_parent = 0;
      operation_param2_memref_parent_flag = 0;
      operation_param2_memref_size = 0;
      operation_param2_memref_offset = 0;
      operation_param2_value_a = 0;
      operation_param2_value_b = 0;
      operation_param2_ionref_ionsharefd = 0;
      operation_param2_ionref_ionsize = 0;

      operation_param3_tmpref_buffer = 0;
      operation_param3_tmpref_size = 0;
      operation_param3_memref_parent = 0;
      operation_param3_memref_parent_flag = 0;
      operation_param3_memref_size = 0;
      operation_param3_memref_offset = 0;
      operation_param3_value_a = 0;
      operation_param3_value_b = 0;
      operation_param3_ionref_ionsharefd = 0;
      operation_param3_ionref_ionsize = 0;

      operation_param4_tmpref_buffer = 0;
      operation_param4_tmpref_size = 0;
      operation_param4_memref_parent = 0;
      operation_param4_memref_parent_flag = 0;
      operation_param4_memref_size = 0;
      operation_param4_memref_offset = 0;
      operation_param4_value_a = 0;
      operation_param4_value_b = 0;
      operation_param4_ionref_ionsharefd = 0;
      operation_param4_ionref_ionsize = 0;

      operation_session = 0;
      operation_cancelflag = 0;

      returnorigin = 0xff;

      buffer1_realsize = 0;
      buffer1 = NULL;
      buffer1_outsize = 0;
      buffer2_realsize = 0;
      buffer2 = NULL;
      buffer2_outsize = 0;
      buffer3_realsize = 0;
      buffer3 = NULL;
      buffer3_outsize = 0;
      buffer4_realsize = 0;
      buffer4 = NULL;
      buffer4_outsize = 0;
   }
   else
   {
      teecresult = TEEC_SUCCESS;

      sessionIns->session_id = in_session_sessionid;
      sessionIns->service_id.timeLow = in_session_serviceid_timelow;
      sessionIns->service_id.timeMid = in_session_serviceid_timemid;
      sessionIns->service_id.timeHiAndVersion = in_session_serviceid_timehiandver;
      if (in_session_serviceid_clockseqandnode_realsize <= 8 &&
          in_session_serviceid_clockseqandnode_realsize > 0 &&
          in_session_serviceid_clockseqandnode != NULL
            )
      {
         for (int i = 0; i < in_session_serviceid_clockseqandnode_realsize; i++)
         {
            sessionIns->service_id.clockSeqAndNode[i] =
                  (uint8_t)(in_session_serviceid_clockseqandnode[i] & 0x000000ff);
         }
      } else
      {
         for (int i = 0; i < 8; i++)
         {
            sessionIns->service_id.clockSeqAndNode[i] = 0;
         }
      }
      sessionIns->ops_cnt = in_session_opscnt;
      sessionIns->head.next = (struct ListNode *) in_session_head_next;
      sessionIns->head.prev = (struct ListNode *) in_session_head_prev;
      // sessionIns->context = (TEEC_Context *)in_session_context;


      TEEC_Operation operationIns;

      operationIns.started = in_operation_started;
      operationIns.paramTypes = in_operation_paramtypes;

      /////////////////////////////////////////////////////////////////////////////////////////////
      /////////////////////////////////////////////////////////////////////////////////////////////

      uint8_t *buffer1_temp = NULL;
      TEEC_SharedMemory shareBuffer1;
      bool sb1AllReged = false;
      switch (
            TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 0)
            )
      {
         case TEEC_VALUE_INPUT:
         case TEEC_VALUE_INOUT:
         {
            operationIns.params[0].value.a = in_operation_param1_value_a;
            operationIns.params[0].value.b = in_operation_param1_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_INPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (
                  in_buffer1 != NULL &&
                  in_buffer1_size > 0
                  )
            {
               uint32_t buffer1_temp_size;
               buffer1_temp_size = in_buffer1_size;
               buffer1_temp = (uint8_t *) malloc(buffer1_temp_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer1_size; isize++)
               {
                  buffer1_temp[isize] = (uint8_t)(in_buffer1[isize] & 0x000000ff);
               }

               operationIns.params[0].tmpref.buffer = (void *) buffer1_temp;
               operationIns.params[0].tmpref.size = buffer1_temp_size;
            }

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         {
            if (
                  in_operation_param1_tmpref_size > 0
                  )
            {
               buffer1_temp = (uint8_t *) malloc(in_operation_param1_tmpref_size * sizeof(uint8_t));
               operationIns.params[0].tmpref.buffer = (void *) buffer1_temp;
               operationIns.params[0].tmpref.size = in_operation_param1_tmpref_size;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            switch (in_operation_param1_memref_parent_flag)
            {
               case TEEC_MEM_INPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        in_buffer1 != NULL &&
                        in_buffer1_size > 0
                        )
                  {
                     memset(&shareBuffer1, 0, sizeof(shareBuffer1));
                     shareBuffer1.size = in_buffer1_size;
                     shareBuffer1.flags = in_operation_param1_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer1);
                     if (retASM)
                     {
                        printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb1AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        memset(shareBuffer1.buffer, 0, shareBuffer1.size);
                        for (int isize = 0; isize < in_buffer1_size; isize++)
                        {
                           *((uint8_t * )(shareBuffer1.buffer) + isize) =
                                 (uint8_t)(in_buffer1[isize] & 0x000000ff);
                        }
                        operationIns.params[0].memref.parent = &shareBuffer1;
                        // operationIns.params[0].memref.parent->flags =
                        //    in_operation_param1_memref_parent_flag;
                        operationIns.params[0].memref.size = shareBuffer1.size;
                     }
                  }

                  break;
               }

               case TEEC_MEM_OUTPUT:
               {
                  if (
                        in_operation_param1_memref_size > 0
                        )
                  {
                     memset(&shareBuffer1, 0, sizeof(shareBuffer1));
                     shareBuffer1.size = in_operation_param1_memref_size;
                     shareBuffer1.flags = in_operation_param1_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer1);
                     if (retASM)
                     {
                        printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb1AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        operationIns.params[0].memref.parent = &shareBuffer1;
                        operationIns.params[0].memref.size = shareBuffer1.size;
                     }

                  }

                  break;
               }

               default:
                  break;
            }

            break;
         }


         case TEEC_MEMREF_PARTIAL_INPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (
                  in_buffer1 != NULL &&
                  in_buffer1_size > 0
                  )
            {
               memset(&shareBuffer1, 0, sizeof(shareBuffer1));
               shareBuffer1.size = in_buffer1_size;
               shareBuffer1.flags = in_operation_param1_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer1);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb1AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  memset(shareBuffer1.buffer, 0, shareBuffer1.size);
                  for (int isize = 0; isize < in_buffer1_size; isize++)
                  {
                     *((uint8_t * )(shareBuffer1.buffer) + isize) =
                           (uint8_t)(in_buffer1[isize] & 0x000000ff);
                  }
                  operationIns.params[0].memref.parent = &shareBuffer1;
                  operationIns.params[0].memref.offset = in_operation_param1_memref_offset;
                  operationIns.params[0].memref.size = in_operation_param1_memref_size;
               }
            }

            break;
         }

         case TEEC_MEMREF_PARTIAL_OUTPUT:
         {
            if (in_operation_param1_memref_size > 0)
            {
               memset(&shareBuffer1, 0, sizeof(shareBuffer1));
               shareBuffer1.size = in_buffer1_size;
               shareBuffer1.flags = in_operation_param1_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer1);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb1AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  operationIns.params[0].memref.parent = &shareBuffer1;
                  operationIns.params[0].memref.offset = in_operation_param1_memref_offset;
                  operationIns.params[0].memref.size = in_operation_param1_memref_size;
               }

            }

            break;
         }


         default:
            break;
      }

      /////////////////////////////////////////////////////////////////////////////////////////////
      /////////////////////////////////////////////////////////////////////////////////////////////

      uint8_t *buffer2_temp = NULL;
      TEEC_SharedMemory shareBuffer2;
      bool sb2AllReged = false;
      switch (
            TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 1)
            )
      {
         case TEEC_VALUE_INPUT:
         case TEEC_VALUE_INOUT:
         {
            operationIns.params[1].value.a = in_operation_param2_value_a;
            operationIns.params[1].value.b = in_operation_param2_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_INPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (
                  in_buffer2 != NULL &&
                  in_buffer2_size > 0
                  )
            {
               uint32_t buffer2_temp_size;
               buffer2_temp_size = in_buffer2_size;
               buffer2_temp = (uint8_t *) malloc(buffer2_temp_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer2_size; isize++)
               {
                  buffer2_temp[isize] = (uint8_t)(in_buffer2[isize] & 0x000000ff);
               }

               operationIns.params[1].tmpref.buffer = (void *) buffer2_temp;
               operationIns.params[1].tmpref.size = buffer2_temp_size;
            }

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         {
            if (
                  in_operation_param2_tmpref_size > 0
                  )
            {
               buffer2_temp = (uint8_t *) malloc(in_operation_param2_tmpref_size * sizeof(uint8_t));
               operationIns.params[1].tmpref.buffer = (void *) buffer2_temp;
               operationIns.params[1].tmpref.size = in_operation_param2_tmpref_size;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            switch (in_operation_param2_memref_parent_flag)
            {
               case TEEC_MEM_INPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        in_buffer2 != NULL &&
                        in_buffer2_size > 0
                        )
                  {
                     memset(&shareBuffer2, 0, sizeof(shareBuffer2));
                     shareBuffer2.size = in_buffer2_size;
                     shareBuffer2.flags = in_operation_param2_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer2);
                     if (retASM)
                     {
                        printf("alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb2AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        memset(shareBuffer2.buffer, 0, shareBuffer2.size);
                        for (int isize = 0; isize < in_buffer2_size; isize++)
                        {
                           *((uint8_t * )(shareBuffer2.buffer) + isize) =
                                 (uint8_t)(in_buffer2[isize] & 0x000000ff);
                        }
                        operationIns.params[1].memref.parent = &shareBuffer2;
                        // operationIns.params[1].memref.parent->flags =
                        //    in_operation_param2_memref_parent_flag;
                        operationIns.params[1].memref.size = shareBuffer2.size;
                     }
                  }

                  break;
               }

               case TEEC_MEM_OUTPUT:
               {
                  if (
                        in_operation_param2_memref_size > 0
                        )
                  {
                     memset(&shareBuffer2, 0, sizeof(shareBuffer2));
                     shareBuffer2.size = in_operation_param2_memref_size;
                     shareBuffer2.flags = in_operation_param2_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer2);
                     if (retASM)
                     {
                        printf("alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb2AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        operationIns.params[1].memref.parent = &shareBuffer2;
                        // operationIns.params[1].memref.parent->flags =
                        //   in_operation_param2_memref_parent_flag;
                        operationIns.params[1].memref.size = shareBuffer2.size;
                     }

                  }

                  break;
               }

               default:
                  break;
            }

            break;
         }


         case TEEC_MEMREF_PARTIAL_INPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (
                  in_buffer2 != NULL &&
                  in_buffer2_size > 0
                  )
            {
               memset(&shareBuffer2, 0, sizeof(shareBuffer2));
               shareBuffer2.size = in_buffer2_size;
               shareBuffer2.flags = in_operation_param2_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer2);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb2AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  memset(shareBuffer2.buffer, 0, shareBuffer2.size);
                  for (int isize = 0; isize < in_buffer2_size; isize++)
                  {
                     *((uint8_t * )(shareBuffer2.buffer) + isize) =
                           (uint8_t)(in_buffer2[isize] & 0x000000ff);
                  }
                  operationIns.params[1].memref.parent = &shareBuffer2;
                  operationIns.params[1].memref.offset = in_operation_param2_memref_offset;
                  operationIns.params[1].memref.size = in_operation_param2_memref_size;
               }
            }

            break;
         }

         case TEEC_MEMREF_PARTIAL_OUTPUT:
         {
            if (in_operation_param2_memref_size > 0)
            {
               memset(&shareBuffer2, 0, sizeof(shareBuffer2));
               shareBuffer2.size = in_buffer2_size;
               shareBuffer2.flags = in_operation_param2_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer2);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb2AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  operationIns.params[1].memref.parent = &shareBuffer2;
                  operationIns.params[1].memref.offset = in_operation_param2_memref_offset;
                  operationIns.params[1].memref.size = in_operation_param2_memref_size;
               }

            }

            break;
         }


         default:
            break;
      }

      /////////////////////////////////////////////////////////////////////////////////////////////
      /////////////////////////////////////////////////////////////////////////////////////////////

      uint8_t *buffer3_temp = NULL;
      TEEC_SharedMemory shareBuffer3;
      bool sb3AllReged = false;
      switch (
            TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 2)
            )
      {
         case TEEC_VALUE_INPUT:
         case TEEC_VALUE_INOUT:
         {
            operationIns.params[2].value.a = in_operation_param3_value_a;
            operationIns.params[2].value.b = in_operation_param3_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_INPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (
                  in_buffer3 != NULL &&
                  in_buffer3_size > 0
                  )
            {
               uint32_t buffer3_temp_size;
               buffer3_temp_size = in_buffer3_size;
               buffer3_temp = (uint8_t *) malloc(buffer3_temp_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer3_size; isize++)
               {
                  buffer3_temp[isize] = (uint8_t)(in_buffer3[isize] & 0x000000ff);
               }

               operationIns.params[2].tmpref.buffer = (void *) buffer3_temp;
               operationIns.params[2].tmpref.size = buffer3_temp_size;
            }

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         {
            if (
                  in_operation_param3_tmpref_size > 0
                  )
            {
               buffer3_temp = (uint8_t *) malloc(in_operation_param3_tmpref_size * sizeof(uint8_t));
               operationIns.params[2].tmpref.buffer = (void *) buffer3_temp;
               operationIns.params[2].tmpref.size = in_operation_param3_tmpref_size;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            switch (in_operation_param3_memref_parent_flag)
            {
               case TEEC_MEM_INPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        in_buffer3 != NULL &&
                        in_buffer3_size > 0
                        )
                  {
                     memset(&shareBuffer3, 0, sizeof(shareBuffer3));
                     shareBuffer3.size = in_buffer3_size;
                     shareBuffer3.flags = in_operation_param3_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer3);
                     if (retASM)
                     {
                        printf("alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb3AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        memset(shareBuffer3.buffer, 0, shareBuffer3.size);
                        for (int isize = 0; isize < in_buffer3_size; isize++)
                        {
                           *((uint8_t * )(shareBuffer3.buffer) + isize) =
                                 (uint8_t)(in_buffer3[isize] & 0x000000ff);
                        }
                        operationIns.params[2].memref.parent = &shareBuffer3;
                        // operationIns.params[2].memref.parent->flags =
                        //    in_operation_param3_memref_parent_flag;
                        operationIns.params[2].memref.size = shareBuffer3.size;
                     }
                  }

                  break;
               }

               case TEEC_MEM_OUTPUT:
               {
                  if (
                        in_operation_param3_memref_size > 0
                        )
                  {
                     memset(&shareBuffer3, 0, sizeof(shareBuffer3));
                     shareBuffer3.size = in_operation_param3_memref_size;
                     shareBuffer3.flags = in_operation_param3_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer3);
                     if (retASM)
                     {
                        printf("alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb3AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        operationIns.params[2].memref.parent = &shareBuffer3;
                        // operationIns.params[2].memref.parent->flags =
                        //    in_operation_param3_memref_parent_flag;
                        operationIns.params[2].memref.size = shareBuffer3.size;
                     }

                  }

                  break;
               }

               default:
                  break;
            }

            break;
         }


         case TEEC_MEMREF_PARTIAL_INPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (
                  in_buffer3 != NULL &&
                  in_buffer3_size > 0
                  )
            {
               memset(&shareBuffer3, 0, sizeof(shareBuffer3));
               shareBuffer3.size = in_buffer3_size;
               shareBuffer3.flags = in_operation_param3_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer3);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb3AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  memset(shareBuffer3.buffer, 0, shareBuffer3.size);
                  for (int isize = 0; isize < in_buffer3_size; isize++)
                  {
                     *((uint8_t * )(shareBuffer3.buffer) + isize) =
                           (uint8_t)(in_buffer3[isize] & 0x000000ff);
                  }
                  operationIns.params[2].memref.parent = &shareBuffer3;
                  operationIns.params[2].memref.offset = in_operation_param3_memref_offset;
                  operationIns.params[2].memref.size = in_operation_param3_memref_size;
               }
            }

            break;
         }

         case TEEC_MEMREF_PARTIAL_OUTPUT:
         {
            if (in_operation_param3_memref_size > 0)
            {
               memset(&shareBuffer3, 0, sizeof(shareBuffer3));
               shareBuffer3.size = in_buffer3_size;
               shareBuffer3.flags = in_operation_param3_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer3);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb3AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  operationIns.params[2].memref.parent = &shareBuffer3;
                  operationIns.params[2].memref.offset = in_operation_param3_memref_offset;
                  operationIns.params[2].memref.size = in_operation_param3_memref_size;
               }

            }

            break;
         }


         default:
            break;
      }

      /////////////////////////////////////////////////////////////////////////////////////////////
      /////////////////////////////////////////////////////////////////////////////////////////////

      uint8_t *buffer4_temp = NULL;
      TEEC_SharedMemory shareBuffer4;
      bool sb4AllReged = false;
      switch (
            TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 3)
            )
      {
         case TEEC_VALUE_INPUT:
         case TEEC_VALUE_INOUT:
         {
            operationIns.params[3].value.a = in_operation_param4_value_a;
            operationIns.params[3].value.b = in_operation_param4_value_b;

            break;
         }

         case TEEC_MEMREF_TEMP_INPUT:
         case TEEC_MEMREF_TEMP_INOUT:
         {
            if (
                  in_buffer4 != NULL &&
                  in_buffer4_size > 0
                  )
            {
               uint32_t buffer4_temp_size;
               buffer4_temp_size = in_buffer4_size;
               buffer4_temp = (uint8_t *) malloc(buffer4_temp_size * sizeof(uint8_t));
               for (int isize = 0; isize < in_buffer4_size; isize++)
               {
                  buffer4_temp[isize] = (uint8_t)(in_buffer4[isize] & 0x000000ff);
               }

               operationIns.params[3].tmpref.buffer = (void *) buffer4_temp;
               operationIns.params[3].tmpref.size = buffer4_temp_size;
            }

            break;
         }

         case TEEC_MEMREF_TEMP_OUTPUT:
         {
            if (
                  in_operation_param4_tmpref_size > 0
                  )
            {
               buffer4_temp = (uint8_t *) malloc(in_operation_param4_tmpref_size * sizeof(uint8_t));
               operationIns.params[3].tmpref.buffer = (void *) buffer4_temp;
               operationIns.params[3].tmpref.size = in_operation_param4_tmpref_size;
            }

            break;
         }


         case TEEC_MEMREF_WHOLE:
         {
            switch (in_operation_param4_memref_parent_flag)
            {
               case TEEC_MEM_INPUT:
               case TEEC_MEM_INOUT:
               {
                  if (
                        in_buffer4 != NULL &&
                        in_buffer4_size > 0
                        )
                  {
                     memset(&shareBuffer4, 0, sizeof(shareBuffer4));
                     shareBuffer4.size = in_buffer4_size;
                     shareBuffer4.flags = in_operation_param4_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer4);
                     if (retASM)
                     {
                        printf("alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb4AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        memset(shareBuffer4.buffer, 0, shareBuffer4.size);
                        for (int isize = 0; isize < in_buffer4_size; isize++)
                        {
                           *((uint8_t * )(shareBuffer4.buffer) + isize) =
                                 (uint8_t)(in_buffer4[isize] & 0x000000ff);
                        }
                        operationIns.params[3].memref.parent = &shareBuffer4;
                        // operationIns.params[3].memref.parent->flags =
                        //    in_operation_param4_memref_parent_flag;
                        operationIns.params[3].memref.size = shareBuffer4.size;
                     }
                  }

                  break;
               }

               case TEEC_MEM_OUTPUT:
               {
                  if (
                        in_operation_param4_memref_size > 0
                        )
                  {
                     memset(&shareBuffer4, 0, sizeof(shareBuffer4));
                     shareBuffer4.size = in_operation_param4_memref_size;
                     shareBuffer4.flags = in_operation_param4_memref_parent_flag;
                     TEEC_Result retASM = 0;
                     retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer4);
                     if (retASM)
                     {
                        printf("alloc share memory failed, ret=0x%x.\n", retASM);
                        teecresult = retASM;
                     } else
                     {
                        sb4AllReged = true;
                        printf("TEEC_AllocateSharedMemory succecced. \n");
                        operationIns.params[3].memref.parent = &shareBuffer4;
                        // operationIns.params[3].memref.parent->flags =
                        //   in_operation_param4_memref_parent_flag;
                        operationIns.params[3].memref.size = shareBuffer4.size;
                     }

                  }

                  break;
               }

               default:
                  break;
            }

            break;
         }


         case TEEC_MEMREF_PARTIAL_INPUT:
         case TEEC_MEMREF_PARTIAL_INOUT:
         {
            if (
                  in_buffer4 != NULL &&
                  in_buffer4_size > 0
                  )
            {
               memset(&shareBuffer4, 0, sizeof(shareBuffer4));
               shareBuffer4.size = in_buffer4_size;
               shareBuffer4.flags = in_operation_param4_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer4);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb4AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  memset(shareBuffer4.buffer, 0, shareBuffer4.size);
                  for (int isize = 0; isize < in_buffer4_size; isize++)
                  {
                     *((uint8_t * )(shareBuffer4.buffer) + isize) =
                           (uint8_t)(in_buffer4[isize] & 0x000000ff);
                  }
                  operationIns.params[3].memref.parent = &shareBuffer4;
                  operationIns.params[3].memref.offset = in_operation_param4_memref_offset;
                  operationIns.params[3].memref.size = in_operation_param4_memref_size;
               }
            }

            break;
         }

         case TEEC_MEMREF_PARTIAL_OUTPUT:
         {
            if (in_operation_param4_memref_size > 0)
            {
               memset(&shareBuffer4, 0, sizeof(shareBuffer4));
               shareBuffer4.size = in_buffer4_size;
               shareBuffer4.flags = in_operation_param4_memref_parent_flag;
               TEEC_Result retASM = 0;
               retASM = TEEC_AllocateSharedMemory(contextIns, &shareBuffer4);
               if (retASM)
               {
                  printf("Alloc share memory failed, ret=0x%x.\n", retASM);
                  teecresult = retASM;
               } else
               {
                  sb4AllReged = true;
                  printf("TEEC_AllocateSharedMemory succecced. \n");
                  operationIns.params[3].memref.parent = &shareBuffer4;
                  operationIns.params[3].memref.offset = in_operation_param4_memref_offset;
                  operationIns.params[3].memref.size = in_operation_param4_memref_size;
               }

            }

            break;
         }


         default:
            break;
      }

      /////////////////////////////////////////////////////////////////////////////////////////////
      /////////////////////////////////////////////////////////////////////////////////////////////

      if (teecresult != TEEC_SUCCESS)
      {
         sessionid = 0;
         serviceid_timelow = 0;
         serviceid_timemid = 0;
         serviceid_timehiandver = 0;
         serviceid_clockseqandnode_realsize = 0;
         serviceid_clockseqandnode = NULL;
         serviceid_clockseqandnode_outsize = 0;
         opscnt = 0;
         head_next = 0;
         head_prev = 0;
         context = 0;

         started = 0;
         paramtypes = 0;

         operation_param1_tmpref_buffer = 0;
         operation_param1_tmpref_size = 0;
         operation_param1_memref_parent = 0;
         operation_param1_memref_parent_flag = 0;
         operation_param1_memref_size = 0;
         operation_param1_memref_offset = 0;
         operation_param1_value_a = 0;
         operation_param1_value_b = 0;
         operation_param1_ionref_ionsharefd = 0;
         operation_param1_ionref_ionsize = 0;

         operation_param2_tmpref_buffer = 0;
         operation_param2_tmpref_size = 0;
         operation_param2_memref_parent = 0;
         operation_param2_memref_parent_flag = 0;
         operation_param2_memref_size = 0;
         operation_param2_memref_offset = 0;
         operation_param2_value_a = 0;
         operation_param2_value_b = 0;
         operation_param2_ionref_ionsharefd = 0;
         operation_param2_ionref_ionsize = 0;

         operation_param3_tmpref_buffer = 0;
         operation_param3_tmpref_size = 0;
         operation_param3_memref_parent = 0;
         operation_param3_memref_parent_flag = 0;
         operation_param3_memref_size = 0;
         operation_param3_memref_offset = 0;
         operation_param3_value_a = 0;
         operation_param3_value_b = 0;
         operation_param3_ionref_ionsharefd = 0;
         operation_param3_ionref_ionsize = 0;

         operation_param4_tmpref_buffer = 0;
         operation_param4_tmpref_size = 0;
         operation_param4_memref_parent = 0;
         operation_param4_memref_parent_flag = 0;
         operation_param4_memref_size = 0;
         operation_param4_memref_offset = 0;
         operation_param4_value_a = 0;
         operation_param4_value_b = 0;
         operation_param4_ionref_ionsharefd = 0;
         operation_param4_ionref_ionsize = 0;

         operation_session = 0;
         operation_cancelflag = 0;

         returnorigin = 0xff;

         buffer1_realsize = 0;
         buffer1 = NULL;
         buffer1_outsize = 0;
         buffer2_realsize = 0;
         buffer2 = NULL;
         buffer2_outsize = 0;
         buffer3_realsize = 0;
         buffer3 = NULL;
         buffer3_outsize = 0;
         buffer4_realsize = 0;
         buffer4 = NULL;
         buffer4_outsize = 0;
      } else
      { //start of the input parameter operation success
#if 0
                                                                                                                                 operationIns.params[0].ionref.ion_share_fd = in_operation_param1_ionref_ionsharefd;
    operationIns.params[0].ionref.ion_size = in_operation_param1_ionref_ionsize;

    operationIns.params[1].ionref.ion_share_fd = in_operation_param2_ionref_ionsharefd;
    operationIns.params[1].ionref.ion_size = in_operation_param2_ionref_ionsize;

    operationIns.params[2].ionref.ion_share_fd = in_operation_param3_ionref_ionsharefd;
    operationIns.params[2].ionref.ion_size = in_operation_param3_ionref_ionsize;

    operationIns.params[3].ionref.ion_share_fd = in_operation_param4_ionref_ionsharefd;
    operationIns.params[3].ionref.ion_size = in_operation_param4_ionref_ionsize;
#endif

         operationIns.session = sessionIns;
         operationIns.cancel_flag = in_operation_cancelflag;

         uint32_t origin;
         origin = in_returnorigin;

         TEEC_Result result;

         struct timeval start, end;
         gettimeofday(&start, NULL);
         result =
               TEEC_InvokeCommand(
                     sessionIns,
                     in_commandid,
                     &operationIns,
                     &origin
               );
         gettimeofday(&end, NULL);
         uint32_t cost = 0;
         cost += (1000000 * end.tv_sec + end.tv_usec) - (1000000 * start.tv_sec + start.tv_usec);

         if (result != TEEC_SUCCESS)
         {
            printf("Teec InvokeCommand Failed. \n");
            printf("   teecresult                  = 0x %8.8x.\n", result);

            teecresult = result;

            sessionid = 0;
            serviceid_timelow = 0;
            serviceid_timemid = 0;
            serviceid_timehiandver = 0;
            serviceid_clockseqandnode_realsize = 0;
            serviceid_clockseqandnode = NULL;
            serviceid_clockseqandnode_outsize = 0;
            opscnt = 0;
            head_next = 0;
            head_prev = 0;
            context = 0;

            started = 0;
            paramtypes = 0;

            operation_param1_tmpref_buffer = 0;
            operation_param1_tmpref_size = 0;
            operation_param1_memref_parent = 0;
            operation_param1_memref_parent_flag = 0;
            operation_param1_memref_size = 0;
            operation_param1_memref_offset = 0;
            operation_param1_value_a = 0;
            operation_param1_value_b = 0;
            operation_param1_ionref_ionsharefd = 0;
            operation_param1_ionref_ionsize = 0;

            operation_param2_tmpref_buffer = 0;
            operation_param2_tmpref_size = 0;
            operation_param2_memref_parent = 0;
            operation_param2_memref_parent_flag = 0;
            operation_param2_memref_size = 0;
            operation_param2_memref_offset = 0;
            operation_param2_value_a = 0;
            operation_param2_value_b = 0;
            operation_param2_ionref_ionsharefd = 0;
            operation_param2_ionref_ionsize = 0;

            operation_param3_tmpref_buffer = 0;
            operation_param3_tmpref_size = 0;
            operation_param3_memref_parent = 0;
            operation_param3_memref_parent_flag = 0;
            operation_param3_memref_size = 0;
            operation_param3_memref_offset = 0;
            operation_param3_value_a = 0;
            operation_param3_value_b = 0;
            operation_param3_ionref_ionsharefd = 0;
            operation_param3_ionref_ionsize = 0;

            operation_param4_tmpref_buffer = 0;
            operation_param4_tmpref_size = 0;
            operation_param4_memref_parent = 0;
            operation_param4_memref_parent_flag = 0;
            operation_param4_memref_size = 0;
            operation_param4_memref_offset = 0;
            operation_param4_value_a = 0;
            operation_param4_value_b = 0;
            operation_param4_ionref_ionsharefd = 0;
            operation_param4_ionref_ionsize = 0;

            operation_session = 0;
            operation_cancelflag = 0;

            returnorigin = 0xff;

            buffer1_realsize = 0;
            buffer1 = NULL;
            buffer1_outsize = 0;
            buffer2_realsize = 0;
            buffer2 = NULL;
            buffer2_outsize = 0;
            buffer3_realsize = 0;
            buffer3 = NULL;
            buffer3_outsize = 0;
            buffer4_realsize = 0;
            buffer4 = NULL;
            buffer4_outsize = 0;
         } else
         { // start of the invoke command success
            printf("Teec InvokeCommand Succed, cost time: %ld us \n", cost);

            teecresult = result;

            sessionid = sessionIns->session_id;
            serviceid_timelow = sessionIns->service_id.timeLow;
            serviceid_timemid = sessionIns->service_id.timeMid;
            serviceid_timehiandver = sessionIns->service_id.timeHiAndVersion;
            if (sessionIns->service_id.clockSeqAndNode != NULL)
            {
               serviceid_clockseqandnode_realsize = 8;
               serviceid_clockseqandnode =
                     (dbus_uint32_t *) malloc(
                           serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
                     );
               for (int iind = 0; iind < 8; iind++)
               {
                  uint8_t u8Temp;
                  u8Temp = sessionIns->service_id.clockSeqAndNode[iind];
                  serviceid_clockseqandnode[iind] = (dbus_uint32_t) u8Temp;
               }
               serviceid_clockseqandnode_outsize = 8;
            } else
            {
               serviceid_clockseqandnode_realsize = 0;
               serviceid_clockseqandnode = NULL;
               serviceid_clockseqandnode_outsize = 0;
            }
            opscnt = sessionIns->ops_cnt;
            head_next = (dbus_uint64_t) sessionIns->head.next;
            head_prev = (dbus_uint64_t) sessionIns->head.prev;
            context = (dbus_uint64_t) sessionIns->context;

            started = operationIns.started;
            paramtypes = operationIns.paramTypes;

            //////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////

            switch (
                  TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 0)
                  )
            {
               case TEEC_VALUE_INOUT:
               case TEEC_VALUE_OUTPUT:
               {
                  operation_param1_value_a = operationIns.params[0].value.a;
                  operation_param1_value_b = operationIns.params[0].value.b;

                  buffer1_realsize = 0;
                  buffer1 = NULL;
                  buffer1_outsize = 0;

                  break;
               }

               case TEEC_MEMREF_TEMP_INOUT:
               case TEEC_MEMREF_TEMP_OUTPUT:
               {
                  if (operationIns.params[0].tmpref.buffer != NULL &&
                      operationIns.params[0].tmpref.size > 0
                        )
                  {
                     buffer1_realsize = operationIns.params[0].tmpref.size;
                     buffer1 =
                           (dbus_uint32_t *) malloc(
                                 buffer1_realsize * sizeof(dbus_uint32_t)
                           );
                     for (int iind = 0; iind < buffer1_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )(operationIns.params[0].tmpref.buffer) + iind);
                        buffer1[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer1_outsize = buffer1_realsize;
                  } else
                  {
                     buffer1_realsize = 0;
                     buffer1 = NULL;
                     buffer1_outsize = 0;
                  }

                  operation_param1_tmpref_buffer = (dbus_uint64_t) operationIns.params[0].tmpref.buffer;
                  operation_param1_tmpref_size = operationIns.params[0].tmpref.size;

                  break;
               }


               case TEEC_MEMREF_WHOLE:
               {
                  switch (operationIns.params[0].memref.parent->flags)
                  {
                     case TEEC_MEM_OUTPUT:
                     case TEEC_MEM_INOUT:
                     {

                        if (operationIns.params[0].memref.parent->buffer != NULL &&
                            operationIns.params[0].memref.parent->size > 0
                              )
                        {
                           buffer1_realsize = operationIns.params[0].memref.parent->size;
                           buffer1 =
                                 (dbus_uint32_t *) malloc(
                                       buffer1_realsize * sizeof(dbus_uint32_t)
                                 );
                           for (int iind = 0; iind < buffer1_realsize; iind++)
                           {
                              uint8_t u8Temp;
                              u8Temp = (uint8_t) * ((uint8_t * )
                                                          (operationIns.params[0].memref.parent->buffer) + iind);
                              buffer1[iind] = (dbus_uint32_t) u8Temp;
                           }
                           buffer1_outsize = buffer1_realsize;
                        } else
                        {
                           buffer1_realsize = 0;
                           buffer1 = NULL;
                           buffer1_outsize = 0;
                        }

                        operation_param1_memref_parent =
                              (dbus_uint64_t) operationIns.params[0].memref.parent->buffer;
                        operation_param1_memref_parent_flag =
                              (dbus_uint32_t) operationIns.params[0].memref.parent->flags;
                        operation_param1_memref_size =
                              operationIns.params[0].memref.parent->size;

                        break;
                     }

                     default:
                        break;
                  }

                  break;
               }


               case TEEC_MEMREF_PARTIAL_OUTPUT:
               case TEEC_MEMREF_PARTIAL_INOUT:
               {
                  if (operationIns.params[0].memref.parent->buffer != NULL &&
                      operationIns.params[0].memref.parent->size > 0
                        )
                  {
                     buffer1_realsize = operationIns.params[0].memref.parent->size;
                     buffer1 =
                           (dbus_uint32_t *) malloc(buffer1_realsize * sizeof(dbus_uint32_t));
                     for (int iind = 0; iind < buffer1_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )
                                                    (operationIns.params[0].memref.parent->buffer) + iind);
                        buffer1[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer1_outsize = buffer1_realsize;
                  } else
                  {
                     buffer1_realsize = 0;
                     buffer1 = NULL;
                     buffer1_outsize = 0;
                  }

                  operation_param1_memref_parent =
                        (dbus_uint64_t) operationIns.params[0].memref.parent->buffer;
                  operation_param1_memref_parent_flag =
                        (dbus_uint32_t) operationIns.params[0].memref.parent->flags;
                  operation_param1_memref_offset = operationIns.params[0].memref.offset;
                  operation_param1_memref_size =
                        operationIns.params[0].memref.size;

                  break;
               }


               default:
               {
                  buffer1_realsize = 0;
                  buffer1 = NULL;
                  buffer1_outsize = 0;
               }
            }

            operation_param1_ionref_ionsharefd = operationIns.params[0].ionref.ion_share_fd;
            operation_param1_ionref_ionsize = operationIns.params[0].ionref.ion_size;

            //////////////////////////////////////////////////////////////////////////////////

            switch (
                  TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 1)
                  )
            {
               case TEEC_VALUE_INOUT:
               case TEEC_VALUE_OUTPUT:
               {
                  operation_param2_value_a = operationIns.params[1].value.a;
                  operation_param2_value_b = operationIns.params[1].value.b;

                  buffer2_realsize = 0;
                  buffer2 = NULL;
                  buffer2_outsize = 0;

                  break;
               }

               case TEEC_MEMREF_TEMP_INOUT:
               case TEEC_MEMREF_TEMP_OUTPUT:
               {
                  if (operationIns.params[1].tmpref.buffer != NULL &&
                      operationIns.params[1].tmpref.size > 0
                        )
                  {
                     buffer2_realsize = operationIns.params[1].tmpref.size;
                     buffer2 =
                           (dbus_uint32_t *) malloc(
                                 buffer2_realsize * sizeof(dbus_uint32_t)
                           );
                     for (int iind = 0; iind < buffer2_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )(operationIns.params[1].tmpref.buffer) + iind);
                        buffer2[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer2_outsize = buffer2_realsize;
                  } else
                  {
                     buffer2_realsize = 0;
                     buffer2 = NULL;
                     buffer2_outsize = 0;
                  }

                  operation_param2_tmpref_buffer = (dbus_uint64_t) operationIns.params[1].tmpref.buffer;
                  operation_param2_tmpref_size = operationIns.params[1].tmpref.size;

                  break;
               }


               case TEEC_MEMREF_WHOLE:
               {
                  switch (operationIns.params[1].memref.parent->flags)
                  {
                     case TEEC_MEM_OUTPUT:
                     case TEEC_MEM_INOUT:
                     {

                        if (operationIns.params[1].memref.parent->buffer != NULL &&
                            operationIns.params[1].memref.parent->size > 0
                              )
                        {
                           buffer2_realsize = operationIns.params[1].memref.parent->size;
                           buffer2 =
                                 (dbus_uint32_t *) malloc(
                                       buffer2_realsize * sizeof(dbus_uint32_t)
                                 );
                           for (int iind = 0; iind < buffer2_realsize; iind++)
                           {
                              uint8_t u8Temp;
                              u8Temp = (uint8_t) * ((uint8_t * )
                                                          (operationIns.params[1].memref.parent->buffer) + iind);
                              buffer2[iind] = (dbus_uint32_t) u8Temp;
                           }
                           buffer2_outsize = buffer2_realsize;
                        } else
                        {
                           buffer2_realsize = 0;
                           buffer2 = NULL;
                           buffer2_outsize = 0;
                        }

                        operation_param2_memref_parent =
                              (dbus_uint64_t) operationIns.params[1].memref.parent->buffer;
                        operation_param2_memref_parent_flag =
                              (dbus_uint32_t) operationIns.params[1].memref.parent->flags;
                        operation_param2_memref_size =
                              operationIns.params[1].memref.parent->size;

                        break;
                     }

                     default:
                        break;
                  }

                  break;
               }


               case TEEC_MEMREF_PARTIAL_OUTPUT:
               case TEEC_MEMREF_PARTIAL_INOUT:
               {
                  if (operationIns.params[1].memref.parent->buffer != NULL &&
                      operationIns.params[1].memref.parent->size > 0
                        )
                  {
                     buffer2_realsize = operationIns.params[1].memref.parent->size;
                     buffer2 =
                           (dbus_uint32_t *) malloc(buffer2_realsize * sizeof(dbus_uint32_t));
                     for (int iind = 0; iind < buffer2_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )
                                                    (operationIns.params[1].memref.parent->buffer) + iind);
                        buffer2[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer2_outsize = buffer2_realsize;
                  } else
                  {
                     buffer2_realsize = 0;
                     buffer2 = NULL;
                     buffer2_outsize = 0;
                  }

                  operation_param2_memref_parent =
                        (dbus_uint64_t) operationIns.params[1].memref.parent->buffer;
                  operation_param2_memref_parent_flag =
                        (dbus_uint32_t) operationIns.params[1].memref.parent->flags;
                  operation_param2_memref_offset = operationIns.params[1].memref.offset;
                  operation_param2_memref_size =
                        operationIns.params[1].memref.size;

                  break;
               }


               default:
               {
                  buffer2_realsize = 0;
                  buffer2 = NULL;
                  buffer2_outsize = 0;
               }
            }

            operation_param2_ionref_ionsharefd = operationIns.params[1].ionref.ion_share_fd;
            operation_param2_ionref_ionsize = operationIns.params[1].ionref.ion_size;

            //////////////////////////////////////////////////////////////////////////////////

            switch (
                  TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 2)
                  )
            {
               case TEEC_VALUE_INOUT:
               case TEEC_VALUE_OUTPUT:
               {
                  operation_param3_value_a = operationIns.params[2].value.a;
                  operation_param3_value_b = operationIns.params[2].value.b;

                  buffer3_realsize = 0;
                  buffer3 = NULL;
                  buffer3_outsize = 0;

                  break;
               }

               case TEEC_MEMREF_TEMP_INOUT:
               case TEEC_MEMREF_TEMP_OUTPUT:
               {
                  if (operationIns.params[2].tmpref.buffer != NULL &&
                      operationIns.params[2].tmpref.size > 0
                        )
                  {
                     buffer3_realsize = operationIns.params[2].tmpref.size;
                     buffer3 =
                           (dbus_uint32_t *) malloc(
                                 buffer3_realsize * sizeof(dbus_uint32_t)
                           );
                     for (int iind = 0; iind < buffer3_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )(operationIns.params[2].tmpref.buffer) + iind);
                        buffer3[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer3_outsize = buffer3_realsize;
                  } else
                  {
                     buffer3_realsize = 0;
                     buffer3 = NULL;
                     buffer3_outsize = 0;
                  }

                  operation_param3_tmpref_buffer = (dbus_uint64_t) operationIns.params[2].tmpref.buffer;
                  operation_param3_tmpref_size = operationIns.params[2].tmpref.size;

                  break;
               }


               case TEEC_MEMREF_WHOLE:
               {
                  switch (operationIns.params[2].memref.parent->flags)
                  {
                     case TEEC_MEM_OUTPUT:
                     case TEEC_MEM_INOUT:
                     {

                        if (operationIns.params[2].memref.parent->buffer != NULL &&
                            operationIns.params[2].memref.parent->size > 0
                              )
                        {
                           buffer3_realsize = operationIns.params[2].memref.parent->size;
                           buffer3 =
                                 (dbus_uint32_t *) malloc(
                                       buffer3_realsize * sizeof(dbus_uint32_t)
                                 );
                           for (int iind = 0; iind < buffer3_realsize; iind++)
                           {
                              uint8_t u8Temp;
                              u8Temp = (uint8_t) * ((uint8_t * )
                                                          (operationIns.params[2].memref.parent->buffer) + iind);
                              buffer3[iind] = (dbus_uint32_t) u8Temp;
                           }
                           buffer3_outsize = buffer3_realsize;
                        } else
                        {
                           buffer3_realsize = 0;
                           buffer3 = NULL;
                           buffer3_outsize = 0;
                        }

                        operation_param3_memref_parent =
                              (dbus_uint64_t) operationIns.params[2].memref.parent->buffer;
                        operation_param3_memref_parent_flag =
                              (dbus_uint32_t) operationIns.params[2].memref.parent->flags;
                        operation_param3_memref_size =
                              operationIns.params[2].memref.parent->size;

                        break;
                     }

                     default:
                        break;
                  }

                  break;
               }


               case TEEC_MEMREF_PARTIAL_OUTPUT:
               case TEEC_MEMREF_PARTIAL_INOUT:
               {
                  if (operationIns.params[2].memref.parent->buffer != NULL &&
                      operationIns.params[2].memref.parent->size > 0
                        )
                  {
                     buffer3_realsize = operationIns.params[2].memref.parent->size;
                     buffer3 =
                           (dbus_uint32_t *) malloc(buffer3_realsize * sizeof(dbus_uint32_t));
                     for (int iind = 0; iind < buffer3_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )
                                                    (operationIns.params[2].memref.parent->buffer) + iind);
                        buffer3[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer3_outsize = buffer3_realsize;
                  } else
                  {
                     buffer3_realsize = 0;
                     buffer3 = NULL;
                     buffer3_outsize = 0;
                  }

                  operation_param3_memref_parent =
                        (dbus_uint64_t) operationIns.params[2].memref.parent->buffer;
                  operation_param3_memref_parent_flag =
                        (dbus_uint32_t) operationIns.params[2].memref.parent->flags;
                  operation_param3_memref_offset = operationIns.params[2].memref.offset;
                  operation_param3_memref_size =
                        operationIns.params[2].memref.size;

                  break;
               }


               default:
               {
                  buffer3_realsize = 0;
                  buffer3 = NULL;
                  buffer3_outsize = 0;
               }
            }

            operation_param3_ionref_ionsharefd = operationIns.params[2].ionref.ion_share_fd;
            operation_param3_ionref_ionsize = operationIns.params[2].ionref.ion_size;

            //////////////////////////////////////////////////////////////////////////////////

            switch (
                  TEEC_PARAM_TYPE_GET(operationIns.paramTypes, 3)
                  )
            {
               case TEEC_VALUE_INOUT:
               case TEEC_VALUE_OUTPUT:
               {
                  operation_param4_value_a = operationIns.params[3].value.a;
                  operation_param4_value_b = operationIns.params[3].value.b;

                  buffer4_realsize = 0;
                  buffer4 = NULL;
                  buffer4_outsize = 0;

                  break;
               }

               case TEEC_MEMREF_TEMP_INOUT:
               case TEEC_MEMREF_TEMP_OUTPUT:
               {
                  if (operationIns.params[3].tmpref.buffer != NULL &&
                      operationIns.params[3].tmpref.size > 0
                        )
                  {
                     buffer4_realsize = operationIns.params[3].tmpref.size;
                     buffer4 =
                           (dbus_uint32_t *) malloc(
                                 buffer4_realsize * sizeof(dbus_uint32_t)
                           );
                     for (int iind = 0; iind < buffer4_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )(operationIns.params[3].tmpref.buffer) + iind);
                        buffer4[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer4_outsize = buffer4_realsize;
                  } else
                  {
                     buffer4_realsize = 0;
                     buffer4 = NULL;
                     buffer4_outsize = 0;
                  }

                  operation_param4_tmpref_buffer = (dbus_uint64_t) operationIns.params[3].tmpref.buffer;
                  operation_param4_tmpref_size = operationIns.params[3].tmpref.size;

                  break;
               }


               case TEEC_MEMREF_WHOLE:
               {
                  switch (operationIns.params[3].memref.parent->flags)
                  {
                     case TEEC_MEM_OUTPUT:
                     case TEEC_MEM_INOUT:
                     {

                        if (operationIns.params[3].memref.parent->buffer != NULL &&
                            operationIns.params[3].memref.parent->size > 0
                              )
                        {
                           buffer4_realsize = operationIns.params[3].memref.parent->size;
                           buffer4 =
                                 (dbus_uint32_t *) malloc(
                                       buffer4_realsize * sizeof(dbus_uint32_t)
                                 );
                           for (int iind = 0; iind < buffer4_realsize; iind++)
                           {
                              uint8_t u8Temp;
                              u8Temp = (uint8_t) * ((uint8_t * )
                                                          (operationIns.params[3].memref.parent->buffer) + iind);
                              buffer4[iind] = (dbus_uint32_t) u8Temp;
                           }
                           buffer4_outsize = buffer4_realsize;
                        } else
                        {
                           buffer4_realsize = 0;
                           buffer4 = NULL;
                           buffer4_outsize = 0;
                        }

                        operation_param4_memref_parent =
                              (dbus_uint64_t) operationIns.params[3].memref.parent->buffer;
                        operation_param4_memref_parent_flag =
                              (dbus_uint32_t) operationIns.params[3].memref.parent->flags;
                        operation_param4_memref_size =
                              operationIns.params[3].memref.parent->size;

                        break;
                     }

                     default:
                        break;
                  }

                  break;
               }


               case TEEC_MEMREF_PARTIAL_OUTPUT:
               case TEEC_MEMREF_PARTIAL_INOUT:
               {
                  if (operationIns.params[3].memref.parent->buffer != NULL &&
                      operationIns.params[3].memref.parent->size > 0
                        )
                  {
                     buffer4_realsize = operationIns.params[3].memref.parent->size;
                     buffer4 =
                           (dbus_uint32_t *) malloc(buffer4_realsize * sizeof(dbus_uint32_t));
                     for (int iind = 0; iind < buffer4_realsize; iind++)
                     {
                        uint8_t u8Temp;
                        u8Temp = (uint8_t) * ((uint8_t * )
                                                    (operationIns.params[3].memref.parent->buffer) + iind);
                        buffer4[iind] = (dbus_uint32_t) u8Temp;
                     }
                     buffer4_outsize = buffer4_realsize;
                  } else
                  {
                     buffer4_realsize = 0;
                     buffer4 = NULL;
                     buffer4_outsize = 0;
                  }

                  operation_param4_memref_parent =
                        (dbus_uint64_t) operationIns.params[3].memref.parent->buffer;
                  operation_param4_memref_parent_flag =
                        (dbus_uint32_t) operationIns.params[3].memref.parent->flags;
                  operation_param4_memref_offset = operationIns.params[3].memref.offset;
                  operation_param4_memref_size =
                        operationIns.params[3].memref.size;

                  break;
               }


               default:
               {
                  buffer4_realsize = 0;
                  buffer4 = NULL;
                  buffer4_outsize = 0;
               }
            }

            operation_param4_ionref_ionsharefd = operationIns.params[3].ionref.ion_share_fd;
            operation_param4_ionref_ionsize = operationIns.params[3].ionref.ion_size;

            //////////////////////////////////////////////////////////////////////////////////
            //////////////////////////////////////////////////////////////////////////////////

            operation_session = (dbus_uint64_t) operationIns.session;
            operation_cancelflag = operationIns.cancel_flag;

            returnorigin = origin;
         }

         if (buffer1_temp != NULL)
         {
            free(buffer1_temp);
         }
         if (buffer2_temp != NULL)
         {
            free(buffer2_temp);
         }
         if (buffer3_temp != NULL)
         {
            free(buffer3_temp);
         }
         if (buffer4_temp != NULL)
         {
            free(buffer4_temp);
         }

         if (sb1AllReged == true)
         {
            TEEC_ReleaseSharedMemory(&shareBuffer1);
            printf("TEEC_ReleaseSharedMemory. \n");
         }

         if (sb2AllReged == true)
         {
            TEEC_ReleaseSharedMemory(&shareBuffer2);
            printf("TEEC_ReleaseSharedMemory. \n");
         }

         if (sb3AllReged == true)
         {
            TEEC_ReleaseSharedMemory(&shareBuffer3);
            printf("TEEC_ReleaseSharedMemory. \n");
         }

         if (sb4AllReged == true)
         {
            TEEC_ReleaseSharedMemory(&shareBuffer4);
            printf("TEEC_ReleaseSharedMemory. \n");
         }

      } // end of the invoke command success

   } // end of the input parameter operation success

   if(lt_flag == 0){
      struct timeval ltstart, ltend;
      gettimeofday(&ltstart, NULL);
      int result;
      pthread_mutex_lock(mutex_tsl);
      printf(" store_tsl %d sessionid = 0x %8.8x \n",__LINE__,in_session_sessionid);
      result = store_tsl(tsl,tsnIns);
      if(result != 0){
         printf("session %d store_tsl error\n",in_session_sessionid);
      }
      pthread_mutex_unlock(mutex_tsl);
      printf("gpworker %d tsl clean\n",__LINE__);

      pthread_mutex_lock(mutex_tcl);
      printf(" store_tcl %d sessionid = 0x %8.8x \n",__LINE__,in_session_sessionid);
      result = store_context(tcl,contextIns,tcnIns,in_session_sessionid,tsl);
      if(result != 0){
         printf("session %d store_tcl error\n",in_session_sessionid);
      }

      pthread_mutex_unlock(mutex_tcl);
      printf("gpworker %d tcl clean\n",__LINE__);
      gettimeofday(&ltend, NULL);
      int zi64Time = (ltend.tv_sec - ltstart.tv_sec) * 1000000 +
                     (ltend.tv_usec - ltstart.tv_usec);
      printf("gpworker baocun  xxxxxx  used time: %ld us. \n", zi64Time);
   }

   //////////////////////////////////////////////////////////////////////////////////////////////////////
   //////////////////////////////////////////////////////////////////////////////////////////////////////
   //////////////////////////////////////////////////////////////////////////////////////////////////////
#else
   if (in_buffer1_size > 0) {
    }
    else
    {
       in_buffer1_realsize = 0;
    }
    if (in_buffer2_size > 0) {
    }
    else
    {
       in_buffer2_realsize = 0;
    }
    if (in_buffer3_size > 0) {
    }
    else
    {
       in_buffer3_realsize = 0;
    }
    if (in_buffer4_size > 0) {
    }
    else
    {
       in_buffer4_realsize = 0;
    }

    serviceid_clockseqandnode_realsize = 8;
    serviceid_clockseqandnode =
            (dbus_uint32_t *)malloc(
                    serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
            );
    uint32_t serviceid_clockseqandnode_outsize_temp;
    uint32_t returnorigin_temp;

    uint32_t * buffer1_temp = NULL;
    uint32_t buffer1_size = 4096;
    uint32_t buffer1_outsize_temp;
    buffer1_temp =
       (uint32_t *)malloc( buffer1_size * sizeof(uint32_t) );

    uint32_t buffer2_size = 4096;
    uint32_t * buffer2_temp = NULL;
    uint32_t buffer2_outsize_temp;
    buffer2_temp =
       (uint32_t *)malloc( buffer2_size * sizeof(uint32_t) );

    uint32_t buffer3_size = 4096;
    uint32_t * buffer3_temp = NULL;
    uint32_t buffer3_outsize_temp;
    buffer3_temp =
       (uint32_t *)malloc( buffer3_size * sizeof(uint32_t) );

    uint32_t buffer4_size = 4096;
    uint32_t * buffer4_temp = NULL;
    uint32_t buffer4_outsize_temp;
    buffer4_temp =
       (uint32_t *)malloc( buffer4_size * sizeof(uint32_t) );

    char workername[1024];
    memset((char *)workername, 0, 1024);
    int ifound = 0;
    int iworker;
    sin_t * sinIns;

    pthread_mutex_lock(mutex_workerrec);
    for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
    {
       if (workerrec[iworker].context_addr == in_session_context)
       {
          sinIns = NULL;
          if (workerrec[iworker].first != NULL)
          {
             sinIns = workerrec[iworker].first;
             do
             {
	        if (sinIns->session_id == in_session_sessionid)
	        {
                   sprintf(workername, "%s%d", "gpworker", iworker);
	           ifound = 1;
                   break;
	        }
	        sinIns = sinIns->next;
             }while (sinIns != NULL);

	     if ( ifound == 1 )
             {
                break;
             }
          }
       }
    }
    pthread_mutex_unlock(mutex_workerrec);

    if (ifound == 0)
    {
       printf("Can't find the worker for the session and the context. \n");

       teecresult = 0xAAAA0017;

       sessionid = 0x0;
       serviceid_timelow = 0x0;
       serviceid_timemid = 0x0;
       serviceid_timehiandver = 0x0;
       opscnt = 0x0;
       head_next = 0x0;
       head_prev = 0x0;
       context = 0x0;
       started = 0x0;
       paramtypes = 0x0;

       serviceid_clockseqandnode_realsize = 8;
       serviceid_clockseqandnode =
          (dbus_uint32_t *)malloc(
             serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
          );
       for (int i = 0; i < serviceid_clockseqandnode_realsize ; i++) {
          serviceid_clockseqandnode[i] = 0x0;
       }
       serviceid_clockseqandnode_outsize = 8;

       operation_param1_tmpref_buffer = 0x0;
       operation_param1_tmpref_size = 0x0;
       operation_param1_memref_parent = 0x0;
       operation_param1_memref_size = 0x0;
       operation_param1_memref_offset = 0x0;
       operation_param1_value_a = 0x0;
       operation_param1_value_b = 0x0;
       operation_param1_ionref_ionsharefd = 0x0;
       operation_param1_ionref_ionsize = 0x0;

       operation_param2_tmpref_buffer = 0x0;
       operation_param2_tmpref_size = 0x0;
       operation_param2_memref_parent = 0x0;
       operation_param2_memref_size = 0x0;
       operation_param2_memref_offset = 0x0;
       operation_param2_value_a = 0x0;
       operation_param2_value_b = 0x0;
       operation_param2_ionref_ionsharefd = 0x0;
       operation_param2_ionref_ionsize = 0x0;

       operation_param3_tmpref_buffer = 0x0;
       operation_param3_tmpref_size = 0x0;
       operation_param3_memref_parent = 0x0;
       operation_param3_memref_size = 0x0;
       operation_param3_memref_offset = 0x0;
       operation_param3_value_a = 0x0;
       operation_param3_value_b = 0x0;
       operation_param3_ionref_ionsharefd = 0x0;
       operation_param3_ionref_ionsize = 0x0;

       operation_param4_tmpref_buffer = 0x0;
       operation_param4_tmpref_size = 0x0;
       operation_param4_memref_parent = 0x0;
       operation_param4_memref_size = 0x0;
       operation_param4_memref_offset = 0x0;
       operation_param4_value_a = 0x0;
       operation_param4_value_b = 0x0;
       operation_param4_ionref_ionsharefd = 0x0;
       operation_param4_ionref_ionsize = 0x0;

       operation_session = 0x0;
       operation_cancelflag = 0x0;

       returnorigin = 0x0;

       buffer1_realsize = 0;
       buffer1_outsize = buffer1_realsize;

       buffer2_realsize = 0;
       buffer2_outsize = buffer2_realsize;

       buffer3_realsize = 0;
       buffer3_outsize = buffer3_realsize;

       buffer4_realsize = 0;
       buffer4_outsize = buffer4_realsize;
    }
    else
   {
    method_call_teec_invokecommand(
       workername,

       in_session_sessionid,
       in_session_serviceid_timelow,
       in_session_serviceid_timemid,
       in_session_serviceid_timehiandver,
       in_session_serviceid_clockseqandnode,
       in_session_serviceid_clockseqandnode_realsize,
       in_session_opscnt,
       in_session_head_next,
       in_session_head_prev,
       in_session_context,

       in_commandid,

       in_operation_started,
       in_operation_paramtypes,

       in_operation_param1_tmpref_buffer,
       in_operation_param1_tmpref_size,
       in_operation_param1_memref_parent,
       in_operation_param1_memref_parent_flag,
       in_operation_param1_memref_size,
       in_operation_param1_memref_offset,
       in_operation_param1_value_a,
       in_operation_param1_value_b,
       in_operation_param1_ionref_ionsharefd,
       in_operation_param1_ionref_ionsize,

       in_operation_param2_tmpref_buffer,
       in_operation_param2_tmpref_size,
       in_operation_param2_memref_parent,
       in_operation_param2_memref_parent_flag,
       in_operation_param2_memref_size,
       in_operation_param2_memref_offset,
       in_operation_param2_value_a,
       in_operation_param2_value_b,
       in_operation_param2_ionref_ionsharefd,
       in_operation_param2_ionref_ionsize,

       in_operation_param3_tmpref_buffer,
       in_operation_param3_tmpref_size,
       in_operation_param3_memref_parent,
       in_operation_param3_memref_parent_flag,
       in_operation_param3_memref_size,
       in_operation_param3_memref_offset,
       in_operation_param3_value_a,
       in_operation_param3_value_b,
       in_operation_param3_ionref_ionsharefd,
       in_operation_param3_ionref_ionsize,

       in_operation_param4_tmpref_buffer,
       in_operation_param4_tmpref_size,
       in_operation_param4_memref_parent,
       in_operation_param4_memref_parent_flag,
       in_operation_param4_memref_size,
       in_operation_param4_memref_offset,
       in_operation_param4_value_a,
       in_operation_param4_value_b,
       in_operation_param4_ionref_ionsharefd,
       in_operation_param4_ionref_ionsize,

       in_operation_session,
       in_operation_cancelflag,

       in_returnorigin,

       in_buffer1,
       in_buffer1_realsize,
       in_buffer2,
       in_buffer2_realsize,
       in_buffer3,
       in_buffer3_realsize,
       in_buffer4,
       in_buffer4_realsize,


       &teecresult,

       &sessionid,
       &serviceid_timelow,
       &serviceid_timemid,
       &serviceid_timehiandver,
       serviceid_clockseqandnode,
       serviceid_clockseqandnode_realsize,
       &serviceid_clockseqandnode_outsize_temp,

       &opscnt,
       &head_next,
       &head_prev,
       &context,

       &started,
       &paramtypes,

       &operation_param1_tmpref_buffer,
       &operation_param1_tmpref_size,
       &operation_param1_memref_parent,
       &operation_param1_memref_parent_flag,
       &operation_param1_memref_size,
       &operation_param1_memref_offset,
       &operation_param1_value_a,
       &operation_param1_value_b,
       &operation_param1_ionref_ionsharefd,
       &operation_param1_ionref_ionsize,

       &operation_param2_tmpref_buffer,
       &operation_param2_tmpref_size,
       &operation_param2_memref_parent,
       &operation_param2_memref_parent_flag,
       &operation_param2_memref_size,
       &operation_param2_memref_offset,
       &operation_param2_value_a,
       &operation_param2_value_b,
       &operation_param2_ionref_ionsharefd,
       &operation_param2_ionref_ionsize,

       &operation_param3_tmpref_buffer,
       &operation_param3_tmpref_size,
       &operation_param3_memref_parent,
       &operation_param3_memref_parent_flag,
       &operation_param3_memref_size,
       &operation_param3_memref_offset,
       &operation_param3_value_a,
       &operation_param3_value_b,
       &operation_param3_ionref_ionsharefd,
       &operation_param3_ionref_ionsize,

       &operation_param4_tmpref_buffer,
       &operation_param4_tmpref_size,
       &operation_param4_memref_parent,
       &operation_param4_memref_parent_flag,
       &operation_param4_memref_size,
       &operation_param4_memref_offset,
       &operation_param4_value_a,
       &operation_param4_value_b,
       &operation_param4_ionref_ionsharefd,
       &operation_param4_ionref_ionsize,

       &operation_session,
       &operation_cancelflag,

       &returnorigin_temp,

       buffer1_temp,
       buffer1_size,
       &buffer1_outsize_temp,
       buffer2_temp,
       buffer2_size,
       &buffer2_outsize_temp,
       buffer3_temp,
       buffer3_size,
       &buffer3_outsize_temp,
       buffer4_temp,
       buffer4_size,
       &buffer4_outsize_temp
    );

    serviceid_clockseqandnode_outsize =
       serviceid_clockseqandnode_outsize_temp;

    returnorigin = returnorigin_temp;

    buffer1_outsize = buffer1_outsize_temp;
    buffer2_outsize = buffer2_outsize_temp;
    buffer3_outsize = buffer3_outsize_temp;
    buffer4_outsize = buffer4_outsize_temp;

    buffer1_realsize = buffer1_outsize;
    if (buffer1_realsize > 0)
    {
       buffer1 =
             (dbus_uint32_t *)malloc(
                                     buffer1_realsize * sizeof(dbus_uint32_t)
                                    );
       for (int i = 0; i < buffer1_realsize ; i++) {
          buffer1[i] = (dbus_uint32_t)buffer1_temp[i];
       }
    }

    buffer2_realsize = buffer2_outsize;
    if (buffer2_realsize > 0)
    {
       buffer2 =
                (dbus_uint32_t *)malloc(
                                     buffer2_realsize * sizeof(dbus_uint32_t)
                                    );
       for (int i = 0; i < buffer2_realsize ; i++) {
          buffer2[i] = (dbus_uint32_t)buffer2_temp[i];
       }
    }

    buffer3_realsize = buffer3_outsize;
    if (buffer3_realsize > 0)
    {
       buffer3 =
             (dbus_uint32_t *)malloc(
                                     buffer3_realsize * sizeof(dbus_uint32_t)
                                    );
       for (int i = 0; i < buffer3_realsize ; i++) {
          buffer3[i] = (dbus_uint32_t)buffer3_temp[i];
       }
    }

    buffer4_realsize = buffer4_outsize;
    if (buffer4_realsize > 0)
    {
       buffer4 =
             (dbus_uint32_t *)malloc(
                                     buffer4_realsize * sizeof(dbus_uint32_t)
                                    );
       for (int i = 0; i < buffer4_realsize ; i++) {
          buffer4[i] = (dbus_uint32_t)buffer4_temp[i];
       }
    }

   } // end of the else  found == 1

    if ( buffer1_temp != NULL )
    {
       free(buffer1_temp);
    }
    if ( buffer2_temp != NULL )
    {
       free(buffer2_temp);
    }
    if ( buffer3_temp != NULL )
    {
       free(buffer3_temp);
    }
    if ( buffer4_temp != NULL )
    {
       free(buffer4_temp);
    }
#endif
   ///////////////////////////////////////////////////////////////////////////////////////////
   ///////////////////////////////////////////////////////////////////////////////////////////
   ///////////////////////////////////////////////////////////////////////////////////////////

   // create a reply from the message
   reply = dbus_message_new_method_return(msg);


   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   dbus_message_iter_open_container(
         &args,
         DBUS_TYPE_STRUCT,
         NULL,
         &structIter
   );


   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &teecresult
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &sessionid
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timelow
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timemid
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_timehiandver
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &serviceid_clockseqandnode_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (serviceid_clockseqandnode_outsize > 0 &&
       serviceid_clockseqandnode != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &serviceid_clockseqandnode,
                  serviceid_clockseqandnode_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &opscnt
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &head_next
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &head_prev
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &context
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &started
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &paramtypes
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param1_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param1_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_memref_parent_flag
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param1_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param1_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param2_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param2_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_memref_parent_flag
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param2_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param2_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param3_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param3_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_memref_parent_flag
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param3_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param3_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param4_tmpref_buffer
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_tmpref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_param4_memref_parent
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_memref_parent_flag
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_memref_size
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_memref_offset
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_value_a
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_value_b
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_param4_ionref_ionsharefd
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &operation_param4_ionref_ionsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT64,
               &operation_session
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_INT32,
               &operation_cancelflag
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &returnorigin
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &buffer1_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (buffer1_outsize > 0 &&
       buffer1 != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &buffer1,
                  buffer1_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &buffer2_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (buffer2_outsize > 0 &&
       buffer2 != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &buffer2,
                  buffer2_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &buffer3_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (buffer3_outsize > 0 &&
       buffer3 != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &buffer3,
                  buffer3_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   bResult =
         dbus_message_iter_append_basic(
               &structIter,
               DBUS_TYPE_UINT32,
               &buffer4_outsize
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   if (buffer4_outsize > 0 &&
       buffer4 != NULL
         )
   {
      dbus_message_iter_open_container(
            &structIter,
            DBUS_TYPE_ARRAY,
            buf,
            &ArrayIter
      );

      bResult =
            dbus_message_iter_append_fixed_array(
                  &ArrayIter,
                  DBUS_TYPE_UINT32,
                  &buffer4,
                  buffer4_realsize
            );

      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory!\n");
         dbus_message_iter_close_container(
               &structIter,
               &ArrayIter
         );
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_connection_flush(conn);
         dbus_message_unref(msg);
         return NULL;
      }

      dbus_message_iter_close_container(
            &structIter,
            &ArrayIter
      );
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   // send the reply && flush the connection
   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      free(thdfargs);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_connection_flush(conn);
   dbus_message_unref(msg);
   // dbus_connection_close(conn);
   // dbus_connection_unref(conn);
   free(thdfargs);
   //printf("gpworker %d\n",__LINE__);

   // sleep(2);

   return NULL;
}


#ifdef GP_PROXY
   void*
session_timeout_process (
   void* thdfargs
)
{
   DBusMsgConn* DBusMCP;
   pthread_mutex_t * mutex_workerrec;
   wr_t * workerrec;

   DBusMCP = (DBusMsgConn*)thdfargs;
   mutex_workerrec = DBusMCP->mutex_workerrec;
   workerrec = DBusMCP->workerrec;

   struct timeval tv;
   uint64_t u64time;

   char workername[1024];
   memset((char *)workername, 0, 1024);
   int iworker;

   dbus_uint32_t in_session_seesionid;
   dbus_uint32_t in_session_serviceid_timelow = 0;
   dbus_uint32_t in_session_serviceid_timemid = 0;
   dbus_uint32_t in_session_serviceid_timehiandver = 0;
   dbus_uint32_t in_session_serviceid_clockseqandnode_size = 8;
   dbus_uint32_t in_session_serviceid_clockseqandnode[8];
   dbus_uint32_t in_session_opscnt = 0;
   dbus_uint64_t in_session_head_next = 0;
   dbus_uint64_t in_session_head_prev = 0;
   dbus_uint64_t in_session_context;

   dbus_uint32_t seesionid;
   dbus_uint32_t serviceid_timelow;
   dbus_uint32_t serviceid_timemid;
   dbus_uint32_t serviceid_timehiandver;
   dbus_uint32_t * serviceid_clockseqandnode;
   int           serviceid_clockseqandnode_realsize;
   dbus_uint32_t opscnt;
   dbus_uint64_t head_next;
   dbus_uint64_t head_prev;
   dbus_uint64_t context;

   sin_t * sinIns;

  while (1)
  {
   sleep(TIMEDOUT_SESSION);

   pthread_mutex_lock(mutex_workerrec);
   for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
   {
      if (workerrec[iworker].busy == 1)
      {
         sinIns = NULL;
         if (workerrec[iworker].first != NULL)
         {
            sinIns = workerrec[iworker].first;
            do
            {
               gettimeofday(&tv, NULL);
               u64time = (long unsigned int)(tv.tv_sec -
                            sinIns->session_createtime.tv_sec
	                 );
               sin_t * sinTemp = NULL;

	       if (u64time > TIMEDOUT_SESSION)
	       {
                  sprintf(workername, "%s%d", "gpworker", iworker);

                  in_session_seesionid = sinIns->session_id;
                  in_session_context = workerrec[iworker].context_addr;

		  for (int iind = 0; iind < 8; iind++)
		  {
		     in_session_serviceid_clockseqandnode[iind] = 0;
                  }

                  pthread_mutex_unlock(mutex_workerrec);

	          uint32_t serviceid_clockseqandnode_outsize_temp;
                  serviceid_clockseqandnode_realsize = 8;
                  serviceid_clockseqandnode =
                     (dbus_uint32_t *)malloc(
                        serviceid_clockseqandnode_realsize * sizeof(dbus_uint32_t)
                     );

                  printf("\nMethod call teec closesession. (Called by Proxy for timeout process) \n");
		  method_call_teec_closesession(
                     workername,

                     in_session_seesionid,
                     in_session_serviceid_timelow,
                     in_session_serviceid_timemid,
                     in_session_serviceid_timehiandver,
                     in_session_serviceid_clockseqandnode,
                     in_session_serviceid_clockseqandnode_size,
                     in_session_opscnt,
                     in_session_head_next,
                     in_session_head_prev,
                     in_session_context,

                     &seesionid,
                     &serviceid_timelow,
                     &serviceid_timemid,
                     &serviceid_timehiandver,
                     serviceid_clockseqandnode,
                     serviceid_clockseqandnode_realsize,
                     &serviceid_clockseqandnode_outsize_temp,
                     &opscnt,
                     &head_next,
                     &head_prev,
                     &context
                  );

                  if (serviceid_clockseqandnode != NULL) {
                     free(serviceid_clockseqandnode);
	          }

     		  pthread_mutex_lock(mutex_workerrec);

                  sinTemp = sinIns->prev;
                  if (sinTemp != NULL)
                  {
                     sinTemp->next = sinIns->next;
                  }
                  sinTemp = sinIns->next;
                  if (sinTemp != NULL)
                  {
                     sinTemp->prev = sinIns->prev;
                  }
                  if (workerrec[iworker].last == sinIns)
                  {
                     workerrec[iworker].last = sinIns->prev;
                  }
                  if (workerrec[iworker].first == sinIns)
                  {
                     workerrec[iworker].first = sinIns->next;
                  }

                  // free(sinIns);
                  sinTemp = sinIns;
                  workerrec[iworker].sessionid_count =
                     workerrec[iworker].sessionid_count - 1;

	       } // end of if timedout
	       sinIns = sinIns->next;
	       if (sinTemp != NULL)
	       {
	          free(sinTemp);
	       }
            }while (sinIns != NULL);


         } // end of the first not null
      } // end of the busy = 1
   } // end of the for iworker
   pthread_mutex_unlock(mutex_workerrec);

  } // end of while 1


   free(thdfargs);
   return NULL;
}


void*
context_timeout_process (
   void* thdfargs
)
{
   DBusMsgConn* DBusMCP;
   pthread_mutex_t * mutex_workerrec;
   pthread_cond_t  * cond_notbusy;
   wr_t * workerrec;

   DBusMCP = (DBusMsgConn*)thdfargs;
   mutex_workerrec = DBusMCP->mutex_workerrec;
   cond_notbusy = DBusMCP->cond_notbusy;
   workerrec = DBusMCP->workerrec;



   struct timeval tv;
   uint64_t u64time;

   char workername[1024];
   memset((char *)workername, 0, 1024);
   int iworker;

   dbus_int32_t  in_fd;
   unsigned char * in_ta_path = NULL;
   dbus_int32_t  in_ta_path_size = 0;
   dbus_uint64_t in_session_list_next = 0;
   dbus_uint64_t in_session_list_prev = 0;
   dbus_uint64_t in_shrd_mem_list_next = 0;
   dbus_uint64_t in_shrd_mem_list_prev = 0;
   dbus_uint64_t in_share_buffer_buffer = 0;
   dbus_int64_t  in_share_buffer_buffer_barrier = 0;
   dbus_uint64_t in_context_addr;

   dbus_int32_t  fd;
   unsigned char * ta_path;
   dbus_int32_t  ta_path_size;
   dbus_uint64_t session_list_next;
   dbus_uint64_t session_list_prev;
   dbus_uint64_t shrd_mem_list_next;
   dbus_uint64_t shrd_mem_list_prev;
   dbus_uint64_t share_buffer_buffer;
   dbus_int64_t  share_buffer_buffer_barrier;
   uint32_t context_tapath_outsize;

   while(1)
   {
      sleep(TIMEDOUT_CONTEXT);

      pthread_mutex_lock(mutex_workerrec);
      for (iworker = 0; iworker < MAX_NUM_WORKER; iworker++)
      {
         if (workerrec[iworker].busy == 1)
	 {
            sprintf(workername, "%s%d", "gpworker", iworker);
            gettimeofday(&tv, NULL);
            u64time = (long unsigned int)(tv.tv_sec -
                         workerrec[iworker].context_createtime.tv_sec
		      );
	    if (u64time > TIMEDOUT_CONTEXT
                &&
		workerrec[iworker].sessionid_count == 0
	       )
	    {
               in_fd = workerrec[iworker].context_fd;
               in_context_addr = workerrec[iworker].context_addr;
               ta_path = (unsigned char *)malloc(1024 * sizeof(char));
               ta_path_size = 1024;
               memset((char *)ta_path, 0, 1024);

     	       pthread_mutex_unlock(mutex_workerrec);

               printf("\nMethod call teec fincont. (Called by Proxy for timeout process) \n");
               method_call_teec_fincont(
		  workername,

                  in_fd,
                  in_ta_path,
		  in_ta_path_size,
                  in_session_list_next,
                  in_session_list_prev,
                  in_shrd_mem_list_next,
                  in_shrd_mem_list_prev,
                  in_share_buffer_buffer,
                  in_share_buffer_buffer_barrier,
		  in_context_addr,

                  &fd,
                  ta_path,
	  	  ta_path_size,
                  &session_list_next,
                  &session_list_prev,
                  &shrd_mem_list_next,
                  &shrd_mem_list_prev,
                  &share_buffer_buffer,
                  &share_buffer_buffer_barrier,

                  &context_tapath_outsize
               );

	       if (ta_path != NULL)
	       {
                  free(ta_path);
	       }

     	       pthread_mutex_lock(mutex_workerrec);

               workerrec[iworker].busy = 0;
               pthread_cond_signal(cond_notbusy);
               workerrec[iworker].context_fd = 0;
               workerrec[iworker].context_addr = 0xffffffff;
               workerrec[iworker].sessionid_count = 0;
               sin_t * sinIns;
               sin_t * sinInsPrev;
               sinIns = workerrec[iworker].last;
               if (sinIns != NULL)
               {
	          for ( ; ; )
                  {
                     sinInsPrev = sinIns->prev;
                     free(sinIns);
                     sinIns = sinInsPrev;
                     if (sinIns == NULL)
                     {
                        break;
                     }
                  }
               }

	    } // end of the if timeed out
         } // end of the if busy = 1
      } // end of the for iworker
      pthread_mutex_unlock(mutex_workerrec);

   } // end of while 1

   free(thdfargs);
   return NULL;
}
#endif


void *
reply_to_method_call_destroy_threadpool(
      DBusMessage *msg,
      DBusConnection *conn,
      threadpool_t *pool
#ifdef GP_WORKER
      ,
      pthread_mutex_t *mutex_tcl,
      pthread_mutex_t *mutex_tsl
#endif

#ifdef GP_PROXY
     ,
	        pthread_mutex_t * mutex_workerrec,
                pthread_cond_t  * cond_notbusy
#endif
)
{
   DBusMessage *reply;
   DBusMessageIter args;
   // char* param = "";
   char *param = NULL;
   dbus_bool_t bResult;
   dbus_uint32_t retcode;
   dbus_uint32_t serial = 0;

   // read the arguments
   if (!dbus_message_iter_init(msg, &args))
      fprintf(stderr, "Message has no arguments!\n");
   else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
      fprintf(stderr, "Argument is not string!\n");
   else
      dbus_message_iter_get_basic(&args, &param);

   printf("\n");
   printf("Received mechod call Destroy: \n");
   printf("   param                       = %s \n", param);
   printf("\n");

   // create a reply from the message
   reply = dbus_message_new_method_return(msg);

   retcode = 0x00;

   // add the arguments to the reply
   dbus_message_iter_init_append(reply, &args);
   bResult =
         dbus_message_iter_append_basic(
               &args,
               DBUS_TYPE_UINT32,
               &retcode
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return NULL;
   }

   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory!\n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      dbus_message_unref(msg);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_connection_flush(conn);
   dbus_message_unref(msg);
   // dbus_connection_close(conn);
   // dbus_connection_unref(conn);


   threadpool_destroy(pool);

#ifdef GP_WORKER
   pthread_mutex_destroy(mutex_tcl);
   pthread_mutex_destroy(mutex_tsl);
#endif

#ifdef GP_PROXY
                                                                                                                           pthread_mutex_destroy(mutex_workerrec);
   pthread_cond_destroy(cond_notbusy);
#endif

   printf("\n");
   printf("This process exits. \n");
   printf("\n");

   exit(1);

   return NULL;
}

#endif
