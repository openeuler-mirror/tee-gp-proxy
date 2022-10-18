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

#include "dbusc_gpw.h"


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

   /*
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
    */

   // printf("\n");
   printf("libdbuscgpw method call teec init contex sent. \n");

   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbuscgpw: initcontext send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbuscgpw: initcontext dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }

   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   msg = reply;

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

   printf("libdbuscgpw got reply of method call teec init contex: \n");
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
      // if (dbus_validate_utf8((const char *) in_context_tapath, &err) == true)
      if (dbus_validate_path((const char *) in_context_tapath, &err) == true)
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

   fprintf(stderr, "libdbuscgpw finalizecontext, in_context_tapath_size, di32Temp = %ld \n", di32Temp);
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
      fprintf(stderr, "libdbuscgpw finalizecontext, in_context_tapath = %s \n", in_context_tapath);

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


   /* 
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

   // printf("\n");
   printf("libdbuscgpw method call teec fin contex sent. \n");

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
    */


   // printf("\n");
   printf("libdbuscgpw method call teec fin contex sent. \n");

   dbus_error_init(&err);
   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbuscgpw: finalizecontext send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbuscgpw: finalizecontext dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }

   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   msg = reply;


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

   if (*context_tapath_outsize > 0)
   {
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

   }

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

   printf("libdbuscgpw got reply of method call teec fin contex: \n");
   printf("   fd                          = 0x %8.8x \n", (unsigned int) *context_fd);
   printf("   ta_path_size                = %d \n", (int) *context_tapath_outsize);
   if ((int) *context_tapath_outsize > 0 && context_tapath_temp != NULL &&
       dbus_validate_path((const char *) context_tapath_temp, &err) == true)
   {
      printf("   ta_path                     = %s \n", context_tapath_temp);
   }
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

   /*
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
    */

   // printf("\n");
   printf("libdbuscgpw method call teec open session sent. \n");

   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbuscgpw: opensession send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbuscgpw: opensession dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }

   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   msg = reply;

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

   printf("libdbuscgpw got reply of method call teec open session: \n");
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
      /*
       memcpy(
	       session_serviceid_clockseqandnode,
	       session_serviceid_clockseqandnode_temp,
	       session_serviceid_clockseqandnode_realsize
	      );
	    */
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

   /*
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
    */

   // printf("\n");
   printf("libdbuscgpw method call teec close session sent. \n");

   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbuscgpw: closesession send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbuscgpw: closesession dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }

   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   msg = reply;

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


   printf("libdbuscgpw got reply of method call teec close session: \n");
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
      int32_t in_operation_param2_ionref_ionsharefd,
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

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   /*
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
    */

   // printf("\n");
   printf("libdbuscgpw method call teec invoke command sent. \n");

   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbuscgpw: invokecommand send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbuscgpw: invokecommand dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return -1;
   }

   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   msg = reply;

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


   printf("libdbuscgpw got reply of method call teec invoke command: \n");
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
      return;
   }

   /*
   // send message and get a handle for a reply
   if (!dbus_connection_send_with_reply(conn, msg, &pending, -1))
   {  // -1 is default timeout
      fprintf(stderr, "Out Of Memory!\n");
      return;
   }
   if (NULL == pending)
   {
      fprintf(stderr, "Pending Call Null\n");
      return;
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
      return;
   }
   // free the pending message handle
   dbus_pending_call_unref(pending);
    */

   // printf("\n");
   printf("libdbuscgpw method call destroygpw sent. \n");

   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbuscgpw: destroygpw send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbuscgpw: destroygpw dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return;
   }

   dbus_message_unref(msg);
   dbus_connection_flush(conn);
   msg = reply;

   // read the parameters
   bResult =
         dbus_message_iter_init(
               msg,
               &args
         );
   if (!bResult)
   {
      fprintf(stderr, "Message has no arguments!\n");
      return;
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
      return;
   }
   dbus_message_iter_get_basic(
         &args,
         &retcode
   );

   printf("libdbusgpw got reply of method call destroygpw: \n");
   printf("   retcode                     = 0x%8x \n", retcode);

   // free reply
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);
}
