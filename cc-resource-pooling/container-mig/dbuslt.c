#include <dbus/dbus.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#define DBUSLT_ERROR -1;

int dbusmethodcall_live_transfer(
)
{
   DBusConnection *conn = NULL;
   DBusMessage *msg;
   DBusMessageIter args;
   DBusError err;
   DBusPendingCall *pending;
   dbus_bool_t bResult;
   int ret;
   int iType;

   DBusMessageIter structIter;
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
         return DBUSLT_ERROR;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              "live_transfer",
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
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return DBUSLT_ERROR;
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return DBUSLT_ERROR;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", "live_transfer");
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", "live_transfer");
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", "live_transfer");
   msg =
         dbus_message_new_method_call(
               // "test.method.server",   // target for the method call
               dbusname,
               // "/test/method/Object",  // object to call on
               objname,
               // "test.method.Type",     // interface to call on
               interfacename,
               "live_transfer"         // method name
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null \n");
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return DBUSLT_ERROR;
   }

   dbus_message_set_destination(msg, "live_transfer.method.server");
   // append arguments
   dbus_message_iter_init_append(msg, &args);
   ;
   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);

   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "live_transfer: live_transfer send_with_reply_and_block error %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return DBUSLT_ERROR;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "live_transfer: live_transfer dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return DBUSLT_ERROR;
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
      fprintf(stderr, "Message has no arguments. \n");
      dbus_message_unref(msg);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return DBUSLT_ERROR;
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
      fprintf(stderr, "Argument is not UINT32. \n");
      dbus_message_unref(msg);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return DBUSLT_ERROR;
   }

   dbus_message_iter_get_basic(
         &structIter,
         &retcode
   );

   // free reply
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return retcode;
}

int
send_signal(
)
{
   DBusMessage *msg;
   DBusMessageIter args;
   DBusConnection *conn;
   DBusError err;
   int ret;
   dbus_uint32_t sigserial = 0;
   int sigvalue = 0;
   printf("Sending signal with value %d\n", sigvalue);

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
   char dbusname[1024];
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.signal.server", "live_transfer");
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/signal/Object", "live_transfer");
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.signal.Type", "live_transfer");

   // register our name on the bus, and check for errors
   ret = dbus_bus_request_name(conn, "live_transfer.signal.source", DBUS_NAME_FLAG_REPLACE_EXISTING, &err);
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
   msg = dbus_message_new_signal(objname, // object name of the signal
                                 interfacename, // interface name of the signal
                                 "live_transfer"); // name of the signal
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null\n");
      exit(1);
   }

   // append arguments onto signal
   dbus_message_iter_init_append(msg, &args);
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_INT32, &sigvalue))
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
   return 0;
}
int main()
{
  /* int retcode = -1;
   retcode = dbusmethodcall_live_transfer();
   printf("%d\n",retcode);*/
   send_signal();
   return 0;
}

