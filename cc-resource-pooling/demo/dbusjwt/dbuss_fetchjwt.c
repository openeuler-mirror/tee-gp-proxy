#include <dbus/dbus.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "spiffejwt.h"

#include "dbus_return_code.h"

#define NO_ERROR 0


void *
reply_methodcall_fetch_jwtsvid(
      DBusMessage *msg,
      DBusConnection *conn
)
{
   DBusMessage *reply;
   DBusMessageIter args;
   dbus_bool_t bResult;
   dbus_uint32_t retcode;
   dbus_uint32_t serial = 0;
   DBusMessageIter structIter;
   char token[1024] = "noToken";

   printf("\n");
   printf("Received mechod call fetch_jwtsvid. \n");

   // read the arguments
   if (!dbus_message_iter_init(msg, &args))
   {
      fprintf(stderr, "Message has no arguments!\n");
      retcode = TEEC_ERROR_DBUS_MSG_NULL;
   } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args))
   {
      fprintf(stderr, "Argument is not string!\n");
      retcode = TEEC_ERROR_DBUS_ARG_TYPE_ERROR;
   } else
   {
      dbus_message_iter_get_basic(&args, &token);

      int iResult = spiffe_fetch_jwtsvid(
            token
      );
      if (iResult == NO_ERROR)
      {
         printf("Token fetching succed, token = %s \n", token);
         retcode = 0;
      } else
      {
         retcode = TEEC_ERROR_FETCHJWT_ERROR;
      }
   }

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
               &retcode
         );
   if (!bResult)
   {
      fprintf(stderr, "Out Of Memory! \n");
      dbus_message_iter_close_container(
            &args,
            &structIter
      );
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      return NULL;
   }

   if (retcode == 0)
   {
      unsigned char *charp;
      charp = token;
      bResult =
            dbus_message_iter_append_basic(
                  &structIter,
                  DBUS_TYPE_STRING,
                  &charp
            );
      if (!bResult)
      {
         fprintf(stderr, "Out Of Memory! \n");
         dbus_message_iter_close_container(
               &args,
               &structIter
         );
         dbus_message_unref(reply);
         dbus_connection_flush(conn);
         return NULL;
      }
   }

   dbus_message_iter_close_container(
         &args,
         &structIter
   );

   serial = 100;
   if (!dbus_connection_send(conn, reply, &serial))
   {
      fprintf(stderr, "Out Of Memory! \n");
      dbus_message_unref(reply);
      dbus_connection_flush(conn);
      return NULL;
   }

   dbus_message_unref(reply);
   dbus_connection_flush(conn);

   return NULL;
}

/**
 * Server that exposes a method call and waits for it to be called
 */
void
receive_methodcall(
)
{
   DBusMessage *msg;
   DBusConnection *conn;
   DBusError err;
   int ret;
   dbus_bool_t bResult;


   printf("Dbus server for fetching jwt is listening for method calls ... \n");

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
      exit(1);
   }

   if (NULL == conn)
   {
      fprintf(stderr, "Connection Null. \n");
      exit(1);
   }

   char dbusname[1024];
   memset((char *) dbusname, 0, 1024);
   // sprintf(dbusname, "%s.method.server", argv[1]);
   sprintf(dbusname, "%s.method.server", "fetchjwt");
   // request our name on the bus and check for errors
   ret =
         dbus_bus_request_name(
               conn,
               dbusname,
               DBUS_NAME_FLAG_REPLACE_EXISTING,
               &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "Name Error (%s)\n", err.message);
      dbus_error_free(&err);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      exit(1);
   }
   if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
   {
      fprintf(stderr, "Not Primary Owner (%d)\n", ret);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      exit(1);
   }

   // loop, testing for new messages
   memset((char *) dbusname, 0, 1024);
   // sprintf(dbusname, "%s.method.Type", argv[1]);
   sprintf(dbusname, "%s.method.Type", "fetchjwt");
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

      // printf("Received one method call. \n");

      // check this is a method call for the right interface & method
      bResult = dbus_message_is_method_call(
            msg,
            dbusname,
            "fetch_jwtsvid"
      );
      if (bResult == TRUE)
      {
         reply_methodcall_fetch_jwtsvid(
               msg,
               conn
         );
      }

      // free the message
      dbus_message_unref(msg);

   } // end of the while true

} // end of the function


int main(int argc, char *argv[])
{
   int iResult;

   iResult = spiffe_start_conn();
   if (iResult != NO_ERROR)
   {
      fprintf(stderr, "Spiffe start conn failed. \n");
      return -1;
   }

   receive_methodcall(
   );

   return 0;
}
