#include <dbus/dbus.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include "dbus_return_code.h"


TEEC_Result dbusmethodcall_fetch_jwt(
      char *token
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

   unsigned char *charp;
   unsigned char param[12] = "fetchtoken";
   DBusMessageIter structIter;
   dbus_uint32_t retcode;
   unsigned char *token_temp = NULL;


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
         return TEEC_ERROR_DBUS_CONN_NULL;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              "fetchjwt",
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
         return TEEC_ERROR_DBUS_NAME_ERROR;
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return TEEC_ERROR_DBUS_NAME_ERROR;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", "fetchjwt");
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", "fetchjwt");
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", "fetchjwt");
   msg =
         dbus_message_new_method_call(
               // "test.method.server",   // target for the method call
               dbusname,
               // "/test/method/Object",  // object to call on
               objname,
               // "test.method.Type",     // interface to call on
               interfacename,
               "fetch_jwtsvid"         // method name
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null \n");
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_MSG_NULL;
   }

   // append arguments
   dbus_message_iter_init_append(msg, &args);

   charp = param;
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &charp))
   {
      fprintf(stderr, "Out Of Memory. \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_APPEND_ERROR;
   }

   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbusc_jwt: fetchjwt send_with_reply_and_block error %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_REPLY_ERROR;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbusc_jwt: fetchjwt dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_REPLY_ERROR;
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
      return TEEC_ERROR_DBUS_ARG_NULL;
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
      return TEEC_ERROR_DBUS_ARG_TYPE_ERROR;
   }
   dbus_message_iter_get_basic(
         &structIter,
         &retcode
   );

   if (retcode == 0)
   {
      bResult =
            dbus_message_iter_next(
                  &structIter
            );
      if (!bResult)
      {
         fprintf(stderr, "Message has too few arguments! \n");
         dbus_message_unref(msg);
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return TEEC_ERROR_DBUS_ARG_NULL;
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
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return TEEC_ERROR_DBUS_ARG_TYPE_ERROR;
      }
      dbus_message_iter_get_basic(
            &structIter,
            &token_temp);

      if (token == NULL)
      {
         dbus_message_unref(msg);
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return TEEC_ERROR_TOKEN_NULL;
      } else
      {
         if (sizeof(token) < sizeof(token_temp))
         {
            dbus_message_unref(msg);
            dbus_connection_close(conn);
            dbus_connection_unref(conn);
            return TEEC_ERROR_TOKEN_SIZE_ERROR;
         } else
         {
            memset(token, '\0', sizeof(token));
            strcpy(token, token_temp);
         }
      }

   }

   // free reply
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return retcode;
}


TEEC_Result dbusmethodcall_validate_jwt(
      char *token
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
         return TEEC_ERROR_DBUS_CONN_NULL;
      }

      memset((uint8_t *) dbusname, 0, 1024);
      struct timeval tv;
      gettimeofday(&tv, NULL);
      uint64_t u64time = (long unsigned int) (tv.tv_sec * 1000000 + tv.tv_usec);
      srand(u64time);
      sprintf(dbusname,
              "%s.method.caller%16.16lx%16.16lx",
              "validatejwt",
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
         return TEEC_ERROR_DBUS_NAME_ERROR;
      }
      if (DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER != ret)
      {
         dbus_connection_flush(conn);
         dbus_connection_close(conn);
         dbus_connection_unref(conn);
         return TEEC_ERROR_DBUS_NAME_ERROR;
      }
   }

   // create a new method call and check for errors
   char objname[1024];
   char interfacename[1024];
   memset((uint8_t *) dbusname, 0, 1024);
   sprintf(dbusname, "%s.method.server", "validatejwt");
   memset((uint8_t *) objname, 0, 1024);
   sprintf(objname, "/%s/method/Object", "validatejwt");
   memset((uint8_t *) interfacename, 0, 1024);
   sprintf(interfacename, "%s.method.Type", "validatejwt");
   msg =
         dbus_message_new_method_call(
               // "test.method.server",   // target for the method call
               dbusname,
               // "/test/method/Object",  // object to call on
               objname,
               // "test.method.Type",     // interface to call on
               interfacename,
               "validate_jwtsvid"         // method name
         );
   if (NULL == msg)
   {
      fprintf(stderr, "Message Null \n");
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_MSG_NULL;
   }

   // append arguments
   dbus_message_iter_init_append(msg, &args);

   if (token == NULL)
   {
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_TOKEN_NULL;
   }

   charp = token;
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &charp))
   {
      fprintf(stderr, "Out Of Memory. \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_APPEND_ERROR;
   }


   DBusMessage *reply;
   reply = dbus_connection_send_with_reply_and_block(conn, msg, -1, &err);
   if (dbus_error_is_set(&err))
   {
      fprintf(stderr, "libdbusc_jwt: validatejwt send_with_reply_and_block error, %s \n", err.message);
      dbus_error_free(&err);

      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_REPLY_ERROR;
   }
   if (reply == NULL)
   {
      fprintf(stderr, "libdbusc_jwt: validatejwt dbus reply error \n");
      dbus_message_unref(msg);
      dbus_connection_flush(conn);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_REPLY_ERROR;
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
      return TEEC_ERROR_DBUS_ARG_NULL;
   }

   iType =
         dbus_message_iter_get_arg_type(
               &args
         );
   if (
         iType != DBUS_TYPE_UINT32
         )
   {
      fprintf(stderr, "Argument is not UINT32. \n");
      dbus_message_unref(msg);
      dbus_connection_close(conn);
      dbus_connection_unref(conn);
      return TEEC_ERROR_DBUS_ARG_TYPE_ERROR;
   }
   dbus_message_iter_get_basic(
         &args,
         &retcode
   );

   printf("libdbusc_jwt: got reply of methodcall validate_jwtsvid \n");
   printf("   retcode = 0x %8x \n", retcode);

   // free reply
   dbus_message_unref(msg);

   dbus_connection_close(conn);
   dbus_connection_unref(conn);

   return retcode;
}

