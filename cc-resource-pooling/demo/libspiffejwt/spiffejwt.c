#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c-spiffe/workload/client.h"

#include "spiffejwt.h"


workloadapi_Client *client;


int spiffe_start_conn()
{
   err_t error = NO_ERROR;

   client = workloadapi_NewClient(&error);

   workloadapi_Client_SetAddress(client, "unix:///tmp/spire-agent/public/api.sock");

   workloadapi_Client_SetHeader(client, "workload.spiffe.io", "true");
   if (error != NO_ERROR)
   {
      // printf("client error! %d\n", (int) error);
      return error;
   }

   error = workloadapi_Client_Connect(client);
   if (error != NO_ERROR)
   {
      // printf("conn error! %d\n", (int) error);
      return error;
   }

   return NO_ERROR;
}


int spiffe_close_conn()
{
   if (client == NULL)
   {
      return -1;
   }

   err_t error = NO_ERROR;

   error = workloadapi_Client_Close(client);
   if (error != NO_ERROR)
   {
      // printf("close error! %d\n", (int) error);
      return error;
   }

   workloadapi_Client_Free(client);
   if (error != NO_ERROR)
   {
      // printf("client free error! %d\n", (int) error);
      return error;
   }

   return NO_ERROR;
}

bool utf8_check_is_valid(const char *string)
{
   if (!string)
      return 0;

   const unsigned char *bytes = (const unsigned char *) string;
   while (*bytes)
   {
      if ((// ASCII
            // use bytes[0] <= 0x7F to allow ASCII control characters
            bytes[0] == 0x09 ||
            bytes[0] == 0x0A ||
            bytes[0] == 0x0D ||
            (0x20 <= bytes[0] && bytes[0] <= 0x7E)
      )
            )
      {
         bytes += 1;
         continue;
      }

      if ((// non-overlong 2-byte
            (0xC2 <= bytes[0] && bytes[0] <= 0xDF) &&
            (0x80 <= bytes[1] && bytes[1] <= 0xBF)
      )
            )
      {
         bytes += 2;
         continue;
      }

      if ((// excluding overlongs
                bytes[0] == 0xE0 &&
                (0xA0 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
          ) ||
          (// straight 3-byte
                ((0xE1 <= bytes[0] && bytes[0] <= 0xEC) ||
                 bytes[0] == 0xEE ||
                 bytes[0] == 0xEF) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
          ) ||
          (// excluding surrogates
                bytes[0] == 0xED &&
                (0x80 <= bytes[1] && bytes[1] <= 0x9F) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF)
          )
            )
      {
         bytes += 3;
         continue;
      }

      if ((// planes 1-3
                bytes[0] == 0xF0 &&
                (0x90 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
          ) ||
          (// planes 4-15
                (0xF1 <= bytes[0] && bytes[0] <= 0xF3) &&
                (0x80 <= bytes[1] && bytes[1] <= 0xBF) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
          ) ||
          (// plane 16
                bytes[0] == 0xF4 &&
                (0x80 <= bytes[1] && bytes[1] <= 0x8F) &&
                (0x80 <= bytes[2] && bytes[2] <= 0xBF) &&
                (0x80 <= bytes[3] && bytes[3] <= 0xBF)
          )
            )
      {
         bytes += 4;
         continue;
      }

      return 0;
   }

   return 1;
}


int spiffe_fetch_jwtsvid(
      char *token
)
{
   err_t error = NO_ERROR;

   if (client == NULL)
   {
      return -1;
   }

   spiffeid_ID id = {string_new("example.org"),
                     string_new("/myservice")};
   string_t audience = string_new("spiffe://example.org/audience");
   jwtsvid_Params params
         = {.audience = audience, .extra_audiences = NULL, .subject = id};
   jwtsvid_SVID *svid
         = workloadapi_Client_FetchJWTSVID(client, &params, &error);
   if (error != NO_ERROR)
   {
      // printf("fetch error! %d\n", (int) error);
      return error;
   }
   // printf("Address: %p\n", svid);

   spiffeid_ID_Free(&id);
   arrfree(audience);

   if (svid)
   {
      if (token == NULL)
      {
         jwtsvid_SVID_Free(svid);
         return -1;
      } else
      {
         if (sizeof(token) < sizeof(svid->token))
         {
            jwtsvid_SVID_Free(svid);
            return -1;
         } else
         {
            bool bResult;
            bResult = utf8_check_is_valid(svid->token);
            if (bResult == false)
            {
               return -1;
            }

            memset(token, '\0', sizeof(token));
            strcpy(token, svid->token);
            jwtsvid_SVID_Free(svid);
         }
      }
   } else
   {
      return -1;
   }

   return NO_ERROR;
}


int spiffe_validate_jwtsvid(
      char *token
)
{
   err_t error = NO_ERROR;

   if (client == NULL)
   {
      return -1;
   }

   if (token == NULL)
   {
      return -1;
   }

   bool bResult;
   bResult = utf8_check_is_valid(token);
   if (bResult == false)
   {
      return -1;
   }

   // string_t audience = string_new(audience_name);
   string_t audience = string_new("spiffe://example.org/audience");
   jwtsvid_SVID *svid = workloadapi_Client_ValidateJWTSVID(
         client, token, audience, &error);
   // printf("%s %d: spiffe_validate_jwtsvid error = %d \n", __FILE__, __LINE__, (int)error);
   printf("libspiffejwt: spiffe_validate_jwtsvid error = %d \n", (int) error);
   if (error != NO_ERROR)
   {
      return error;
   }

   if (svid)
   {
      jwtsvid_SVID_Free(svid);
   }
   arrfree(audience);

   return NO_ERROR;
}
