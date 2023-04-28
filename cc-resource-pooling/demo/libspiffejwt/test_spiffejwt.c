#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "spiffejwt.h"


#define NO_ERROR 0


int main()
{
   char token[1024];
   int iResult;


   iResult = spiffe_start_conn();
   if (iResult != NO_ERROR)
   {
      return -1;
   }

   iResult = spiffe_fetch_jwtsvid(
         token
   );
   if (iResult != NO_ERROR)
   {
      return -1;
   } else
   {
      printf("The feteched token: %s \n", token);
   }

   iResult = spiffe_validate_jwtsvid(
         token
   );
   if (iResult != NO_ERROR)
   {
      printf("Token validate failed. \n");
      return -1;
   } else
   {
      printf("Token validate succed. \n");
   }

   spiffe_close_conn();

   return 0;
}

