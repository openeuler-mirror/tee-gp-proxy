#ifndef _DBUSC_JWT_H
#define _DBUSC_JWT_H

#ifdef __cplusplus
extern "C" {
#endif

int dbusmethodcall_fetch_jwt(
      char *token
);

int dbusmethodcall_validate_jwt(
      // const char * taname,
      char *token
);

/*
int dbusmethodcall_restart(
   const char * taname
);
 */

#ifdef __cplusplus
}
#endif

#endif
