#ifndef _SPIFFEJWT_H
#define _SPIFFEJWT_H

int spiffe_start_conn();
int spiffe_close_conn();
int spiffe_fetch_jwtsvid(
     char * token
);
int spiffe_validate_jwtsvid(
    char * token
);

#endif // _SPIFFEJWT_H
