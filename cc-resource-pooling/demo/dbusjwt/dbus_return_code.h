//
// Created by 62754 on 2022/8/19.
//

#ifndef _DBUS_RETURN_CODE_H
#define _DBUS_RETURN_CODE_H

enum TEEC_ReturnCode
{
    TEEC_ERROR_JWTVALIDATE_FAIL = 0xAAAA0020,  /* jwt validate fail */
    TEEC_ERROR_GRPC_ERROR = 0xAAAA0021,  /* grpc transmission error */
    TEEC_ERROR_DBUS_CONN_NULL = 0xAAAA0022,  /* dbus connection null */
    TEEC_ERROR_DBUS_NAME_ERROR = 0xAAAA0023,  /* dbus name set is error */
    TEEC_ERROR_DBUS_MSG_NULL = 0xAAAA0024,  /* dbus message is null */
    TEEC_ERROR_DBUS_APPEND_ERROR = 0xAAAA0025,  /* dbus append argument error */
    TEEC_ERROR_DBUS_REPLY_ERROR = 0xAAAA0026,  /* dbus send with reply error */
    TEEC_ERROR_DBUS_ARG_NULL = 0xAAAA0027,  /* dbus argument is null */
    TEEC_ERROR_DBUS_ARG_TYPE_ERROR = 0xAAAA0028,  /* dbus argument type error */
    TEEC_ERROR_TOKEN_NULL = 0xAAAA0029,  /* fetch token is null */
    TEEC_ERROR_TOKEN_SIZE_ERROR = 0xAAAA0030,  /* token size is error */
    TEEC_ERROR_FETCHJWT_ERROR = 0xAAAA0031,  /* fetch jwt error */
    TEEC_INFILE_PATH_NULL = 0xAAAA0032   /* deployta infile patn is null*/
};

typedef enum TEEC_ReturnCode TEEC_Result;
#endif //_DBUS_RETURN_CODE_H
