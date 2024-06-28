/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib_server_client_common.h
* @brief      Contains network related definitions needed for code of server/client
*             application over w77q
*
************************************************************************************************************/
#ifndef __QLIB_SERVER_CLIENT_COMMON_H__
#define __QLIB_SERVER_CLIENT_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include "qlib.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                  TYPES                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------------------------*/
/* Packet types                                                                                            */
/*---------------------------------------------------------------------------------------------------------*/
typedef enum
{
    QLIB_PACKET_TYPE__ILLEGAL       = 0,
    QLIB_PACKET_TYPE__REGISTER      = 1,
    QLIB_PACKET_TYPE__REGISTER_RESP = 2,
    QLIB_PACKET_TYPE__CONNECT       = 3,
    QLIB_PACKET_TYPE__DISCONNECT    = 4,
    QLIB_PACKET_TYPE__STD_CMD       = 5,
    QLIB_PACKET_TYPE__SEC_CMD       = 6,
    QLIB_PACKET_TYPE__CMD_RESP      = 7,
    QLIB_PACKET_TYPE__CUSTOM        = 8,

    QLIB__NUM_OF_PACKET_TYPES
} QLIB_PACKET_TYPE_T;

/*---------------------------------------------------------------------------------------------------------*/
/*                                 Start definitions of packed structures                                  */
/*---------------------------------------------------------------------------------------------------------*/
PACKED_START

/*---------------------------------------------------------------------------------------------------------*/
/*Header packet                                                                                            */
/*---------------------------------------------------------------------------------------------------------*/
typedef struct
{
    U16 type;
    U16 size;
} PACKED QLIB_PACKET_STRUCT__HEADER_T;

/*---------------------------------------------------------------------------------------------------------*/
/* Client registration packet                                                                              */
/*---------------------------------------------------------------------------------------------------------*/
typedef struct
{
    QLIB_SYNC_OBJ_T syncObject;
} PACKED QLIB_PACKET_STRUCT__REGISTER_T;

#ifdef _WIN32
#pragma warning(disable : 4200)
#endif // _WIN32
typedef struct
{
    QLIB_BUS_FORMAT_T busFormat;
    BOOL              needWriteEnable;
    BOOL              waitWhileBusy;
    BOOL              checkSsr;
    U8                cmd;
    U32               address;
    BOOL              addressExists;
    U32               writeDataSize;
    U32               dummyCycles;
    U32               readDataSize;
    U32               writeData[];
} PACKED QLIB_PACKET_STRUCT__STANDARD_CMD_T;

typedef struct
{
    BOOL checkSsr;
    U32  ctag;
    U32  writeDataSize;
    U32  readDataSize;
    U32  writeData[];
} PACKED QLIB_PACKET_STRUCT__SECURE_CMD_T;

typedef struct
{
    U32 status;
    U32 ssr;
    U32 data[];
} PACKED QLIB_PACKET_STRUCT__RESP_T;

typedef struct
{
    U32 shortData;
    U32 longData[];
} PACKED QLIB_PACKET_STRUCT__CUSTOM_T;

/*---------------------------------------------------------------------------------------------------------*/
/*                                  End definitions of packed structures                                   */
/*---------------------------------------------------------------------------------------------------------*/
PACKED_END

#ifdef __cplusplus
}
#endif

#endif //__QLIB_SERVER_CLIENT_COMMON_H__
