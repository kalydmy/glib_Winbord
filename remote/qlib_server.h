/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib_server.h
* @brief      This code shows server application over W77Q sample definitions
*
************************************************************************************************************/
#ifndef _QLIB_SERVER__H_
#define _QLIB_SERVER__H_

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include "qlib.h"
#include "qlib_server_client_common.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                  TYPES                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

struct _QLIB_SERVER_CLIENT_T;

// Custom packets callback
typedef QLIB_STATUS_T (*QLIB_SERVER_CUSTOM_PACKET_CB)(struct _QLIB_SERVER_CLIENT_T* client, void* buf, U32 size);

// Default callback
typedef QLIB_STATUS_T (*QLIB_SERVER_DEFAULT_CB)(struct _QLIB_SERVER_CLIENT_T* client);

// Callbacks object for the client
typedef struct
{
    void*                        customBuf;
    U32                          customSize;
    QLIB_SERVER_CUSTOM_PACKET_CB onCustomPacket;
    QLIB_SERVER_DEFAULT_CB       onRegistration;
    QLIB_SERVER_DEFAULT_CB       onInvalidPacket;
} QLIB_SERVER_CLIENT_CALLBACKS_T;

// Client object
typedef struct _QLIB_SERVER_CLIENT_T
{
    QLIB_CONTEXT_T                  qlibContext;
    BOOL                            qlibContextReady;
    KEY_ARRAY_T                     fk;
    KEY_ARRAY_T                     rk;
    void*                           socket;
    void*                           responseBuf;
    U32                             responseSize;
    BOOL                            responseReady;
    QLIB_SERVER_CLIENT_CALLBACKS_T* callbacks;
    QLIB_PACKET_STRUCT__HEADER_T*   hdr_in;
} QLIB_SERVER_CLIENT_T;

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                   API                                                   */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
 * @brief This function initializes a new Client object
 *
 * @param[out]  client      Pointer to a new Client object
 * @param[in]   socket      Socket handler for the new client
 * @param[in]   callbacks   Optional callbacks object
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_InitClient(QLIB_SERVER_CLIENT_T* client, void* socket, QLIB_SERVER_CLIENT_CALLBACKS_T* callbacks);

/************************************************************************************************************
 * @brief   This function processes a single packet for a given Client.
 *          This function should be executed in a dedicated thread, in while(1) loop
 *          or as a callback for new data event on the socket
 *
 * @param[in]   client  Client object
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_HandlePacket(QLIB_SERVER_CLIENT_T* client);

/************************************************************************************************************
 * @brief   This function allows the Server to send custom packet to the Client
 *
 * @param[in]   client      Client object
 * @param[in]   packet      Packet struct
 * @param[in]   packetSize  Size of the packet struct (Note that custom packet can have variable data size)
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_SendCustomPacket(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__CUSTOM_T* packet, U16 packetSize);

#ifdef __cplusplus
}
#endif

#endif // _QLIB_SERVER__H_
