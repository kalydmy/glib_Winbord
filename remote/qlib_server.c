/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib_server.c
* @brief      This code shows server application over W77Q sample definitions
*
************************************************************************************************************/
#define QLIB_SERVER_C

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include "qlib_server.h"
#include "qlib_server_platform.h"
#include "qlib_server_client_common.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                 DEFINES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#define QLIB_SERVER_CLIENT_TIMEOUT 50000 // in ms

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                  TYPES                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
typedef QLIB_STATUS_T (*QLIB_CLIENT_EVENT_T)(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in);

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                           LOCAL FUNCTION API                                            */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
static QLIB_STATUS_T QLIB_SERVER_OnInvalidPacket_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in);
static QLIB_STATUS_T QLIB_SERVER_OnRegistration_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in);
static QLIB_STATUS_T QLIB_SERVER_OnResponse_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in);
static QLIB_STATUS_T QLIB_SERVER_OnCustomCMD_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in);

static QLIB_STATUS_T QLIB_SERVER_ClientRegistration_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__REGISTER_T* regPacket);

static QLIB_STATUS_T QLIB_SERVER_SendReceive_L(QLIB_SERVER_CLIENT_T*         client,
                                               QLIB_PACKET_STRUCT__HEADER_T* hdrOut,
                                               void*                         dataOut,
                                               QLIB_PACKET_STRUCT__HEADER_T* hdrIn,
                                               void*                         dataIn,
                                               U32                           dataInSize);

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                CONSTANTS                                                */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
static const QLIB_CLIENT_EVENT_T QLIB_SERVER_Events[QLIB__NUM_OF_PACKET_TYPES] = {
    QLIB_SERVER_OnInvalidPacket_L, // QLIB_PACKET_TYPE__ILLEGAL         - We should never receive it on the server
    QLIB_SERVER_OnRegistration_L,  // QLIB_PACKET_TYPE__REGISTER
    QLIB_SERVER_OnInvalidPacket_L, // QLIB_PACKET_TYPE__REGISTER_RESP   - We should never receive it on the server
    QLIB_SERVER_OnInvalidPacket_L, // QLIB_PACKET_TYPE__CONNECT         - We should never receive it on the server
    QLIB_SERVER_OnInvalidPacket_L, // QLIB_PACKET_TYPE__DISCONNECT      - We should never receive it on the server
    QLIB_SERVER_OnInvalidPacket_L, // QLIB_PACKET_TYPE__STD_CMD         - We should never receive it on the server
    QLIB_SERVER_OnInvalidPacket_L, // QLIB_PACKET_TYPE__SEC_CMD         - We should never receive it on the server
    QLIB_SERVER_OnResponse_L,      // QLIB_PACKET_TYPE__CMD_RESP
    QLIB_SERVER_OnCustomCMD_L,     // QLIB_PACKET_TYPE__CUSTOM
};

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                 TM API                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
QLIB_STATUS_T QLIB_TM_Init(QLIB_CONTEXT_T* qlibContext)
{
    TOUCH(qlibContext);
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_TM_Connect(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /*Build structures for communication                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SERVER_CLIENT_T*        client      = (QLIB_SERVER_CLIENT_T*)QLIB_GetUserData(qlibContext);
    QLIB_PACKET_STRUCT__HEADER_T connect_hdr = {QLIB_PACKET_TYPE__CONNECT, 0};
    QLIB_PACKET_STRUCT__HEADER_T resp_hdr;
    QLIB_PACKET_STRUCT__RESP_T   resp;

    /*-----------------------------------------------------------------------------------------------------*/
    /*Send 'connect' command, and get 'response'                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(
        QLIB_SERVER_SendReceive_L(client, &connect_hdr, NULL, &resp_hdr, &resp, sizeof(QLIB_PACKET_STRUCT__RESP_T)));

    /*-----------------------------------------------------------------------------------------------------*/
    /*Check response                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(resp_hdr.type == QLIB_PACKET_TYPE__CMD_RESP, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(resp_hdr.size == sizeof(QLIB_PACKET_STRUCT__RESP_T), QLIB_STATUS__COMMUNICATION_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Return response status                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    return (QLIB_STATUS_T)resp.status;
}

QLIB_STATUS_T QLIB_TM_Disconnect(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /*Build structures for communication                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SERVER_CLIENT_T*        client      = (QLIB_SERVER_CLIENT_T*)QLIB_GetUserData(qlibContext);
    QLIB_PACKET_STRUCT__HEADER_T connect_hdr = {QLIB_PACKET_TYPE__DISCONNECT, 0};
    QLIB_PACKET_STRUCT__HEADER_T resp_hdr;
    QLIB_PACKET_STRUCT__RESP_T   resp;

    /*-----------------------------------------------------------------------------------------------------*/
    /*Send 'connect' command, and get 'response'                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(
        QLIB_SERVER_SendReceive_L(client, &connect_hdr, NULL, &resp_hdr, &resp, sizeof(QLIB_PACKET_STRUCT__RESP_T)));

    /*-----------------------------------------------------------------------------------------------------*/
    /*Check response                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(resp_hdr.type == QLIB_PACKET_TYPE__CMD_RESP, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(resp_hdr.size == sizeof(QLIB_PACKET_STRUCT__RESP_T), QLIB_STATUS__COMMUNICATION_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Return response status                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    return (QLIB_STATUS_T)resp.status;
}

QLIB_STATUS_T QLIB_TM_Standard(QLIB_CONTEXT_T*   qlibContext,
                               QLIB_BUS_FORMAT_T busFormat,
                               BOOL              needWriteEnable,
                               BOOL              waitWhileBusy,
                               U8                cmd,
                               const U32*        address,
                               const U8*         writeData,
                               U32               writeDataSize,
                               U32               dummyCycles,
                               U8*               readData,
                               U32               readDataSize,
                               QLIB_REG_SSR_T*   ssr)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Build structures for communication                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SERVER_CLIENT_T*               client       = (QLIB_SERVER_CLIENT_T*)QLIB_GetUserData(qlibContext);
    U16                                 std_cmd_size = (U16)(sizeof(QLIB_PACKET_STRUCT__STANDARD_CMD_T) + writeDataSize);
    U16                                 resp_size    = (U16)(sizeof(QLIB_PACKET_STRUCT__RESP_T) + readDataSize);
    QLIB_PACKET_STRUCT__HEADER_T        std_hdr      = {QLIB_PACKET_TYPE__STD_CMD, 0};
    QLIB_PACKET_STRUCT__STANDARD_CMD_T* std_cmd      = MALLOC(std_cmd_size);
    QLIB_PACKET_STRUCT__RESP_T*         resp         = MALLOC(resp_size);
    QLIB_PACKET_STRUCT__HEADER_T        resp_hdr;
    QLIB_STATUS_T                       ret = QLIB_STATUS__SECURITY_ERR;
    std_hdr.size                            = std_cmd_size;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_WITH_ERROR_GOTO((std_cmd != NULL) && (resp != NULL), QLIB_STATUS__OUT_OF_MEMORY, ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set command data                                                                                    */
    /*-----------------------------------------------------------------------------------------------------*/
    std_cmd->busFormat       = busFormat;
    std_cmd->needWriteEnable = needWriteEnable;
    std_cmd->waitWhileBusy   = waitWhileBusy;
    std_cmd->checkSsr        = (ssr != NULL) ? TRUE : FALSE;
    std_cmd->cmd             = cmd;
    std_cmd->address         = (address != NULL) ? *address : 0;
    std_cmd->addressExists   = (address != NULL) ? TRUE : FALSE;
    std_cmd->writeDataSize   = writeDataSize;
    std_cmd->dummyCycles     = dummyCycles;
    std_cmd->readDataSize    = readDataSize;
    memcpy(&std_cmd->writeData, writeData, writeDataSize);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Send 'std' command, and get 'response with data'                                                    */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_SERVER_SendReceive_L(client, &std_hdr, std_cmd, &resp_hdr, resp, resp_size), ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check response                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_WITH_ERROR_GOTO(resp_hdr.type == QLIB_PACKET_TYPE__CMD_RESP, QLIB_STATUS__COMMUNICATION_ERR, ret, exit);
    QLIB_ASSERT_WITH_ERROR_GOTO(resp_hdr.size == resp_size, QLIB_STATUS__COMMUNICATION_ERR, ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Extract response data                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    if (ssr != NULL)
    {
        ssr->asUint = resp->ssr;
    }

    if ((readDataSize != 0) && (readData != NULL))
    {
        memcpy(readData, (void*)resp->data, readDataSize);
    }

    ret = (QLIB_STATUS_T)resp->status;

exit:
    FREE(std_cmd);
    FREE(resp);
    return ret;
}

QLIB_STATUS_T QLIB_TM_Secure(QLIB_CONTEXT_T* qlibContext,
                             U32             ctag,
                             const U32*      writeData,
                             U32             writeDataSize,
                             U32*            readData,
                             U32             readDataSize,
                             QLIB_REG_SSR_T* ssr)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Build structures for communication                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SERVER_CLIENT_T*             client       = (QLIB_SERVER_CLIENT_T*)QLIB_GetUserData(qlibContext);
    U16                               sec_cmd_size = (U16)(sizeof(QLIB_PACKET_STRUCT__SECURE_CMD_T) + writeDataSize);
    U16                               resp_size    = (U16)(sizeof(QLIB_PACKET_STRUCT__RESP_T) + readDataSize);
    QLIB_PACKET_STRUCT__HEADER_T      sec_hdr      = {QLIB_PACKET_TYPE__SEC_CMD, 0};
    QLIB_PACKET_STRUCT__SECURE_CMD_T* sec_cmd      = MALLOC(sec_cmd_size);
    QLIB_PACKET_STRUCT__RESP_T*       resp         = MALLOC(resp_size);
    QLIB_PACKET_STRUCT__HEADER_T      resp_hdr;
    QLIB_STATUS_T                     ret = QLIB_STATUS__SECURITY_ERR;
    sec_hdr.size                          = sec_cmd_size;

    /*-----------------------------------------------------------------------------------------------------*/
    /*Error checking                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_WITH_ERROR_GOTO((sec_cmd != NULL) && (resp != NULL), QLIB_STATUS__OUT_OF_MEMORY, ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Set command data                                                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    sec_cmd->checkSsr      = (ssr != NULL) ? TRUE : FALSE;
    sec_cmd->ctag          = ctag;
    sec_cmd->writeDataSize = writeDataSize;
    sec_cmd->readDataSize  = readDataSize;
    memcpy((void*)&sec_cmd->writeData, (const void*)writeData, writeDataSize);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Send 'sec' command, and get 'response with data'                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_SERVER_SendReceive_L(client, &sec_hdr, sec_cmd, &resp_hdr, resp, resp_size), ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Check response                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_WITH_ERROR_GOTO(resp_hdr.type == QLIB_PACKET_TYPE__CMD_RESP, QLIB_STATUS__COMMUNICATION_ERR, ret, exit);
    QLIB_ASSERT_WITH_ERROR_GOTO(resp_hdr.size == resp_size, QLIB_STATUS__COMMUNICATION_ERR, ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Extract response data                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    if (ssr != NULL)
    {
        ssr->asUint = resp->ssr;
    }

    if ((readDataSize != 0) && (readData != NULL))
    {
        memcpy(readData, (void*)resp->data, readDataSize);
    }

    ret = (QLIB_STATUS_T)resp->status;

exit:
    FREE(sec_cmd);
    FREE(resp);
    return ret;
}

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                               Server API                                                */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

QLIB_STATUS_T QLIB_SERVER_InitClient(QLIB_SERVER_CLIENT_T* client, void* socket, QLIB_SERVER_CLIENT_CALLBACKS_T* callbacks)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /*Error checking                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(client != NULL, QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Set variables                                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    client->socket           = socket;
    client->callbacks        = callbacks;
    client->responseReady    = TRUE;
    client->responseBuf      = NULL;
    client->responseSize     = 0;
    client->qlibContextReady = FALSE;
    memset(&client->qlibContext, 0, sizeof(QLIB_CONTEXT_T));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SERVER_HandlePacket(QLIB_SERVER_CLIENT_T* client)
{
    QLIB_PACKET_STRUCT__HEADER_T hdr;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Wait for packet                                                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Receive(client->socket, &hdr, sizeof(QLIB_PACKET_STRUCT__HEADER_T), FALSE));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Process packet by type                                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(hdr.type < QLIB__NUM_OF_PACKET_TYPES, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Events[hdr.type](client, &hdr));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SERVER_SendCustomPacket(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__CUSTOM_T* packet, U16 packetSize)
{
    QLIB_PACKET_STRUCT__HEADER_T hdr = {QLIB_PACKET_TYPE__CUSTOM, 0};
    hdr.size                         = packetSize;

    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Send(client->socket, &hdr, sizeof(QLIB_PACKET_STRUCT__HEADER_T)));
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Send(client->socket, packet, packetSize));

    return QLIB_STATUS__OK;
}

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                             LOCAL FUNCTIONS                                             */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

static QLIB_STATUS_T QLIB_SERVER_ClientRegistration_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__REGISTER_T* regPacket)
{
    QLIB_STATUS_T ret = QLIB_STATUS__SECURITY_ERR;
    U32           i;
    QLIB_WID_T    wid;

    /*-----------------------------------------------------------------------------------------------------*/
    /*Set comm object into QLIB context                                                                    */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SetUserData(&client->qlibContext, client);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Error checking                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(client != NULL, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(regPacket != NULL, QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Get keys                                                                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    memcpy((void*)wid, (const void*)regPacket->syncObject.wid, sizeof(QLIB_WID_T));
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_SERVER_GetKeys(wid, client->fk, client->rk), ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Initialize local QLIB                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_InitLib(&client->qlibContext), ret, exit);
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_ImportState(&client->qlibContext, &regPacket->syncObject), ret, exit);

    /*-----------------------------------------------------------------------------------------------------*/
    /*Load keys                                                                                            */
    /*-----------------------------------------------------------------------------------------------------*/
    for (i = 0; i < QLIB_NUM_OF_SECTIONS; ++i)
    {
        if ((client->fk[i] != NULL) && (QLIB_KEY_MNGR__IS_KEY_VALID(client->fk[i])))
        {
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_LoadKey(&client->qlibContext, i, client->fk[i], TRUE), ret, exit);
        }
        if ((client->rk[i] != NULL) && (QLIB_KEY_MNGR__IS_KEY_VALID(client->rk[i])))
        {
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_LoadKey(&client->qlibContext, i, client->rk[i], FALSE), ret, exit);
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Mark qlibContext is ready                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    client->qlibContextReady = TRUE;

    /*-----------------------------------------------------------------------------------------------------*/
    /*Set return OK                                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    ret = QLIB_STATUS__OK;

exit:
    return ret;
}

static QLIB_STATUS_T QLIB_SERVER_SendReceive_L(QLIB_SERVER_CLIENT_T*         client,
                                               QLIB_PACKET_STRUCT__HEADER_T* hdrOut,
                                               void*                         dataOut,
                                               QLIB_PACKET_STRUCT__HEADER_T* hdrIn,
                                               void*                         dataIn,
                                               U32                           dataInSize)
{
    U64   timeout = 0;
    void* timer   = NULL;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Register buffer for response read                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    if ((dataIn != NULL) && (dataInSize != 0))
    {
        client->responseBuf   = dataIn;
        client->responseSize  = dataInSize;
        client->responseReady = FALSE;
        client->hdr_in        = hdrIn;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Send header                                                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Send(client->socket, hdrOut, sizeof(QLIB_PACKET_STRUCT__HEADER_T)));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Send data                                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    if ((hdrOut->size != 0) && (dataOut != NULL))
    {
        QLIB_STATUS_RET_CHECK(QLIB_SERVER_Send(client->socket, dataOut, hdrOut->size));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Wait for response with timeout                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_TimerStart(&timer));
    while ((client->responseReady == FALSE) && (timeout < QLIB_SERVER_CLIENT_TIMEOUT))
    {
        QLIB_STATUS_RET_CHECK(QLIB_SERVER_TimerGetMS(timer, &timeout));
    }
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_TimerStop(timer));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if timeout occurred                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    if (timeout >= QLIB_SERVER_CLIENT_TIMEOUT)
    {
        return QLIB_STATUS__COMMAND_FAIL;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Data output is ready                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    return QLIB_STATUS__OK;
}

static QLIB_STATUS_T QLIB_SERVER_OnInvalidPacket_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Unused parameters                                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    TOUCH(hdr_in);

    if (client->callbacks)
    {
        if (client->callbacks->onInvalidPacket)
        {
            QLIB_STATUS_RET_CHECK(client->callbacks->onInvalidPacket(client));
        }
    }

    return QLIB_STATUS__COMMUNICATION_ERR;
}

static QLIB_STATUS_T QLIB_SERVER_OnRegistration_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in)
{
    QLIB_PACKET_STRUCT__REGISTER_T regPacket;
    QLIB_PACKET_STRUCT__HEADER_T   hdrResp = {QLIB_PACKET_TYPE__REGISTER_RESP, 0};
    QLIB_ASSERT_RET(hdr_in->size == sizeof(QLIB_PACKET_STRUCT__REGISTER_T), QLIB_STATUS__COMMUNICATION_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Get registration packet                                                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Receive(client->socket, &regPacket, hdr_in->size, TRUE));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform registration                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_ClientRegistration_L(client, &regPacket));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Call callback                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    if (client->callbacks)
    {
        if (client->callbacks->onRegistration)
        {
            QLIB_STATUS_RET_CHECK(client->callbacks->onRegistration(client));
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Send registration response                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Send(client->socket, &hdrResp, sizeof(QLIB_PACKET_STRUCT__HEADER_T)));

    return QLIB_STATUS__OK;
}

static QLIB_STATUS_T QLIB_SERVER_OnResponse_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in)
{
    QLIB_ASSERT_RET(client->responseReady == FALSE, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(client->responseBuf != NULL, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(client->responseSize == hdr_in->size, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(client->hdr_in != NULL, QLIB_STATUS__COMMUNICATION_ERR);

    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Receive(client->socket, client->responseBuf, hdr_in->size, TRUE));

    memcpy(client->hdr_in, hdr_in, sizeof(QLIB_PACKET_STRUCT__HEADER_T));
    client->responseReady = TRUE;

    return QLIB_STATUS__OK;
}

static QLIB_STATUS_T QLIB_SERVER_OnCustomCMD_L(QLIB_SERVER_CLIENT_T* client, QLIB_PACKET_STRUCT__HEADER_T* hdr_in)
{
    QLIB_ASSERT_RET(client->callbacks != NULL, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(client->callbacks->onCustomPacket != NULL, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(client->callbacks->customBuf != NULL, QLIB_STATUS__COMMUNICATION_ERR);
    QLIB_ASSERT_RET(hdr_in->size < client->callbacks->customSize, QLIB_STATUS__COMMUNICATION_ERR);

    QLIB_STATUS_RET_CHECK(QLIB_SERVER_Receive(client->socket, client->callbacks->customBuf, hdr_in->size, TRUE));
    QLIB_STATUS_RET_CHECK(client->callbacks->onCustomPacket(client, client->callbacks->customBuf, hdr_in->size));

    return QLIB_STATUS__OK;
}

#undef QLIB_SERVER_C
