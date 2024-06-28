/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2021 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib_server_platform.h
* @brief      This file includes platform specific definitions for QLIB Server.
*             These definitions must be implemented for specific platform
*
************************************************************************************************************/
#ifndef __QLIB_SERVER_PLATFORM_H__
#define __QLIB_SERVER_PLATFORM_H__

#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                              INCLUDES                                                   */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include "qlib.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                API                                                      */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
 * @brief   This function sends data to client
 *
 * @param[in,out]   socket          Communication data
 * @param[in]       dataOut         Data to send
 * @param[in]       dataOutSize     Send data size
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_Send(void* socket, void* dataOut, U32 dataOutSize);

/************************************************************************************************************
 * @brief   This function receives data from client
 *
 * @param[in,out]   socket          Communication data
 * @param[out]      dataIn          Buffer to hold input data
 * @param[in]       dataInSize      Input data size
 * @param[in]       blocking        if TRUE, the function will be block execution till all data received
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_Receive(void* socket, void* dataIn, U32 dataInSize, BOOL blocking);

/************************************************************************************************************
 * @brief  This function returns full-access and restricted keys for a given device
 *
 * @param[in]   id  W77Q id
 * @param[out]  fk  Full access keys
 * @param[out]  rk  Restricted keys
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_GetKeys(const QLIB_WID_T id, KEY_ARRAY_T fk, KEY_ARRAY_T rk);

/************************************************************************************************************
 * @brief   This function starts a millisecond precision timer
 *
 * @param[out]   timer  Timer handler
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_TimerStart(void** timer);

/************************************************************************************************************
 * @brief   This function returns time in milliseconds of a given timer
 *
 * @param[in]   timer   Timer handler that was started by @ref QLIB_SERVER_TimerStart
 * @param[out]  ms      Time in milliseconds since @ref QLIB_SERVER_TimerStart
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_TimerGetMS(void* timer, U64* ms);

/************************************************************************************************************
 * @brief   This function stops the timer started by @ref QLIB_SERVER_TimerStart
 *
 * @param[in]   timer  Timer handler
 *
 * @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SERVER_TimerStop(void* timer);

#ifdef __cplusplus
}
#endif

#endif //__QLIB_SERVER_PLATFORM_H__
