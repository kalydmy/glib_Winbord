/************************************************************************************************************
 * @internal
 * @remark     Winbond Electronics Corporation - Confidential
 * @copyright  Copyright (c) 2019 by Winbond Electronics Corporation . All rights reserved
 * @endinternal
 *
 * @file       qlib_sample_server_main.c
 * @brief      This file includes sample QLIB server implementation
 *
 * ### project qlib
 *
 ***********************************************************************************************************/

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include "qlib.h"
#include "qlib_server.h"
#include "qlib_sample_server_client_common.h"
#include "qlib_sample_qconf.h"
#include "qlib_sample_secure_storage.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                  TYPES                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
typedef enum
{
    SERVER_STATE_INIT,
    SERVER_STATE_REGISTRATION_COMPLETED,
    SERVER_STATE_TRYING_TO_CONNECT,
    SERVER_STATE_READY,
} SERVER_STATE_T;

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                 GLOBALS                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
static SERVER_STATE_T state;

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                 DEFINES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#define TEXT_COLOR_RED    "\033[31m"
#define TEXT_COLOR_GREEN  "\033[32m"
#define TEXT_COLOR_BLUE   "\033[34m"
#define TEXT_COLOR_YELLOW "\033[33m"
#define TEXT_COLOR_WHITE  "\033[37m"

#define COLOR_PRINTF(color, ...)                             \
    {                                                        \
        printf(color);                                       \
        printf(__VA_ARGS__);                                 \
        printf(TEXT_COLOR_WHITE);                            \
    }

#define STATUS_RET_CHECK_RETURN_1(func, message)   \
    {                                              \
        QLIB_STATUS_T ___ret;                      \
        if (QLIB_STATUS__OK != (___ret = func))    \
        {                                          \
            COLOR_PRINTF(TEXT_COLOR_RED, message); \
            return 1;                              \
        }                                          \
    }

#ifndef PRINT_BUF
#define PRINT_BUF(buf, size)                                           \
    {                                                                  \
        unsigned int ____i;                                            \
        for (____i = 0; ____i < size; ++____i)                         \
        {                                                              \
            COLOR_PRINTF(TEXT_COLOR_WHITE, "%02x", ((U8*)buf)[____i]); \
        }                                                              \
        COLOR_PRINTF(TEXT_COLOR_WHITE, "\n\r");                        \
    }
#endif // PRINT_BUF

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                             LOCAL FUNCTIONS                                             */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
 * @brief   Packet processing thread
 *
 * @param   data    Qlib client object
 *
 * @return NULL if no error occurred
************************************************************************************************************/
void* PacketProcessThread(void* data)
{
    QLIB_STATUS_T         ret;
    QLIB_SERVER_CLIENT_T* client = (QLIB_SERVER_CLIENT_T*)data;

    do
    {
        ret = QLIB_SERVER_HandlePacket(client);
    } while (QLIB_STATUS__OK == ret);
    COLOR_PRINTF(TEXT_COLOR_WHITE, "Connection to client lost.\r\n");

    return NULL;
}

/************************************************************************************************************
 * @brief   Custom packet callback
 *
 * @param[in]   client  pointer to client object
 * @param[in]   buf     Custom packet data buffer
 * @param[in]   size    Custom packet size
************************************************************************************************************/
QLIB_STATUS_T OnCustomPacket(struct _QLIB_SERVER_CLIENT_T* client, void* buf, U32 size)
{
    TOUCH(client);
    TOUCH(buf);
    TOUCH(size);

    COLOR_PRINTF(TEXT_COLOR_YELLOW, "Custom packet received (%lu bytes):", (unsigned long)size);
    PRINT_BUF(buf, size);

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief   Registration callback
************************************************************************************************************/
QLIB_STATUS_T OnRegistration(struct _QLIB_SERVER_CLIENT_T* client)
{
    // Client registered and we are synchronized. Now we can use QLIB API with client's qlibContext.
    // Now we shall wait for QLIB_PACKET_CLIENT2SERVER__DATA_IS_READY notification.
    state = SERVER_STATE_REGISTRATION_COMPLETED;

    COLOR_PRINTF(TEXT_COLOR_YELLOW,
                 "Client %08lx%08lx completed registration\n\r",
                 (unsigned long)client->qlibContext.wid[1],
                 (unsigned long)client->qlibContext.wid[0]);

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief   Custom packet callback
 *
 * @param[in]   port    Port number
 * @param[out]  sock    Pointer to the new socket handler
 *
 * @return  0 on successful termination
************************************************************************************************************/
int OpenListenerSocket(char* port, int* sock)
{
    int              iResult;
    int              listenSocket = -1;
    int              clientSocket = -1;
    struct addrinfo* result       = NULL;
    struct addrinfo  hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags    = AI_PASSIVE;

    // Resolve the server address and port
    iResult = getaddrinfo(NULL, port, &hints, &result);
    if (iResult != 0)
    {
        COLOR_PRINTF(TEXT_COLOR_RED, "getaddrinfo failed with error: %s\n", gai_strerror(iResult));
        return 1;
    }

    // Create a SOCKET for connecting to server
    COLOR_PRINTF(TEXT_COLOR_WHITE, "Waiting for client\r\n");
    listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == -1)
    {
        COLOR_PRINTF(TEXT_COLOR_RED, "socket failed with error: %s\n", strerror(errno));
        freeaddrinfo(result);
        return 1;
    }

    // Setup the TCP listening socket
    iResult = bind(listenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == -1)
    {
        COLOR_PRINTF(TEXT_COLOR_RED, "bind failed with error: %s\n", strerror(errno));
        freeaddrinfo(result);
        close(listenSocket);
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(listenSocket, SOMAXCONN);
    if (iResult == -1)
    {
        COLOR_PRINTF(TEXT_COLOR_RED, "listen failed with error: %s\n", strerror(errno));
        close(listenSocket);
        return 1;
    }

    // Accept a client socket
    clientSocket = accept(listenSocket, NULL, NULL);
    if (clientSocket == -1)
    {
        COLOR_PRINTF(TEXT_COLOR_RED, "accept failed with error: %s\n", strerror(errno));
        close(listenSocket);
        return 1;
    }

    *sock = clientSocket;
    return 0;
}

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                               ENTRY POINT                                               */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
 * @brief   MAIN ENTRY POINT
 *
 * @param   argc
 * @param   argv
 *
 * @return  0 on successful termination
************************************************************************************************************/
int main(int argc, char** argv)
{
    U32                            buf[1024 / sizeof(U32)] = {0};
    QLIB_SERVER_CLIENT_T           client;
    QLIB_SERVER_CLIENT_CALLBACKS_T callbacks = {buf, sizeof(buf), OnCustomPacket, OnRegistration, NULL};
    QLIB_STATUS_T                  ret;
    char*                          port = QLIB_REMOTE_SAMPLE_PORT;
    int                            sock;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Unused parameters                                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    TOUCH(argc);
    TOUCH(argv);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Setup globals                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    state = SERVER_STATE_INIT;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Open listener socket                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    if (OpenListenerSocket(port, &sock))
    {
        return 1;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Initialize client                                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    STATUS_RET_CHECK_RETURN_1(QLIB_SERVER_InitClient(&client, (void*)(intptr_t)sock, &callbacks), "Init client FAILED.\r\n");

    /*-----------------------------------------------------------------------------------------------------*/
    /* Initialize Qlib                                                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    STATUS_RET_CHECK_RETURN_1(QLIB_InitLib(&client.qlibContext), "Qlib init FAILED.\r\n");

    /*-----------------------------------------------------------------------------------------------------*/
    /* Create packet processing thread for this client                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, PacketProcessThread, &client);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Start working with this client                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    while (1)
    {
        switch (state)
        {
            case SERVER_STATE_INIT:
            {
                break;
            }

            case SERVER_STATE_REGISTRATION_COMPLETED:
            {
                state = SERVER_STATE_TRYING_TO_CONNECT;
                break;
            }

            case SERVER_STATE_TRYING_TO_CONNECT:
            {
                ret = QLIB_Connect(&client.qlibContext);
                if (ret == QLIB_STATUS__OK)
                {
                    COLOR_PRINTF(TEXT_COLOR_YELLOW, "Connection with client succeeded\n\r");
                    state = SERVER_STATE_READY;
                }
                else
                {
                    COLOR_PRINTF(TEXT_COLOR_RED, "Connection with client FAILED. Will retry\n\r");
                    (void)QLIB_Disconnect(&client.qlibContext);
                }

                break;
            }

            case SERVER_STATE_READY:
            {
                /*-----------------------------------------------------------------------------------------*/
                /* Run the samples                                                                         */
                /*-----------------------------------------------------------------------------------------*/
                STATUS_RET_CHECK_RETURN_1(QLIB_Disconnect(&client.qlibContext), "Qlib disconnect FAILED.\r\n");
                STATUS_RET_CHECK_RETURN_1(QLIB_SAMPLE_QconfRecovery(&client.qlibContext), "Qconf recovery FAILED.\r\n");
                STATUS_RET_CHECK_RETURN_1(QLIB_SAMPLE_QconfConfig(&client.qlibContext), "Qconf config sample FAILED.\r\n");
                STATUS_RET_CHECK_RETURN_1(QLIB_Connect(&client.qlibContext), "Re-connection with client FAILED.\r\n");
                STATUS_RET_CHECK_RETURN_1(QLIB_SAMPLE_SecureSectionWithPlainAccessRead(&client.qlibContext),
                                          "Secure section with plain access read sample FAILED.\r\n");
                STATUS_RET_CHECK_RETURN_1(QLIB_SAMPLE_SecureSectionFullKey(&client.qlibContext),
                                          "Secure section full key sample FAILED.\r\n");
                STATUS_RET_CHECK_RETURN_1(QLIB_SAMPLE_SecureSectionRestrictedKey(&client.qlibContext),
                                          "Secure section restricted key sample FAILED.\r\n");

                COLOR_PRINTF(TEXT_COLOR_YELLOW, "Sample server sample succeeded\r\n");
                return 0;
            }
        }
    }

    return 0;
}