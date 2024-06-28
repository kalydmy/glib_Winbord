/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2019 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib.c
* @brief      This file contains QLIB main interface
*
* ### project qlib
*
************************************************************************************************************/
#define __QLIB_C__
// Prevent unused macro warning

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#define NO_Q2_API_H
#include "qlib.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                 MACROS                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#define QLIB_DEVICE_INITIALIZED(qlibContext) ((qlibContext)->busInterface.busMode != QLIB_BUS_MODE_INVALID)

#ifdef Q2_API
#ifdef QLIB_INIT_AFTER_FLASH_POWER_UP
#define QLIB_INIT_AFTER_Q2_POWER_UP
#endif
#endif

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                  TYPES                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
typedef enum
{
    QLIB_LOAD_ACLR_ANY      = 0,          // load SSPR to ACLR
    QLIB_LOAD_ACLR_PLAIN_RD = (1u << 0u), // load SSPR to ACLR only if plain read is configured for section
    QLIB_LOAD_ACLR_PLAIN_WR = (1u << 1u), // load SSPR to ACLR only if plain write is configured for section
    QLIB_LOAD_ACLR_NON_AUTH = (1u << 2u), // load SSPR to ACLR only if non-authenticated plain access is configured for section
    QLIB_LOAD_ACLR_NON_AUTH_PLAIN_RD =
        ((U8)QLIB_LOAD_ACLR_NON_AUTH |
         (U8)QLIB_LOAD_ACLR_PLAIN_RD), // load SSPR to ACLR only if non-authenticated plain read is configured for section
    QLIB_LOAD_ACLR_NON_AUTH_PLAIN_WR =
        ((U8)QLIB_LOAD_ACLR_NON_AUTH |
         (U8)QLIB_LOAD_ACLR_PLAIN_WR), // load SSPR to ACLR only if non-authenticated plain write is configured for section
} QLIB_LOAD_ACLR_T;
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                        LOCAL FUNCTION PROTOTYPES                                        */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

static QLIB_STATUS_T QLIB_waitReadyAndInitBusMode_L(QLIB_CONTEXT_T* qlibContext);
static QLIB_STATUS_T QLIB_PlainAccessGrant_L(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_LOAD_ACLR_T condition);
static QLIB_STATUS_T QLIB_GetTargetFlash_L(QLIB_HW_VER_T* hwVer, U32* target);

#ifdef Q2_API
#ifdef __cplusplus
extern "C" {
#endif
QLIB_STATUS_T QLIB2_Watchdog_Get(QLIB_CONTEXT_T* qlibContext, U32* secondsPassed, U32* ticksResidue, BOOL* expired);
#ifdef __cplusplus
}
#endif
#endif
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                           INTERFACE FUNCTIONS                                           */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

QLIB_STATUS_T QLIB_InitLib(QLIB_CONTEXT_T* qlibContext)
{
    void* userData;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* We must keep user data untouched since could be set before calling QLIB_InitLib                     */
    /*-----------------------------------------------------------------------------------------------------*/
    userData = QLIB_GetUserData(qlibContext);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Clear globals                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    (void)memset(qlibContext, 0, sizeof(QLIB_CONTEXT_T));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Initiate the standard module                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_STD_InitLib(qlibContext));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Initiate the secure module                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_InitLib(qlibContext));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Initiate the transport manager module with configured user data                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SetUserData(qlibContext, userData);
    QLIB_STATUS_RET_CHECK(QLIB_TM_Init(qlibContext));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T
    QLIB_SetInterface(QLIB_CONTEXT_T* qlibContext, QLIB_BUS_FORMAT_T busFormat)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(QLIB_BUS_FORMAT_GET_MODE(busFormat) > QLIB_BUS_MODE_INVALID, QLIB_STATUS__INVALID_PARAMETER);
#ifdef Q2_API
    QLIB_ASSERT_RET(QLIB_BUS_FORMAT_GET_MODE(busFormat) <= QLIB_BUS_MODE_4_4_4, QLIB_STATUS__INVALID_PARAMETER);
#else
    QLIB_ASSERT_RET(QLIB_BUS_FORMAT_GET_MODE(busFormat) <= QLIB_BUS_MODE_MAX, QLIB_STATUS__INVALID_PARAMETER);
#endif
    QLIB_ASSERT_RET((W77Q_SUPPORT_DUAL_SPI(qlibContext) != 0u) || (QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_1_1_2 &&
                                                                   QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_1_2_2),
                    QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_SUPPORT_OCTAL_SPI(qlibContext) != 0u) || (QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_1_8_8 &&
                                                                    QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_8_8_8),
                    QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_SUPPORT__1_1_4_SPI(qlibContext) != 0u) || (QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_1_1_4),
                    QLIB_STATUS__INVALID_PARAMETER);
#ifndef QLIB_SUPPORT_QPI
    QLIB_ASSERT_RET(QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_4_4_4, QLIB_STATUS__NOT_SUPPORTED);
#endif
#ifndef QLIB_SUPPORT_OPI
    QLIB_ASSERT_RET(QLIB_BUS_FORMAT_GET_MODE(busFormat) != QLIB_BUS_MODE_8_8_8, QLIB_STATUS__NOT_SUPPORTED);
#endif

    /*-----------------------------------------------------------------------------------------------------*/
    /* Change the bus interface                                                                            */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_STD_SetInterface(qlibContext, busFormat));
    QLIB_STATUS_RET_CHECK(QLIB_SEC_SetInterface(qlibContext, busFormat));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_InitDevice(QLIB_CONTEXT_T* qlibContext, QLIB_BUS_FORMAT_T busFormat)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);

    /********************************************************************************************************
     * Make sure to be synchronized with the flash device, exit power down mode, detect SPI mode
     * and command extension mode, make sure flash is ready and there is no connectivity issues
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_waitReadyAndInitBusMode_L(qlibContext));

    // set configuration table according to detected device
    QLIB_STATUS_RET_CHECK(QLIB_Cfg_Init(qlibContext));

#if !defined QLIB_INIT_AFTER_FLASH_POWER_UP && QLIB_NUM_OF_DIES > 1
    {
        QLIB_REG_ESSR_T essr;
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_ESSR_UNSIGNED(qlibContext, &essr));
        qlibContext->activeDie = READ_VAR_FIELD(essr.asUint, QLIB_REG_ESSR__DIE_ID);
    }
#endif

#ifndef QLIB_INIT_AFTER_FLASH_POWER_UP
    // reset flash to be sure all volatile registers are loaded
    QLIB_STATUS_RET_CHECK(QLIB_STD_ResetFlash(qlibContext, FALSE));
#endif
    /*-----------------------------------------------------------------------------------------------------*/
    /* synchronize the lib state with the flash state                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncState(qlibContext));

    // Set new bus format
    QLIB_STATUS_RET_CHECK(QLIB_SetInterface(qlibContext, busFormat));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_Read(QLIB_CONTEXT_T* qlibContext, U8* buf, U32 sectionID, U32 offset, U32 size, BOOL secure, BOOL auth)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(0u < size, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET((offset + size) >= size, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    if (TRUE == secure)
    {
        QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, sectionID), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        return QLIB_SEC_Read(qlibContext, buf, sectionID, offset, size, auth);
    }
    else
    {
        U32 section = QLIB_FALLBACK_SECTION(qlibContext, sectionID);
        QLIB_ASSERT_RET(sectionID < QLIB_SECTION_ID_VAULT, QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((offset + size) <= _QLIB_MAX_LEGACY_OFFSET(qlibContext), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, section), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
#if QLIB_NUM_OF_DIES > 1
        QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID || qlibContext->addrMode == QLIB_STD_ADDR_MODE__4_BYTE,
                        QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
#endif
        if ((QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[section].plainEnabled & QLIB_SECTION_PLAIN_EN_RD) == 0u)
        {
            QLIB_STATUS_RET_CHECK(QLIB_PlainAccessGrant_L(qlibContext,
                                                          section,
                                                          W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u
                                                              ? QLIB_LOAD_ACLR_PLAIN_RD
                                                              : QLIB_LOAD_ACLR_NON_AUTH_PLAIN_RD));
        }
        return QLIB_STD_Read(qlibContext, buf, QLIB_MAKE_LOGICAL_ADDRESS(qlibContext, sectionID, offset), size);
    }
}

QLIB_STATUS_T QLIB_Write(QLIB_CONTEXT_T* qlibContext, const U8* buf, U32 sectionID, U32 offset, U32 size, BOOL secure)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(0u < size, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET((offset + size) >= size, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    if (TRUE == secure)
    {
        QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, sectionID), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        return QLIB_SEC_Write(qlibContext, buf, sectionID, offset, size);
    }
    else
    {
        U32 section = QLIB_FALLBACK_SECTION(qlibContext, sectionID);
        QLIB_ASSERT_RET(sectionID < QLIB_SECTION_ID_VAULT, QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((offset + size) <= _QLIB_MAX_LEGACY_OFFSET(qlibContext), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, section), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
#if QLIB_NUM_OF_DIES > 1
        QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID || qlibContext->addrMode == QLIB_STD_ADDR_MODE__4_BYTE,
                        QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
#endif
        if ((QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[section].plainEnabled & QLIB_SECTION_PLAIN_EN_WR) == 0u)
        {
            QLIB_STATUS_RET_CHECK(QLIB_PlainAccessGrant_L(qlibContext,
                                                          section,
                                                          W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u
                                                              ? QLIB_LOAD_ACLR_PLAIN_WR
                                                              : QLIB_LOAD_ACLR_NON_AUTH_PLAIN_WR));
        }
        return QLIB_STD_Write(qlibContext, buf, QLIB_MAKE_LOGICAL_ADDRESS(qlibContext, sectionID, offset), size);
    }
}

QLIB_STATUS_T QLIB_Erase(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U32 offset, U32 size, BOOL secure)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(0u < size, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET((offset + size) >= size, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    if (TRUE == secure)
    {
        QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, sectionID), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        return QLIB_SEC_Erase(qlibContext, sectionID, offset, size);
    }
    else
    {
        U32 section = QLIB_FALLBACK_SECTION(qlibContext, sectionID);
        QLIB_ASSERT_RET(sectionID < QLIB_SECTION_ID_VAULT, QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((offset + size) <= _QLIB_MAX_LEGACY_OFFSET(qlibContext), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, section), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
#if QLIB_NUM_OF_DIES > 1
        QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID || qlibContext->addrMode == QLIB_STD_ADDR_MODE__4_BYTE,
                        QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
#endif

        if ((QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[section].plainEnabled & QLIB_SECTION_PLAIN_EN_WR) == 0u)
        {
            QLIB_STATUS_RET_CHECK(QLIB_PlainAccessGrant_L(qlibContext,
                                                          section,
                                                          W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u
                                                              ? QLIB_LOAD_ACLR_PLAIN_WR
                                                              : QLIB_LOAD_ACLR_NON_AUTH_PLAIN_WR));
        }
        return QLIB_STD_Erase(qlibContext, QLIB_MAKE_LOGICAL_ADDRESS(qlibContext, sectionID, offset), size);
    }
}

QLIB_STATUS_T QLIB_EraseSection(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL secure)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(!((QLIB_SECTION_ID_VAULT == sectionID) && (QLIB_VAULT_GET_SIZE(qlibContext) == 0u)),
                    QLIB_STATUS__DEVICE_PRIVILEGE_ERR);

    if (FALSE == secure)
    {
        QLIB_ASSERT_RET(sectionID < QLIB_SECTION_ID_VAULT, QLIB_STATUS__INVALID_PARAMETER);
        if ((QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled & QLIB_SECTION_PLAIN_EN_WR) == 0u)
        {
            QLIB_STATUS_RET_CHECK(QLIB_PlainAccessGrant_L(qlibContext,
                                                          sectionID,
                                                          W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u
                                                              ? QLIB_LOAD_ACLR_PLAIN_WR
                                                              : QLIB_LOAD_ACLR_NON_AUTH_PLAIN_WR));
        }
    }
    else
    {
        QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
    }

    return QLIB_SEC_EraseSection(qlibContext, sectionID, secure);
}

QLIB_STATUS_T QLIB_Suspend(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    QLIB_STATUS_RET_CHECK(QLIB_STD_EraseSuspend(qlibContext));

    qlibContext->isSuspended = 1u;
#if QLIB_NUM_OF_DIES > 1
    qlibContext->suspendDie = qlibContext->activeDie;
#endif
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_Resume(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 1u, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
#if QLIB_NUM_OF_DIES > 1
    QLIB_STATUS_RET_CHECK(QLIB_STD_SetActiveDie(qlibContext, qlibContext->suspendDie, FALSE));
#endif
    QLIB_STATUS_RET_CHECK(QLIB_STD_EraseResume(qlibContext, FALSE));

    qlibContext->isSuspended                    = 0u;
    QLIB_ACTIVE_DIE_STATE(qlibContext).mcInSync = 0u;

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_Power(QLIB_CONTEXT_T* qlibContext, QLIB_POWER_T power)
{
    U32 die;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_STATUS_RET_CHECK(QLIB_STD_Power(qlibContext, power));

    /*-----------------------------------------------------------------------------------------------------*/
    /* During power down SW could try to communicate and increment counters                                */
    /*-----------------------------------------------------------------------------------------------------*/
    if (QLIB_POWER_UP == power)
    {
        for (die = 0; die < QLIB_NUM_OF_DIES; die++)
        {
            qlibContext->dieState[die].mcInSync = 0u;
        }
    };

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_ResetFlash(QLIB_CONTEXT_T* qlibContext)
{
    U32 dmc;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

#if QLIB_NUM_OF_DIES > 1
    QLIB_STATUS_RET_CHECK(QLIB_STD_SetActiveDie(qlibContext, QLIB_INIT_DIE_ID, FALSE));
#endif
    /*-----------------------------------------------------------------------------------------------------*/
    /* Save previous value of DMC. DMC is incremented on flash reset                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__synch_MC(qlibContext));
    dmc = qlibContext->dieState[QLIB_INIT_DIE_ID].mc[DMC];

    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform reset                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_STD_ResetFlash(qlibContext, TRUE));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Sync qlib state after reset                                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncAfterFlashReset(qlibContext));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Verify reset occurred by testing DMC new value                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__synch_MC(qlibContext));
    QLIB_ASSERT_RET(dmc < qlibContext->dieState[QLIB_INIT_DIE_ID].mc[DMC], QLIB_STATUS__COMMAND_IGNORED);

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_Format(QLIB_CONTEXT_T* qlibContext, const KEY_T deviceMasterKey, BOOL eraseDataOnly, BOOL factoryDefault)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(FALSE == eraseDataOnly || QLIB_KEY_MNGR__IS_KEY_VALID(deviceMasterKey), QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_Format(qlibContext, deviceMasterKey, eraseDataOnly, factoryDefault);
}

QLIB_STATUS_T QLIB_GetNotifications(QLIB_CONTEXT_T* qlibContext, QLIB_NOTIFICATIONS_T* notifs)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != notifs, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_GetNotifications(qlibContext, notifs);
}

QLIB_STATUS_T QLIB_PerformMaintenance(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_PerformMCMaint(qlibContext);
}

QLIB_STATUS_T QLIB_ConfigDevice(QLIB_CONTEXT_T*                   qlibContext,
                                const KEY_T                       deviceMasterKey,
                                const KEY_T                       deviceSecretKey,
                                const QLIB_SECTION_CONFIG_TABLE_T sectionTable[QLIB_NUM_OF_DIES],
                                const KEY_ARRAY_T                 restrictedKeys[QLIB_NUM_OF_DIES],
                                const KEY_ARRAY_T                 fullAccessKeys[QLIB_NUM_OF_DIES],
                                const QLIB_LMS_KEY_ARRAY_T        lmsKeys[QLIB_NUM_OF_DIES],
                                const KEY_T                       preProvisionedMasterKey,
                                const QLIB_WATCHDOG_CONF_T*       watchdogDefault,
                                const QLIB_DEVICE_CONF_T*         deviceConf,
                                const _128BIT                     suid)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    if (NULL != sectionTable)
    {
        uint_fast8_t die;
        for (die = 0; die < QLIB_NUM_OF_DIES; die++)
        {
            if (W77Q_VAULT(qlibContext) != 0u)
            {
                QLIB_ASSERT_RET(0u == sectionTable[die][QLIB_SECTION_ID_VAULT].policy.plainAccessReadEnable,
                                QLIB_STATUS__INVALID_PARAMETER);
                QLIB_ASSERT_RET(0u == sectionTable[die][QLIB_SECTION_ID_VAULT].policy.plainAccessWriteEnable,
                                QLIB_STATUS__INVALID_PARAMETER);
                QLIB_ASSERT_RET(0u == sectionTable[die][QLIB_SECTION_ID_VAULT].policy.authPlainAccess,
                                QLIB_STATUS__INVALID_PARAMETER);
                QLIB_ASSERT_RET(QLIB_VAULT_CFG_TO_SIZE(deviceConf->vaultSize[die]) ==
                                    sectionTable[die][QLIB_SECTION_ID_VAULT].size,
                                QLIB_STATUS__INVALID_PARAMETER);
            }
#ifndef Q2_API
            else
            {
                QLIB_ASSERT_RET(sectionTable[die][QLIB_SECTION_ID_VAULT].size == 0u, QLIB_STATUS__INVALID_PARAMETER);
                QLIB_ASSERT_RET(deviceConf->vaultSize[die] == QLIB_VAULT_DISABLED_RPMC_8_COUNTERS,
                                QLIB_STATUS__INVALID_PARAMETER);
            }
#endif
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Configure the device                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_ConfigDevice(qlibContext,
                                                deviceMasterKey,
                                                deviceSecretKey,
                                                sectionTable,
                                                restrictedKeys,
                                                fullAccessKeys,
                                                lmsKeys,
                                                preProvisionedMasterKey,
                                                watchdogDefault,
                                                deviceConf,
                                                suid));
    /*-----------------------------------------------------------------------------------------------------*/
    /* Re-sync the device                                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncState(qlibContext));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_GetDeviceConfig(QLIB_CONTEXT_T*       qlibContext,
                                   QLIB_WATCHDOG_CONF_T* watchdogDefault,
                                   QLIB_DEVICE_CONF_T*   deviceConf)
{
    GMC_T         gmc;
    DEVCFG_T      devCfg = 0;
    AWDTCFG_T     awdtDefault;
    BOOL          quadEnabled;
    U32           val = 0u;
    U8            sectionId;
    U8            rstPAField = 0u;
    U8            origDie    = qlibContext->activeDie;
    QLIB_STATUS_T ret        = QLIB_STATUS__OK;
#if QLIB_NUM_OF_DIES > 1
    uint_fast8_t nextDie;
#endif
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != watchdogDefault, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != deviceConf, QLIB_STATUS__INVALID_PARAMETER);

    (void)memset(watchdogDefault, 0, sizeof(QLIB_WATCHDOG_CONF_T));
    (void)memset(deviceConf, 0, sizeof(QLIB_DEVICE_CONF_T));
    do
    {
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC__get_GMC(qlibContext, gmc), ret, error);
        devCfg = QLIB_REG_GMC_GET_DEVCFG(gmc);
        if (qlibContext->activeDie == QLIB_INIT_DIE_ID)
        {
            awdtDefault = QLIB_REG_GMC_GET_AWDT_DFLT(gmc);

            //Set watchdogDefault values
            watchdogDefault->enable        = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__AWDT_EN));
            watchdogDefault->lfOscEn       = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__LFOSC_EN));
            watchdogDefault->swResetEn     = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__SRST_EN));
            watchdogDefault->authenticated = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__AUTH_WDT));
            watchdogDefault->sectionID     = (U32)READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__KID);
            watchdogDefault->threshold =
                (QLIB_AWDT_TH_T)MIN((U32)READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__TH), (U32)QLIB_AWDT_TH_12_DAYS);
            watchdogDefault->lock      = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__LOCK));
            watchdogDefault->oscRateHz = ((U32)READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__OSC_RATE_KHZ) << 10);
            if (W77Q_AWDTCFG_OSC_RATE_FRAC(qlibContext) != 0u)
            {
                watchdogDefault->oscRateHz += ((U32)READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__OSC_RATE_FRAC) << 6);
            }
            watchdogDefault->fallbackEn = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__FB_EN));

            //Set devCfg values
            if ((0u == W77Q_RST_RESP(qlibContext)) || (0u == READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__RST_RESP_EN)))
            {
                (void)memset(deviceConf->resetResp.response1, 0, sizeof(deviceConf->resetResp.response1));
                (void)memset(deviceConf->resetResp.response2, 0, sizeof(deviceConf->resetResp.response2));
            }
            else
            {
                QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_RST_RESP(qlibContext, deviceConf->resetResp.response1));
            }
            deviceConf->safeFB            = INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__FB_EN));
            deviceConf->speculCK          = INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__CK_SPECUL));
            deviceConf->nonSecureFormatEn = INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__FORMAT_EN));
            deviceConf->lock =
                (W77Q_DEVCFG_LOCK(qlibContext) != 0u) ? INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__CFG_LOCK)) : FALSE;

            QLIB_STATUS_RET_CHECK_GOTO(QLIB_STD_GetQuadEnable(qlibContext, &quadEnabled), ret, error);
            deviceConf->pinMux.dedicatedResetInEn = INT_TO_BOOLEAN(READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RST_IN_EN));

            deviceConf->pinMux.io23Mux = QLIB_IO23_MODE__NONE;
            if (quadEnabled == TRUE)
            {
                if ((READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTI_OVRD) == 0u) &&
                    (READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTO_EN) == 0u))
                {
                    deviceConf->pinMux.io23Mux = QLIB_IO23_MODE__QUAD;
                }
            }
            else
            { //quadEnable == FALSE
                if ((READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTI_OVRD) == 0u) &&
                    (READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTO_EN) == 0u))
                {
                    deviceConf->pinMux.io23Mux = QLIB_IO23_MODE__LEGACY_WP_HOLD;
                }
                else
                {
                    if (
                        (READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTI_OVRD) == 1u) &&
                        (READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTO_EN) == 1u) &&
                        (READ_VAR_FIELD(awdtDefault, QLIB_REG_AWDTCFG__RSTI_EN) == 1u))
                    {
                        deviceConf->pinMux.io23Mux = QLIB_IO23_MODE__RESET_IN_OUT;
                    }
                }
            }

            deviceConf->bootFailReset = (W77Q_DEVCFG_BOOT_FAIL_RST(qlibContext) != 0u)
                                            ? INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__BOOT_FAIL_RST))
                                            : FALSE;
            if (W77Q_FAST_READ_DUMMY_CONFIG(qlibContext) != 0u)
            {
                QLIB_STATUS_RET_CHECK_GOTO(QLIB_STD_getPowerUpDummyCycles(qlibContext, &deviceConf->fastReadDummyCycles),
                                           ret,
                                           error);
            }

            val = (U32)(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__SECT_SEL) + (U32)LOG2(QLIB_MIN_SECTION_SIZE));
            QLIB_ASSERT_WITH_ERROR_GOTO(val >= (U32)QLIB_STD_ADDR_LEN__22_BIT && val < (U32)QLIB_STD_ADDR_LEN__LAST,
                                        QLIB_STATUS__INVALID_PARAMETER,
                                        ret,
                                        error)
            deviceConf->stdAddrSize.addrLen = (QLIB_STD_ADDR_LEN_T)val;

            QLIB_STATUS_RET_CHECK_GOTO(QLIB_STD_GetPowerUpAddressMode(qlibContext, &deviceConf->stdAddrSize.addrMode),
                                       ret,
                                       error);
            deviceConf->rngPAEn = (W77Q_RNG_FEATURE(qlibContext) != 0u)
                                      ? INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__RNG_PA_EN))
                                      : FALSE;
        }
        deviceConf->ctagModeMulti =
            (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u) ? INT_TO_BOOLEAN(READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__CTAG_MODE)) : FALSE;

        val = (U32)READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__VAULT_MEM);
        deviceConf->vaultSize[qlibContext->activeDie] =
            (W77Q_VAULT(qlibContext) != 0u) ? (QLIB_VAULT_RPMC_CONFIG_T)val : QLIB_VAULT_DISABLED_RPMC_8_COUNTERS;

        rstPAField = (W77Q_RST_PA(qlibContext) != 0u) ? (U8)READ_VAR_FIELD(devCfg, QLIB_REG_DEVCFG__RST_PA) : 1u;
        for (sectionId = 0; sectionId < QLIB_NUM_OF_MAIN_SECTIONS; sectionId++)
        {
            deviceConf->resetPA[qlibContext->activeDie][sectionId] = INT_TO_BOOLEAN(rstPAField & (1u << sectionId));
        }

#if QLIB_NUM_OF_DIES > 1
        nextDie = (qlibContext->activeDie + 1) % QLIB_NUM_OF_DIES;
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_SetActiveDie(qlibContext, nextDie), ret, error);
#endif
    } while (qlibContext->activeDie != origDie);

    return QLIB_STATUS__OK;
error:
#if QLIB_NUM_OF_DIES > 1
    QLIB_SetActiveDie(qlibContext, origDie);
#endif
    return ret;
}

QLIB_STATUS_T QLIB_GetSectionConfiguration(QLIB_CONTEXT_T* qlibContext,
                                           U32             sectionID,
                                           U32*            baseAddr,
                                           U32*            size,
                                           QLIB_POLICY_T*  policy,
                                           U64*            digest,
                                           U32*            crc,
                                           U32*            version)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_GetSectionConfiguration(qlibContext, sectionID, baseAddr, size, policy, digest, crc, version);
}

QLIB_STATUS_T QLIB_ConfigSection(QLIB_CONTEXT_T*            qlibContext,
                                 U32                        sectionID,
                                 const QLIB_POLICY_T*       policy,
                                 const U64*                 digest,
                                 const U32*                 crc,
                                 const U32*                 newVersion,
                                 BOOL                       swap,
                                 QLIB_SECTION_CONF_ACTION_T action)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform Section Config                                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_ConfigSection(qlibContext, sectionID, policy, digest, crc, newVersion, swap, action));

    if ((W77Q_SET_SCR_MODE(qlibContext) == 0u) && (action != QLIB_SECTION_CONF_ACTION__NO))
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Reopen the session to this section, after 'set_SCRn' revokes access privileges to the section   */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSession(qlibContext, sectionID, QLIB_SESSION_ACCESS_FULL));
    }
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_ConfigAccess(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL readEnable, BOOL writeEnable)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform configuration                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    return QLIB_SEC_ConfigAccess(qlibContext, sectionID, readEnable, writeEnable);
}

QLIB_STATUS_T QLIB_LoadKey(QLIB_CONTEXT_T* qlibContext, U32 sectionID, const KEY_T key, BOOL fullAccess)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_LoadKey(qlibContext, sectionID, key, fullAccess);
}

QLIB_STATUS_T QLIB_RemoveKey(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL fullAccess)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_RemoveKey(qlibContext, sectionID, fullAccess);
}

QLIB_STATUS_T QLIB_Connect(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_STATUS_RET_CHECK(QLIB_TM_Connect(qlibContext));

#if QLIB_NUM_OF_DIES > 1
    qlibContext->activeDie = QLIB_INIT_DIE_ID;
#endif
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_Disconnect(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(!QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

#if QLIB_NUM_OF_DIES > 1
    QLIB_STATUS_RET_CHECK(QLIB_SetActiveDie(qlibContext, QLIB_INIT_DIE_ID));
#endif
    QLIB_STATUS_RET_CHECK(QLIB_TM_Disconnect(qlibContext));
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_OpenSession(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_SESSION_ACCESS_T sessionAccess)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_OpenSession(qlibContext, sectionID, sessionAccess);
}

QLIB_STATUS_T QLIB_CloseSession(QLIB_CONTEXT_T* qlibContext, U32 sectionID)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_CloseSession(qlibContext, sectionID);
}

QLIB_STATUS_T QLIB_PlainAccessGrant(QLIB_CONTEXT_T* qlibContext, U32 sectionID)
{
    return QLIB_PlainAccessGrant_L(qlibContext, sectionID, QLIB_LOAD_ACLR_ANY);
}

QLIB_STATUS_T QLIB_PlainAccessRevoke(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_PA_REVOKE_TYPE_T revokeType)
{
    QLIB_POLICY_T policy = {0};

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_SECTION_ID_VAULT > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* check if the section is authenticated plain access                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_GetSectionConfiguration(qlibContext, sectionID, NULL, NULL, &policy, NULL, NULL, NULL));
    QLIB_ASSERT_RET((W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u) || (policy.authPlainAccess == 1u), QLIB_STATUS__NOT_SUPPORTED);

    if (((revokeType == QLIB_PA_REVOKE_ALL_ACCESS) &&
         (QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled != QLIB_SECTION_PLAIN_EN_NO)) ||
        ((QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled & QLIB_SECTION_PLAIN_EN_WR) != 0u))

    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_PlainAccess_Revoke(qlibContext, sectionID, revokeType));

        /*-------------------------------------------------------------------------------------------------*/
        /* Set plain access state in QLIB                                                                  */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled =
            (revokeType == QLIB_PA_REVOKE_ALL_ACCESS || policy.plainAccessReadEnable == 0u) ? QLIB_SECTION_PLAIN_EN_NO
                                                                                            : QLIB_SECTION_PLAIN_EN_RD;
    }
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_CheckIntegrity(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_INTEGRITY_T integrityType)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_CheckIntegrity(qlibContext, sectionID, integrityType);
}

QLIB_STATUS_T QLIB_CalcCDI(QLIB_CONTEXT_T* qlibContext, _256BIT nextCdi, const _256BIT prevCdi, U32 sectionId)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != nextCdi, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionId, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionId), QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_CalcCDI(qlibContext, nextCdi, prevCdi, sectionId);
}

QLIB_STATUS_T QLIB_Watchdog_ConfigSet(QLIB_CONTEXT_T* qlibContext, const QLIB_WATCHDOG_CONF_T* watchdogCFG)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != watchdogCFG, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_Watchdog_ConfigSet(qlibContext, watchdogCFG);
}

QLIB_STATUS_T QLIB_Watchdog_ConfigGet(QLIB_CONTEXT_T* qlibContext, QLIB_WATCHDOG_CONF_T* watchdogCFG)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != watchdogCFG, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_Watchdog_ConfigGet(qlibContext, watchdogCFG);
}

#ifdef Q2_API
QLIB_STATUS_T QLIB2_Watchdog_Get(QLIB_CONTEXT_T* qlibContext, U32* secondsPassed, U32* ticksResidue, BOOL* expired)
{
    AWDTSR_T AWDTSR = 0;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_AWDTSR(qlibContext, &AWDTSR));

    if (NULL != secondsPassed)
    {
        *secondsPassed = (U32)READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_VAL(qlibContext));
    }

    if (NULL != ticksResidue)
    {
        *ticksResidue = (U32)READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_RES(qlibContext));
    }

    if (NULL != expired)
    {
        *expired = (1u == READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_EXP_S)) ? TRUE : FALSE;
    }

    return QLIB_STATUS__OK;
}
#endif

QLIB_STATUS_T QLIB_Watchdog_Touch(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_Watchdog_Touch(qlibContext);
}

QLIB_STATUS_T QLIB_Watchdog_Trigger(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_Watchdog_Trigger(qlibContext);
}

QLIB_STATUS_T QLIB_Watchdog_Get(QLIB_CONTEXT_T* qlibContext, U32* milliSecondsPassed, BOOL* expired)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(qlibContext->activeDie == QLIB_INIT_DIE_ID, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_Watchdog_Get(qlibContext, milliSecondsPassed, expired);
}

QLIB_STATUS_T QLIB_GetId(QLIB_CONTEXT_T* qlibContext, QLIB_ID_T* id_p)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != id_p, QLIB_STATUS__INVALID_PARAMETER);

        QLIB_STATUS_RET_CHECK(QLIB_STD_GetId(qlibContext, &(id_p->std)));
    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetId(qlibContext, &(id_p->sec)));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_GetHWVersion(QLIB_CONTEXT_T* qlibContext, QLIB_HW_VER_T* hwVer)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != hwVer, QLIB_STATUS__INVALID_PARAMETER);

        QLIB_STATUS_RET_CHECK(QLIB_STD_GetHwVersion(qlibContext, &(hwVer->std)));
        hwVer->info.isSingleDie = ((hwVer->std.memoryType == 0x8Bu) || (hwVer->std.memoryType == 0x8Du) ? FALSE : TRUE);

        hwVer->info.flashSize = DEVICE_ID_TO_TARGET_SIZE(hwVer->std.deviceID);
        hwVer->info.voltage   = (hwVer->std.memoryType == 0x4Au) || (hwVer->std.memoryType == 0x4Bu) ||
                                      (hwVer->std.memoryType == 0x4Cu) || (hwVer->std.memoryType == 0x4Du)
                                    ? QLIB_TARGET_VOLTAGE_3_3V
                                    : QLIB_TARGET_VOLTAGE_1_8V;

    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetHWVersion(qlibContext, &(hwVer->sec)));

    switch (hwVer->sec.revision)
    {
        case 0:
            hwVer->info.revision = QLIB_TARGET_REVISION_A;
            break;
        case 1:
            hwVer->info.revision = QLIB_TARGET_REVISION_B;
            break;
        case 2:
            hwVer->info.revision = QLIB_TARGET_REVISION_C;
            break;
        default:
            hwVer->info.revision = QLIB_TARGET_REVISION_UNKNOWN;
            break;
    }
    QLIB_STATUS_RET_CHECK(QLIB_GetTargetFlash_L(hwVer, &hwVer->info.target));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_GetStatus(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    return QLIB_SEC_GetStatus(qlibContext);
}

void* QLIB_GetUserData(QLIB_CONTEXT_T* qlibContext)
{
    if (qlibContext == NULL)
    {
        return NULL;
    }
    else
    {
        return qlibContext->userData;
    }
}

void QLIB_SetUserData(QLIB_CONTEXT_T* qlibContext, void* userData)
{
    if (qlibContext != NULL)
    {
        qlibContext->userData = userData;
    }
}

QLIB_STATUS_T QLIB_ExportState(QLIB_CONTEXT_T* qlibContext, QLIB_SYNC_OBJ_T* syncObject)
{
    U32 die;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != syncObject, QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Fill the synchronization object                                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    (void)memset(syncObject, 0, sizeof(QLIB_SYNC_OBJ_T));
    (void)memcpy(&syncObject->busInterface, &qlibContext->busInterface, sizeof(qlibContext->busInterface));
    syncObject->busInterface.busIsLocked = FALSE;
    (void)memcpy((void*)syncObject->wid, (void*)qlibContext->wid, sizeof(QLIB_WID_T));

    syncObject->resetStatus = qlibContext->resetStatus;
    syncObject->addrSize    = qlibContext->addrSize;
    syncObject->addrMode    = qlibContext->addrMode;

    for (die = 0; die < QLIB_NUM_OF_DIES; die++)
    {
        (void)memcpy(syncObject->sectionsState[die],
                     qlibContext->dieState[die].sectionsState,
                     sizeof(qlibContext->dieState[die].sectionsState));
        syncObject->vaultSize[die] = qlibContext->dieState[die].vaultSize;
    }
    (void)memcpy(syncObject->cfgBitArr, qlibContext->cfgBitArr, sizeof(qlibContext->cfgBitArr));
    syncObject->detectedDeviceID = qlibContext->detectedDeviceID;
    syncObject->fastReadDummy    = qlibContext->fastReadDummy;
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_ImportState(QLIB_CONTEXT_T* qlibContext, const QLIB_SYNC_OBJ_T* syncObject)
{
    BOOL busIsLocked = FALSE;
    U32  die;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != syncObject, QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Update the lib context                                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    busIsLocked = qlibContext->busInterface.busIsLocked;
    (void)memcpy(&qlibContext->busInterface, &syncObject->busInterface, sizeof(qlibContext->busInterface));
    qlibContext->busInterface.busIsLocked = busIsLocked;
    (void)memcpy((void*)qlibContext->wid, (const void*)syncObject->wid, sizeof(QLIB_WID_T));
    qlibContext->resetStatus = syncObject->resetStatus;
    qlibContext->addrSize    = syncObject->addrSize;
    qlibContext->addrMode    = syncObject->addrMode;

    for (die = 0; die < QLIB_NUM_OF_DIES; die++)
    {
        (void)memcpy(qlibContext->dieState[die].sectionsState,
                     syncObject->sectionsState[die],
                     sizeof(qlibContext->dieState[die].sectionsState));
        qlibContext->dieState[die].vaultSize = syncObject->vaultSize[die];
    }
    (void)memcpy(qlibContext->cfgBitArr, syncObject->cfgBitArr, sizeof(qlibContext->cfgBitArr));
    qlibContext->detectedDeviceID = syncObject->detectedDeviceID;
    qlibContext->fastReadDummy    = syncObject->fastReadDummy;

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_GetVersion(QLIB_SW_VERSION_T* versionInfo)
{
    versionInfo->qlibVersion = QLIB_VERSION;
#ifdef Q2_API
    versionInfo->qlibTarget.isSingleDie = TRUE;
#if (QLIB_TARGET == w77q32jw_revB)
    versionInfo->qlibTarget.flashSize = QLIB_TARGET_SIZE_32Mb;
    versionInfo->qlibTarget.revision  = QLIB_TARGET_REVISION_C;
#elif ((QLIB_TARGET == w77q64jw_revA) || (QLIB_TARGET == w77q64jv_revA))
    versionInfo->qlibTarget.flashSize = QLIB_TARGET_SIZE_64Mb;
    versionInfo->qlibTarget.revision  = QLIB_TARGET_REVISION_A;
#elif ((QLIB_TARGET == w77q128jw_revA) || (QLIB_TARGET == w77q128jv_revA))
    versionInfo->qlibTarget.flashSize = QLIB_TARGET_SIZE_128Mb;
    versionInfo->qlibTarget.revision  = QLIB_TARGET_REVISION_A;
#else
    versionInfo->qlibTarget.flashSize = QLIB_TARGET_SIZE_UNKNOWN;
    versionInfo->qlibTarget.revision  = QLIB_TARGET_REVISION_UNKNOWN;
#endif
#if ((QLIB_TARGET == w77q128jv_revA) || (QLIB_TARGET == w77q64jv_revA))
    versionInfo->qlibTarget.voltage = QLIB_TARGET_VOLTAGE_3_3V;
#elif ((QLIB_TARGET == w77q32jw_revB) || (QLIB_TARGET == w77q128jw_revA) || (QLIB_TARGET == w77q64jw_revA))
    versionInfo->qlibTarget.voltage   = QLIB_TARGET_VOLTAGE_1_8V;
#else
    versionInfo->qlibTarget.voltage   = QLIB_TARGET_VOLTAGE_UNKNOWN;
#endif
#else
    versionInfo->qlibTarget = (U32)(QLIB_TARGET);
#endif
    return QLIB_STATUS__OK;
}


#if QLIB_NUM_OF_DIES > 1
QLIB_STATUS_T QLIB_SetActiveDie(QLIB_CONTEXT_T* qlibContext, U8 die)
{
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(QLIB_NUM_OF_DIES > die, QLIB_STATUS__INVALID_PARAMETER);

    if (die != qlibContext->activeDie)
    {
#ifdef QLIB_RESUME_ON_DIE_SELECT
        // before leaving the previous die, resume suspend
        {
            if (QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u && qlibContext->isSuspended == 1u)
            {
                QLIB_STATUS_RET_CHECK(QLIB_Resume(qlibContext));
            }
        }
#endif //QLIB_RESUME_ON_DIE_SELECT
        QLIB_STATUS_RET_CHECK(QLIB_STD_SetActiveDie(qlibContext, die, FALSE));
        qlibContext->activeDie = die;
    }

    return QLIB_STATUS__OK;
}
#endif

QLIB_STATUS_T QLIB_GetResetStatus(QLIB_CONTEXT_T* qlibContext, QLIB_RESET_STATUS_T* resetStatus)
{
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != resetStatus, QLIB_STATUS__INVALID_PARAMETER);

    *resetStatus = qlibContext->resetStatus;

    return QLIB_STATUS__OK;
}

#ifndef EXCLUDE_Q2_4_BYTES_ADDRESS_MODE
QLIB_STATUS_T QLIB_SetAddressMode(QLIB_CONTEXT_T* qlibContext, QLIB_STD_ADDR_MODE_T addrMode)
{
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(Q2_4_BYTES_ADDRESS_MODE(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_STATUS_RET_CHECK(QLIB_STD_SetAddressMode(qlibContext, addrMode));
    return QLIB_STATUS__OK;
}
#endif


#ifdef QLIB_SIGN_DATA_BY_FLASH
QLIB_STATUS_T QLIB_Sign(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U8* dataIn, U32 dataSize, _256BIT signature)
{
    QLIB_POLICY_T policy;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != dataIn, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(0u != dataSize, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != signature, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
    if (W77Q_SUPPORT_LMS_ATTESTATION(qlibContext) != 0u)
    {
        return QLIB_STATUS__NOT_SUPPORTED;
    }
    else
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Verify section is not rollback protected since both active and inactive partitions are erased   */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_SEC_GetSectionConfiguration(qlibContext, sectionID, NULL, NULL, &policy, NULL, NULL, NULL));
        QLIB_ASSERT_RET(policy.rollbackProt == 0u, QLIB_STATUS__INVALID_PARAMETER);

        /*-------------------------------------------------------------------------------------------------*/
        /* Secure command is ignored if power is down or suspended                                         */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
        QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

        return QLIB_SEC_SignVerify(qlibContext, sectionID, dataIn, dataSize, signature, FALSE);
    }
}

QLIB_STATUS_T QLIB_Verify(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U8* dataIn, U32 dataSize, const _256BIT signature)
{
    _256BIT tempSignature;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != (void*)qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(NULL != (void*)dataIn, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(0u != dataSize, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != signature, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
    if (W77Q_SUPPORT_LMS_ATTESTATION(qlibContext) != 0u)
    {
        return QLIB_STATUS__NOT_SUPPORTED;
    }
    else
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Open session is required for Verify                                                             */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);

        /*-----------------------------------------------------------------------------------------------------*/
        /* Copy the signature to a temporary variable as the QLIB_SEC_SignVerify gets a non-const signature    */
        /*-----------------------------------------------------------------------------------------------------*/
        (void)memcpy(tempSignature, signature, sizeof(tempSignature));
        return QLIB_SEC_SignVerify(qlibContext, sectionID, dataIn, dataSize, tempSignature, TRUE);
    }
}

#endif

#ifndef EXCLUDE_LMS
QLIB_STATUS_T QLIB_SendLMSCommand(QLIB_CONTEXT_T* qlibContext, const U32* cmd, U32 cmdSize, U32 sectionID)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_SUPPORT_LMS(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(NULL != cmd, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_LMS_COMMAND_SIZE == cmdSize, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_SendLMSCommand(qlibContext, cmd, cmdSize, sectionID);
}
#endif

#ifndef EXCLUDE_MEM_COPY
QLIB_STATUS_T QLIB_MemCpy(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U32 dest, U32 src, U32 size)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_MEM_COPY(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(0u < size, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET((dest + size) >= size, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((src + size) >= size, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_MemCopy(qlibContext, dest, src, size, sectionID);
}
#endif

#ifndef EXCLUDE_MEM_CRC
QLIB_STATUS_T QLIB_MemCRC(QLIB_CONTEXT_T* qlibContext, U32* crc32, U32 sectionID, U32 offset, U32 size)
{
    QLIB_POLICY_T policy = {0};
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_MEM_CRC(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(0u < size, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    /********************************************************************************************************
     * Read current section version tag and check policy
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_GetSectionConfiguration(qlibContext, sectionID, NULL, NULL, &policy, NULL, NULL, NULL));
    QLIB_ASSERT_RET((offset + size) <= QLIB_CALC_SECTION_SIZE(qlibContext, sectionID), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);

    return QLIB_SEC_MemCrc(qlibContext, crc32, sectionID, offset, size);
}
#endif

#ifndef EXCLUDE_SECURE_LOG
QLIB_STATUS_T QLIB_SecureLogRead(QLIB_CONTEXT_T* qlibContext, U8* buf, U32* addr, U32 sectionID, BOOL secure)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_SECURE_LOG(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(!((FALSE == secure) && (QLIB_SECTION_ID_VAULT == sectionID)), QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_SecureLogRead(qlibContext, buf, addr, sectionID, secure);
}

QLIB_STATUS_T QLIB_SecureLogWrite(QLIB_CONTEXT_T* qlibContext, const U8* buf, U32 sectionID, U32 size, BOOL secure)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_SECURE_LOG(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(0u < size, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(!((FALSE == secure) && (QLIB_SECTION_ID_VAULT == sectionID)), QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_SecureLogWrite(qlibContext, buf, sectionID, size, secure);
}
#endif

#ifndef EXCLUDE_W77Q_RNG_FEATURE
QLIB_STATUS_T QLIB_GetRandom(QLIB_CONTEXT_T* qlibContext, U8* random, U32 randomSize)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_RNG_FEATURE(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(NULL != random, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(0u != randomSize, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_GetRandom(qlibContext, random, randomSize);
}
#endif

#if !defined EXCLUDE_LMS_ATTESTATION && !defined Q2_API
QLIB_STATUS_T                                    QLIB_LMS_Attest_SetPrivateKey(QLIB_CONTEXT_T*                 qlibContext,
                                                                               const LMS_ATTEST_PRIVATE_SEED_T seed,
                                                                               const LMS_ATTEST_KEY_ID_T       keyId)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_SUPPORT_LMS_ATTESTATION(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(NULL != seed, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != keyId, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_LMS_Attest_SetPrivateKey(qlibContext, seed, keyId);
}

QLIB_STATUS_T QLIB_LMS_Attest_GetPublicKey(QLIB_CONTEXT_T*    qlibContext,
                                           LMS_ATTEST_CHUNK_T pubKey,
                                           LMS_ATTEST_CHUNK_T pubCache[],
                                           U32                pubCacheLen)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER)
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_SUPPORT_LMS_ATTESTATION(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(NULL != pubKey, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(0u == pubCacheLen || NULL != pubCache, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(pubCacheLen <= QLIB_LMS_ATTEST_ALL_NODES, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_LMS_Attest_GetPublicKey(qlibContext, pubKey, pubCache, pubCacheLen);
}

QLIB_STATUS_T QLIB_LMS_Attest_Sign(QLIB_CONTEXT_T*          qlibContext,
                                   const U8*                msg,
                                   U32                      msgSize,
                                   const LMS_ATTEST_NONCE_T nonce,
                                   LMS_ATTEST_CHUNK_T       pubCache[],
                                   U32                      pubCacheLen,
                                   QLIB_OTS_SIG_T*          sig)
{
    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(W77Q_SUPPORT_LMS_ATTESTATION(qlibContext) != 0u, QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET(NULL != msg, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(0u < msgSize, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != nonce, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != sig, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(0u == pubCacheLen || NULL != pubCache, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(pubCacheLen <= QLIB_LMS_ATTEST_ALL_NODES, QLIB_STATUS__INVALID_PARAMETER);

    return QLIB_SEC_LMS_Attest_Sign(qlibContext, msg, msgSize, nonce, pubCache, pubCacheLen, sig);
}
#endif

QLIB_STATUS_T QLIB_IsKeyProvisioned(QLIB_CONTEXT_T* qlibContext, QLIB_KID_TYPE_T keyIdType, U32 sectionID, BOOL* isProvisioned)
{
    QLIB_STATUS_T status = QLIB_STATUS__OK;

    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != isProvisioned, QLIB_STATUS__INVALID_PARAMETER);

    if (W77Q_CMD_GET_KEYS_STATUS(qlibContext) != 0u)
    {
        status = QLIB_SEC_IsKeyProvisioned(qlibContext, keyIdType, sectionID, isProvisioned);
    }
    else
    {
        status = QLIB_STATUS__NOT_SUPPORTED;
    }
    return status;
}

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                             LOCAL FUNCTIONS                                             */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
* @brief       This routine waits till flash is ready and detects and sets the bus mode (SPI/QPI) and flash device ID
*
* @param       qlibContext   qlib context object
*
* @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_waitReadyAndInitBusMode_L(QLIB_CONTEXT_T* qlibContext)
{
    QLIB_BUS_FORMAT_T currentFormat;

    // identify and set current bus mode
    QLIB_STATUS_RET_CHECK(QLIB_STD_WaitTillFlashIsReady(qlibContext, &currentFormat, &qlibContext->detectedDeviceID));

    // Set bus mode
    qlibContext->busInterface.busMode = QLIB_BUS_FORMAT_GET_MODE(currentFormat);
    qlibContext->busInterface.dtr     = QLIB_BUS_FORMAT_GET_DTR(currentFormat);
    QLIB_STATUS_RET_CHECK(QLIB_SetInterface(qlibContext, currentFormat));

    // Clear errors in SSR caused by AutoSense
    QLIB_STATUS_RET_CHECK(QLIB_SEC_ClearSSR(qlibContext));

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
* @brief       This routine loads the ACL from Section Security Policy Register (SSPR), affecting the 
*              plain access runtime privileges of the Section
*
* @param       qlibContext   qlib context object
* @param       sectionID     Section ID
* @param       condition     load ACL only if the section is with specific authentication or access. fail otherwise
*
* @return      0 if no error occurred, QLIB_STATUS__(ERROR) otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_PlainAccessGrant_L(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_LOAD_ACLR_T condition)
{
    QLIB_POLICY_T policy = {0};
    U32           sectionSize;
    QLIB_STATUS_T ret;

    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != qlibContext, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_DEVICE_INITIALIZED(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(QLIB_SECTION_ID_VAULT > sectionID, QLIB_STATUS__INVALID_PARAMETER);

    /********************************************************************************************************
     * check if the section is authenticated plain access
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_GetSectionConfiguration(qlibContext, sectionID, NULL, &sectionSize, &policy, NULL, NULL, NULL));
    QLIB_ASSERT_RET(sectionSize != 0u, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE); // section is disabled

    QLIB_ASSERT_RET((policy.plainAccessWriteEnable == 1u) || (((U8)condition & (U8)QLIB_LOAD_ACLR_PLAIN_WR) == 0u),
                    QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
    QLIB_ASSERT_RET((policy.plainAccessReadEnable == 1u) || (((U8)condition & (U8)QLIB_LOAD_ACLR_PLAIN_RD) == 0u),
                    QLIB_STATUS__DEVICE_PRIVILEGE_ERR);

    if (policy.authPlainAccess == 1u)
    {
        QLIB_ASSERT_RET(((U8)condition & (U8)QLIB_LOAD_ACLR_NON_AUTH) == 0u, QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
        ret = QLIB_SEC_AuthPlainAccess_Grant(qlibContext, sectionID);
    }
    else
    {
        ret = QLIB_SEC_EnablePlainAccess(qlibContext, sectionID);
    }

    /*---------------------------------------------------------------------------------------------*/
    /* Mark plain access is enabled                                                                */
    /*---------------------------------------------------------------------------------------------*/
    if (QLIB_STATUS__OK == ret || QLIB_STATUS__DEVICE_INTEGRITY_ERR == ret)
    {
        QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled = QLIB_SECTION_PLAIN_EN_NO;
        if (policy.plainAccessWriteEnable == 1u)
        {
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled |= QLIB_SECTION_PLAIN_EN_WR;
        }
        if (policy.plainAccessReadEnable == 1u && QLIB_STATUS__DEVICE_INTEGRITY_ERR != ret)
        {
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled |= QLIB_SECTION_PLAIN_EN_RD;
        }
    }
    QLIB_STATUS_RET_CHECK(ret);
    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function translates the flash HW version to qlib target as defined in @ref qlib_targets.h
 *
 * @param[in]   hwVer        Hardware version information
 * @param[out]  target       The detected flash target
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_GetTargetFlash_L(QLIB_HW_VER_T* hwVer, U32* target)
{
    if ((hwVer->sec.securityVersion & 0xF0u) == 0x20u)
    {
        // Q2 flash
        if (hwVer->sec.securityVersion == 0x20u)
        {
            // Q2 MCD (32Mb)
            if (hwVer->info.revision == QLIB_TARGET_REVISION_B || hwVer->info.revision == QLIB_TARGET_REVISION_C)
            {
                *target = w77q32jw_revB;
            }
            else
            {
                return QLIB_STATUS__NOT_SUPPORTED;
            }
        }
        else if ((hwVer->sec.securityVersion == 0x24u) || (hwVer->sec.securityVersion == 0x28u))
        {
            // Q2 HCD (64Mb/128Mb)
            if (hwVer->info.voltage == QLIB_TARGET_VOLTAGE_1_8V)
            {
                if (hwVer->info.revision == QLIB_TARGET_REVISION_A)
                {
                    *target = (hwVer->info.flashSize == QLIB_TARGET_SIZE_64Mb ? w77q64jw_revA : w77q128jw_revA);
                }
                else
                {
                    return QLIB_STATUS__NOT_SUPPORTED;
                }
            }
            else
            {
                // QLIB_TARGET_VOLTAGE_3_3V
                if (hwVer->info.revision == QLIB_TARGET_REVISION_A)
                {
                    *target = (hwVer->info.flashSize == QLIB_TARGET_SIZE_64Mb ? w77q64jv_revA : w77q128jv_revA);
                }
                else
                {
                    return QLIB_STATUS__NOT_SUPPORTED;
                }
            }
        }
        else
        {
            return QLIB_STATUS__NOT_SUPPORTED;
        }
    }
    else if ((hwVer->sec.securityVersion & 0xF0u) == 0x30u)
    {
        // Q3 chip
        if (hwVer->sec.securityVersion == 0x30u)
        {
            // Q3 chip W77Q/T industrial
            if (hwVer->std.memoryType == 0x8Eu)
            {
                // W77T : Octal SPI secure flash
                *target = w77t25nwxxi_revA;
            }
            else
            {
                // W77Q: Quad SPI secure flash
                *target = w77q25nwxxi_revA;
            }
        }
        else if (hwVer->sec.securityVersion == 0x34u)
        {
            // Q3 chip W77Q/T automotive
            if (hwVer->std.memoryType == 0x8Eu)
            {
                // W77T : Octal SPI secure flash
                *target = w77t25nwxxa_revA;
            }
            else
            {
                // W77Q: Quad SPI secure flash
                *target = w77q25nwxxa_revA;
            }
        }
        else
        {
            return QLIB_STATUS__NOT_SUPPORTED;
        }
    }
    else
    {
        return QLIB_STATUS__NOT_SUPPORTED;
    }

    return QLIB_STATUS__OK;
}
