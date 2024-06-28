/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2019 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib_sec.c
* @brief      This file contains security features implementation
*
* ### project qlib
*
************************************************************************************************************/

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include "qlib_sec.h"

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                              DEFINITIONS                                                */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
 * Threshold value for DMC.
 * @ref QLIB_GetNotifications will return replaceDevice notification if DMC reach this value.
 * User may choose to define a different value .
************************************************************************************************************/
#ifndef QLIB_SEC_DMC_EOL_THRESHOLD
#define QLIB_SEC_DMC_EOL_THRESHOLD 0x3FFFF000
#endif
/************************************************************************************************************
 * Threshold value for TC.
 * @ref QLIB_GetNotifications will report resetDevice notification if TC reach this value.
 * User may choose to define a different value .
************************************************************************************************************/
#ifndef QLIB_SEC_TC_RESET_THRESHOLD
#define QLIB_SEC_TC_RESET_THRESHOLD 0xFFFFFFF0u
#endif

/************************************************************************************************************
 * LMS Attestation definitions
************************************************************************************************************/
#define QLIB_SEC_LMS_ATTEST_NODE_IS_EMPTY(node) \
    ((node[0] != 0u || node[1] != 0u || node[2] != 0u || node[3] != 0u || node[4] != 0u || node[5] != 0u) ? FALSE : TRUE)

#define SET_CMD_HW_BYPASS_NUM_RETRIES (100u)
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                  TYPES                                                  */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
typedef QLIB_STATUS_T (*QLIB_READ_FUNC_T)(QLIB_CONTEXT_T* qlibContext, U32 addr, U32* data32B);
#ifdef QLIB_SIGN_DATA_BY_FLASH
typedef QLIB_STATUS_T (*QLIB_SIGN_VERIFY_FUNC_T)(QLIB_CONTEXT_T* qlibContext, U32 enc_addr, _64BIT signature);
#endif

#ifndef EXCLUDE_LMS_ATTESTATION
/************************************************************************************************************
 * @brief Buffer used for LMS Attestation message hashing
************************************************************************************************************/
PACKED_START
typedef struct
{
    LMS_ATTEST_KEY_ID_T keyId;
    U32                 q;
    U16                 d_msg;
    LMS_ATTEST_NONCE_T  nonce;
} PACKED QLIB_SEC_OTS_MSG_T;
PACKED_END

typedef struct
{
    U32                nodeIndex;
    LMS_ATTEST_CHUNK_T hash;
} QLIB_SEC_LMS_ATTEST_HASH_NODE_T;
#endif

typedef enum QLIB_SEC_PROV_ACTION_T
{
    QLIB_SEC_PROV_VERIFY_ONLY,
    QLIB_SEC_PROV_CONFIG_ONLY,
    QLIB_SEC_PROV_CONFIG_IF_VERIFY_FAIL,
} QLIB_SEC_PROV_ACTION_T;
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                          FORWARD DECLARATION                                            */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
static QLIB_STATUS_T QLIB_SEC_KeyProvisioning_L(QLIB_CONTEXT_T*        qlibContext,
                                                const KEY_T            Kd,
                                                QLIB_KID_T             new_kid,
                                                const KEY_T            new_key,
                                                QLIB_SEC_PROV_ACTION_T action);

static QLIB_STATUS_T QLIB_SEC_LmsKeyProvisioning_L(QLIB_CONTEXT_T*      qlibContext,
                                                   const KEY_T          Kd,
                                                   QLIB_KID_T           new_kid,
                                                   const QLIB_LMS_KEY_T publicKey);

static QLIB_STATUS_T QLIB_SEC_setAllKeys_L(QLIB_CONTEXT_T*            qlibContext,
                                           const KEY_T                deviceMasterKey,
                                           const KEY_T                deviceSecretKey,
                                           const KEY_ARRAY_T          restrictedKeys,
                                           const KEY_ARRAY_T          fullAccessKeys,
                                           const QLIB_LMS_KEY_ARRAY_T lmsKeys,
                                           const KEY_T                preProvisionedMasterKey);
static QLIB_STATUS_T QLIB_SEC_configGMC_L(QLIB_CONTEXT_T*             qlibContext,
                                          const KEY_T                 deviceMasterKey,
                                          const QLIB_WATCHDOG_CONF_T* watchdogDefault,
                                          const QLIB_DEVICE_CONF_T*   deviceConf,
                                          BOOL*                       gmcChanged);
static QLIB_STATUS_T QLIB_SEC_configGMT_L(QLIB_CONTEXT_T*                   qlibContext,
                                          const KEY_T                       deviceMasterKey,
                                          const QLIB_SECTION_CONFIG_TABLE_T sectionTable,
                                          BOOL*                             gmtChanged);
static QLIB_STATUS_T QLIB_SEC_OpenSessionInternal_L(QLIB_CONTEXT_T* qlibContext,
                                                    QLIB_KID_T      kid,
                                                    const KEY_T     keyBuf,
                                                    BOOL            ignoreScrValidity);
static QLIB_STATUS_T QLIB_SEC_CloseSessionInternal_L(QLIB_CONTEXT_T* qlibContext, BOOL revokePA);
static QLIB_STATUS_T QLIB_SEC_GetWID_L(QLIB_CONTEXT_T* qlibContext, QLIB_WID_T id);
static QLIB_STATUS_T QLIB_SEC_GetStdAddrSize_L(QLIB_CONTEXT_T* qlibContext);
static QLIB_STATUS_T QLIB_SEC_GetSectionsSize_L(QLIB_CONTEXT_T* qlibContext);
static QLIB_STATUS_T QLIB_SEC_GetWatchdogConfig_L(QLIB_CONTEXT_T* qlibContext);
static void          QLIB_SEC_MarkSessionClose_L(QLIB_CONTEXT_T* qlibContext, U8 die);
static QLIB_STATUS_T QLIB_SEC_ConfigInitialSection_L(QLIB_CONTEXT_T*      qlibContext,
                                                     U32                  sectionIndex,
                                                     const QLIB_POLICY_T* policy,
                                                     U32                  crc,
                                                     U64                  digest,
                                                     const KEY_T          fullAccessKey);
static BOOL          QLIB_SEC_ConfigSectionPolicyAfterSize_L(QLIB_CONTEXT_T*              qlibContext,
                                                             U32                          sectionIndex,
                                                             const QLIB_SECTION_CONFIG_T* config);
static QLIB_STATUS_T QLIB_SEC_HwAuthPlainAccess_Grant_L(QLIB_CONTEXT_T* qlibContext, U32 sectionID);
static QLIB_STATUS_T QLIB_SEC_SwGrantRevokePA_L(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL grant);
static QLIB_STATUS_T QLIB_SEC_VerifyAddressSizeConfig_L(QLIB_CONTEXT_T* qlibContext, const QLIB_STD_ADDR_SIZE_T* addrSizeConf);
static void          QLIB_SEC_SetInterface_L(QLIB_CONTEXT_T* qlibContext, QLIB_BUS_MODE_T format);
static QLIB_STATUS_T QLIB_SEC_FormatActiveDie_L(QLIB_CONTEXT_T* qlibContext,
                                                const KEY_T     deviceMasterKey,
                                                BOOL            eraseDataOnly,
                                                BOOL            reset,
                                                BOOL            factoryDefault);
#ifndef EXCLUDE_LMS
static QLIB_STATUS_T QLIB_SEC_LMS_Write_L(QLIB_CONTEXT_T* qlibContext, const U32* buf, U32 sectionID, U32 size);
static QLIB_STATUS_T QLIB_SEC_LMS_Execute_L(QLIB_CONTEXT_T* qlibContext,
                                            U32             sectionID,
                                            const _64BIT    digest,
                                            BOOL            reset,
                                            BOOL            grantPA);
#endif
static QLIB_STATUS_T QLIB_SEC_GetVaultSize_L(QLIB_CONTEXT_T* qlibContext);

#if !defined EXCLUDE_LMS_ATTESTATION && !defined Q2_API
static QLIB_STATUS_T                             QLIB_SEC_LMS_Attest_Sign_L(QLIB_CONTEXT_T*          qlibContext,
                                                                            const LMS_ATTEST_CHUNK_T msgHash,
                                                                            LMS_ATTEST_OTS_SIG_T     otsSig);
static QLIB_STATUS_T                             QLIB_SEC_LMS_Attest_GetRoot_L(QLIB_CONTEXT_T*           qlibContext,
                                                                               const LMS_ATTEST_KEY_ID_T keyId,
                                                                               U32                       rootIndex,
                                                                               LMS_ATTEST_CHUNK_T        pubCache[],
                                                                               U32                       pubCacheLen,
                                                                               LMS_ATTEST_CHUNK_T        root,
                                                                               BOOL                      cacheRO);

static QLIB_STATUS_T QLIB_SEC_LMS_Attest_GetLeaf_L(QLIB_CONTEXT_T*           qlibContext,
                                                   const LMS_ATTEST_KEY_ID_T keyId,
                                                   U32                       leafIndex,
                                                   LMS_ATTEST_CHUNK_T        leafHash);
static QLIB_STATUS_T QLIB_SEC_LMS_Attest_GetLeafPublicKey_L(QLIB_CONTEXT_T*    qlibContext,
                                                            U32                leafNum,
                                                            LMS_ATTEST_CHUNK_T otsPubKey);
#endif
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                          INTERFACE FUNCTIONS                                            */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

QLIB_STATUS_T QLIB_SEC_InitLib(QLIB_CONTEXT_T* qlibContext)
{
    U32 die;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Configure the globals                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    qlibContext->isSuspended = FALSE;
    for (die = 0; die < QLIB_NUM_OF_DIES; die++)
    {
        qlibContext->dieState[die].isPoweredDown = FALSE;
        qlibContext->dieState[die].mcInSync      = FALSE;
        // Set the cached SSR busy bit in order to mark it as invalid
        SET_VAR_FIELD_32(qlibContext->dieState[die].ssr.asUint, QLIB_REG_SSR__BUSY, 1u);
#ifdef Q3_TEST_MODE
        // chip begins as in non test-mode.
        qlibContext->dieState[die].isInTestMode = FALSE;
#endif
    }
    qlibContext->multiTransactionCmd = FALSE;
    qlibContext->watchdogIsSecure    = FALSE;
    qlibContext->watchdogSectionId   = QLIB_NUM_OF_SECTIONS;
    qlibContext->ctagMode            = 0;

    for (die = 0; die < QLIB_NUM_OF_DIES; die++)
    {
        /*-----------------------------------------------------------------------------------------------------*/
        /* Init the key manager module                                                                         */
        /*-----------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_KEYMNGR_Init(&qlibContext->dieState[die].keyMngr));
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_SyncState(QLIB_CONTEXT_T* qlibContext)
{
    U8 die;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Sync after reset                                                                                    */
    /*-----------------------------------------------------------------------------------------------------*/

    QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncAfterFlashReset(qlibContext));

    /*-----------------------------------------------------------------------------------------------------*/
    /* read WID on reset once                                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetWID_L(qlibContext, qlibContext->wid));

    /*-----------------------------------------------------------------------------------------------------*/
    /* read standard address size                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetStdAddrSize_L(qlibContext));

    /*-----------------------------------------------------------------------------------------------------*/
    /* read Sections sizes                                                                                 */
    /*-----------------------------------------------------------------------------------------------------*/
    for (die = 0; die < QLIB_NUM_OF_DIES; die++)
    {
#if QLIB_NUM_OF_DIES > 1
        QLIB_STATUS_RET_CHECK(QLIB_STD_SetActiveDie(qlibContext, die, FALSE));
#endif
        QLIB_STATUS_RET_CHECK(QLIB_SEC_GetSectionsSize_L(qlibContext));
        if (W77Q_VAULT(qlibContext) != 0u)
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_GetVaultSize_L(qlibContext));
        }
    }
#if QLIB_NUM_OF_DIES > 1
    QLIB_STATUS_RET_CHECK(QLIB_STD_SetActiveDie(qlibContext, QLIB_INIT_DIE_ID, FALSE));
#endif
    /*-----------------------------------------------------------------------------------------------------*/
    /* Get watchdog configuration                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetWatchdogConfig_L(qlibContext));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_Format(QLIB_CONTEXT_T* qlibContext, const KEY_T deviceMasterKey, BOOL eraseDataOnly, BOOL factoryDefault)
{
#if QLIB_NUM_OF_DIES > 1
    U32 die;
    for (die = QLIB_NUM_OF_DIES; die--;)
    {
        QLIB_STATUS_RET_CHECK(QLIB_SetActiveDie(qlibContext, die));
        QLIB_STATUS_RET_CHECK(QLIB_SEC_FormatActiveDie_L(qlibContext,
                                                         deviceMasterKey,
                                                         eraseDataOnly,
                                                         (die > 0) || (eraseDataOnly == TRUE) ? FALSE : TRUE,
                                                         factoryDefault));
    }
#else
    QLIB_STATUS_RET_CHECK(QLIB_SEC_FormatActiveDie_L(qlibContext,
                                                     deviceMasterKey,
                                                     eraseDataOnly,
                                                     eraseDataOnly == TRUE ? FALSE : TRUE,
                                                     factoryDefault));
#endif
    return QLIB_STATUS__OK;
}

static QLIB_STATUS_T QLIB_SEC_FormatActiveDie_L(QLIB_CONTEXT_T* qlibContext,
                                                const KEY_T     deviceMasterKey,
                                                BOOL            eraseDataOnly,
                                                BOOL            reset,
                                                BOOL            factoryDefault)
{
    QLIB_STATUS_T ret     = QLIB_STATUS__COMMAND_FAIL;
    BOOL          hwReset = ((reset == TRUE) && (W77Q_FORMAT_MODE(qlibContext) != 0u)) ? TRUE : FALSE;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET((FALSE == factoryDefault) || (1u == W77Q_FORMAT_MODE(qlibContext)), QLIB_STATUS__NOT_SUPPORTED);
    QLIB_ASSERT_RET((FALSE == eraseDataOnly) || (FALSE == factoryDefault), QLIB_STATUS__INVALID_PARAMETER);

    if (NULL == deviceMasterKey)
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Perform non-secure full device format                                                           */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ASSERT_RET(FALSE == eraseDataOnly, QLIB_STATUS__INVALID_PARAMETER);
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__FORMAT(qlibContext, hwReset, factoryDefault));
    }
    else
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Perform secure full device format                                                               */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ASSERT_RET(QLIB_KEY_MNGR__IS_KEY_VALID(deviceMasterKey), QLIB_STATUS__INVALID_PARAMETER);
        QLIB_STATUS_RET_CHECK(
            QLIB_SEC_OpenSessionInternal_L(qlibContext, (QLIB_KID_T)QLIB_KID__DEVICE_MASTER, deviceMasterKey, FALSE));
        if (TRUE == eraseDataOnly)
        {
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__SERASE(qlibContext, QLIB_ERASE_CHIP, 0), ret, error_session);
        }
        else
        {
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__SFORMAT(qlibContext, hwReset, factoryDefault, FALSE), ret, error_session);
        }
        if (hwReset == TRUE)
        {
            QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);
        }
        else
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));
        }
    }

    if (FALSE == eraseDataOnly)
    {
        U32 sectionID;
        for (sectionID = 0; sectionID < QLIB_NUM_OF_SECTIONS; ++sectionID)
        {
            QLIB_KEYMNGR_RemoveKey(&QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr, sectionID, FALSE);
            QLIB_KEYMNGR_RemoveKey(&QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr, sectionID, TRUE);
        }

        if (reset == TRUE)
        {
            if (W77Q_FORMAT_MODE(qlibContext) == 0u)
            {
                // perform SW reset if HW reset with mode bit is not supported, and sync state
                QLIB_BUS_MODE_T origBusMode = qlibContext->busInterface.secureCmdsFormat;
                if ((origBusMode == QLIB_BUS_MODE_1_2_2 || origBusMode == QLIB_BUS_MODE_1_4_4) &&
                    (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u))
                {
                    /*-----------------------------------------------------------------------------------------*/
                    /* after format ctag mode is set to 0 in the GMC DEVCFG register. The new ctag will        */
                    /* be active only after device reset. So to keep qlib context in sync with flash CTAG mode,*/
                    /* secure interface is set to bus format which is not affected by CTAG configuration       */
                    /*-----------------------------------------------------------------------------------------*/
                    QLIB_STATUS_RET_CHECK(
                        QLIB_SEC_SetInterface(qlibContext, QLIB_BUS_FORMAT(QLIB_BUS_MODE_1_1_1, qlibContext->busInterface.dtr)));
                }

                /*---------------------------------------------------------------------------------------------*/
                /* Reset flash and sync context                                                                */
                /*---------------------------------------------------------------------------------------------*/
                QLIB_STATUS_RET_CHECK(QLIB_ResetFlash(qlibContext));

                /*---------------------------------------------------------------------------------------------*/
                /* Set back to original bus format                                                             */
                /*---------------------------------------------------------------------------------------------*/
                if ((origBusMode == QLIB_BUS_MODE_1_2_2 || origBusMode == QLIB_BUS_MODE_1_4_4) &&
                    (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u))
                {
                    QLIB_STATUS_RET_CHECK(
                        QLIB_SEC_SetInterface(qlibContext, QLIB_BUS_FORMAT(origBusMode, qlibContext->busInterface.dtr)));
                }
            }

            // sync state
            if (factoryDefault == FALSE)
            {
                uint_fast8_t die;
                qlibContext->activeDie = 0; //after sw reset the active die is 0
                for (die = 0; die < QLIB_NUM_OF_DIES; die++)
                {
                    if (W77Q_VAULT(qlibContext) != 0u)
                    {
                        qlibContext->dieState[die].vaultSize = QLIB_VAULT_128KB_RPMC_DISABLED;
                    }
                    (void)memset(qlibContext->dieState[die].sectionsState, 0, sizeof(qlibContext->dieState[die].sectionsState));
                }
                if (W77Q_FORMAT_MODE(qlibContext) != 0u)
                {
                    // was already performed by SW reset function if mode is not supported
                    QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncAfterFlashReset(qlibContext));
                }
            }
            else
            {
                // also sync context with the new configuration
                QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncState(qlibContext));
            }
        }
    }

    ret = QLIB_STATUS__OK;

    goto exit;

error_session:
    (void)QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE);

exit:
    return ret;
}

void QLIB_SEC_configOPS(QLIB_CONTEXT_T* qlibContext)
{
    QLIB_INTERFACE_T* busInterface_p = &(qlibContext->busInterface);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Build OP codes                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    if (Q2_OP0_OP2_DTR_FEATURE(qlibContext) != 0u)
    {
        busInterface_p->op0 =
            (U8)W77Q_SEC_INST__MAKE((U32)W77Q_SEC_INST__OP0, busInterface_p->secureCmdsFormat, (U32)busInterface_p->dtr);
        busInterface_p->op1 = (U8)W77Q_SEC_INST__MAKE((U32)W77Q_SEC_INST__OP1, busInterface_p->secureCmdsFormat, 0u);
        busInterface_p->op2 =
            (U8)W77Q_SEC_INST__MAKE((U32)W77Q_SEC_INST__OP2, busInterface_p->secureCmdsFormat, (U32)busInterface_p->dtr);
    }
    else
    {
        busInterface_p->op0 = (U8)W77Q_SEC_INST__MAKE((U32)W77Q_SEC_INST__OP0, busInterface_p->secureCmdsFormat, 0u);
        busInterface_p->op1 = (U8)W77Q_SEC_INST__MAKE((U32)W77Q_SEC_INST__OP1, busInterface_p->secureCmdsFormat, 0u);
        busInterface_p->op2 = (U8)W77Q_SEC_INST__MAKE((U32)W77Q_SEC_INST__OP2, busInterface_p->secureCmdsFormat, 0u);
    }
}

QLIB_STATUS_T QLIB_SEC_GetNotifications(QLIB_CONTEXT_T* qlibContext, QLIB_NOTIFICATIONS_T* notifs)
{
    (void)memset(notifs, 0, sizeof(QLIB_NOTIFICATIONS_T));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if Monotonic Counter maintenance is needed                                                    */
    /*-----------------------------------------------------------------------------------------------------*/

    /*-----------------------------------------------------------------------------------------------------*/
    /* GET_SSR command is ignored if power is down                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(qlibContext->dieState[qlibContext->activeDie].isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* SSR is not valid while busy, if busy, update the cached SSR                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    if (1u == READ_VAR_FIELD(qlibContext->dieState[qlibContext->activeDie].ssr.asUint, QLIB_REG_SSR__BUSY))
    {
        QLIB_STATUS_RET_CHECK(
            QLIB_SEC__get_SSR(qlibContext, &qlibContext->dieState[qlibContext->activeDie].ssr, SSR_MASK__ALL_ERRORS));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* check from the last status                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    if (0u != READ_VAR_FIELD(qlibContext->dieState[qlibContext->activeDie].ssr.asUint, QLIB_REG_SSR__MC_MAINT))
    {
        notifs->mcMaintenance = 1;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if device replacement is needed since DMC is close to its maximal value                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__synch_MC(qlibContext));
    if (qlibContext->dieState[qlibContext->activeDie].mc[DMC] >= (U32)QLIB_SEC_DMC_EOL_THRESHOLD)
    {
        notifs->replaceDevice = 1;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if device reset is needed since TC is close to its maximal value                              */
    /*-----------------------------------------------------------------------------------------------------*/
    if (qlibContext->dieState[qlibContext->activeDie].mc[TC] >= QLIB_SEC_TC_RESET_THRESHOLD)
    {
        notifs->resetDevice = 1;
    }
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_PerformMCMaint(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__MC_MAINT(qlibContext));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_ConfigDevice(QLIB_CONTEXT_T*                   qlibContext,
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
    U8            sectionIndex = 0;
    QLIB_STATUS_T ret          = QLIB_STATUS__COMMAND_FAIL;
    _128BIT       suid_test;
    BOOL          resetRequired = FALSE;
    U8            die;
    BOOL          configSectionPolicyAfterSize[QLIB_NUM_OF_DIES][QLIB_NUM_OF_SECTIONS];

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    (void)memset(configSectionPolicyAfterSize, 0, sizeof(configSectionPolicyAfterSize));

    if (deviceConf != NULL)
    {
        QLIB_ASSERT_RET((Q2_4_BYTES_ADDRESS_MODE(qlibContext) != 0u) ||
                            (deviceConf->stdAddrSize.addrMode != QLIB_STD_ADDR_MODE__4_BYTE),
                        QLIB_STATUS__NOT_SUPPORTED);
        if (Q2_4_BYTES_ADDRESS_MODE(qlibContext) != 0u)
        {
            /*---------------------------------------------------------------------------------------------*/
            /* Set power-up standard address mode. This command is executed by chip for all dies           */
            /*---------------------------------------------------------------------------------------------*/
            QLIB_STATUS_RET_CHECK(QLIB_STD_SetPowerUpAddressMode(qlibContext, deviceConf->stdAddrSize.addrMode));
            if (qlibContext->addrMode != deviceConf->stdAddrSize.addrMode)
            {
                resetRequired = TRUE;
            }
        }

        if (W77Q_FAST_READ_DUMMY_CONFIG(qlibContext) != 0u)
        {
            QLIB_ASSERT_RET((deviceConf->fastReadDummyCycles > 0u) && (deviceConf->fastReadDummyCycles <= 30u),
                            QLIB_STATUS__INVALID_PARAMETER);
            /************************************************************************************************
             * Set power-up dummy cycles
            ************************************************************************************************/
            QLIB_STATUS_RET_CHECK(QLIB_STD_SetDefaultFastReadDummyCycles(qlibContext, deviceConf->fastReadDummyCycles));
            if (qlibContext->fastReadDummy != deviceConf->fastReadDummyCycles)
            {
                resetRequired = TRUE;
            }
        }
    }

    for (die = 0; die < QLIB_NUM_OF_DIES; die++)
    {
#if QLIB_NUM_OF_DIES > 1
        QLIB_STATUS_RET_CHECK(QLIB_SetActiveDie(qlibContext, die));
#endif
        /*-------------------------------------------------------------------------------------------------*/
        /* Write all keys                                                                                  */
        /*-------------------------------------------------------------------------------------------------*/
        if (deviceMasterKey != NULL)
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_setAllKeys_L(qlibContext,
                                                        deviceMasterKey,
                                                        deviceSecretKey,
                                                        restrictedKeys == NULL ? NULL : restrictedKeys[die],
                                                        fullAccessKeys == NULL ? NULL : fullAccessKeys[die],
                                                        lmsKeys == NULL ? NULL : lmsKeys[die],
                                                        preProvisionedMasterKey));
        }


        /*-----------------------------------------------------------------------------------------------------*/
        /* Set Secure User ID                                                                                  */
        /*-----------------------------------------------------------------------------------------------------*/
        if (suid != NULL)
        {
            _128BIT suidTest;

            // Check if already programmed
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC__get_SUID(qlibContext, suidTest), ret, error_session);

            if (0 != memcmp(suid, suidTest, sizeof(_128BIT)))
            {
                QLIB_STATUS_RET_CHECK(
                    QLIB_SEC_OpenSessionInternal_L(qlibContext, (QLIB_KID_T)QLIB_KID__DEVICE_MASTER, deviceMasterKey, FALSE));
                QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__set_SUID(qlibContext, suid), ret, error_session);
                QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));
                QLIB_STATUS_RET_CHECK(QLIB_SEC__get_SUID(qlibContext, suid_test));
                QLIB_ASSERT_RET(0 == memcmp(suid, suid_test, sizeof(_128BIT)), QLIB_STATUS__COMMAND_FAIL);
            }
        }

        /*-----------------------------------------------------------------------------------------------------*/
        /* configure Global Configuration Register (GMC)                                                       */
        /*-----------------------------------------------------------------------------------------------------*/
        if (Q2_BYPASS_HW_ISSUE_49(qlibContext) != 0u)
        {
            if ((deviceConf != NULL) && (deviceConf->safeFB == TRUE) &&
                (qlibContext->dieState[die].sectionsState[W77Q_BOOT_SECTION_FALLBACK].enabled == 1u) && (sectionTable == NULL))
            {
                QLIB_POLICY_T policy;

                (void)memset(&policy, 0, sizeof(QLIB_POLICY_T));
                QLIB_STATUS_RET_CHECK(QLIB_SEC_GetSectionConfiguration(qlibContext,
                                                                       W77Q_BOOT_SECTION_FALLBACK,
                                                                       NULL,
                                                                       NULL,
                                                                       &policy,
                                                                       NULL,
                                                                       NULL,
                                                                       NULL));
                QLIB_ASSERT_RET(policy.checksumIntegrity == 0u || policy.rollbackProt == 0u, QLIB_STATUS__INVALID_PARAMETER);
            }
        }
        if ((deviceConf != NULL) || (watchdogDefault != NULL && die == QLIB_INIT_DIE_ID))
        {
            BOOL gmcChanged;

            if (deviceConf != NULL && sectionTable == NULL)
            {
                QLIB_STATUS_RET_CHECK(QLIB_SEC_VerifyAddressSizeConfig_L(qlibContext, &deviceConf->stdAddrSize));
            }
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC_configGMC_L(qlibContext,
                                                            deviceMasterKey,
                                                            die == QLIB_INIT_DIE_ID ? watchdogDefault : NULL,
                                                            deviceConf,
                                                            &gmcChanged),
                                       ret,
                                       error_config_size);
            if (gmcChanged == TRUE)
            {
                resetRequired = TRUE;
            }

            if ((W77Q_VAULT(qlibContext) != 0u) && (deviceConf != NULL) &&
                ((sectionTable == NULL) || (sectionTable[die][QLIB_SECTION_ID_VAULT].size == 0u)))
            {
                // if vault section is configured, we will update context later (we still need the active
                // vault size before new value is loaded)
                QLIB_ACTIVE_DIE_STATE(qlibContext).vaultSize = deviceConf->vaultSize[die];
            }
        }

        /*-----------------------------------------------------------------------------------------------------*/
        /* Set Section Configuration Registers (SCRn) for sections that need to be configured prior to GMT/GMC */
        /*-----------------------------------------------------------------------------------------------------*/
        if (sectionTable != NULL)
        {
            for (sectionIndex = 0;
                 sectionIndex < ((W77Q_VAULT(qlibContext) != 0u) ? QLIB_NUM_OF_SECTIONS : QLIB_NUM_OF_MAIN_SECTIONS);
                 sectionIndex++)
            {
                if (sectionTable[die][sectionIndex].size != 0u)
                {
                    configSectionPolicyAfterSize[die][sectionIndex] =
                        QLIB_SEC_ConfigSectionPolicyAfterSize_L(qlibContext, sectionIndex, &sectionTable[die][sectionIndex]);

                    // set size on context before it is set in HW so section configuration checks will test new size
                    if (QLIB_SECTION_ID_VAULT == sectionIndex)
                    {
                        if (deviceConf != NULL)
                        {
                            QLIB_ACTIVE_DIE_STATE(qlibContext).vaultSize = deviceConf->vaultSize[die];
                        }
                    }
                    else
                    {
                        qlibContext->dieState[die].sectionsState[sectionIndex].sizeTag =
                            (U8)QLIB_REG_SMRn__LEN_IN_BYTES_TO_TAG(qlibContext, sectionTable[die][sectionIndex].size);
                        qlibContext->dieState[die].sectionsState[sectionIndex].scale =
                            QLIB_REG_SMRn__LEN_IN_BYTES_TO_SCALE(sectionTable[die][sectionIndex].size);
                        qlibContext->dieState[die].sectionsState[sectionIndex].enabled = 1u;
                    }
                    if (configSectionPolicyAfterSize[die][sectionIndex] == FALSE)
                    {
                        // set policy without CRC & digest since section size is not set yet
                        QLIB_POLICY_T initialPolicy           = sectionTable[die][sectionIndex].policy;
                        initialPolicy.checksumIntegrity       = 0;
                        initialPolicy.digestIntegrity         = 0;
                        initialPolicy.digestIntegrityOnAccess = 0;
                        QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC_ConfigInitialSection_L(qlibContext,
                                                                                   (U32)sectionIndex,
                                                                                   &initialPolicy,
                                                                                   0,
                                                                                   0,
                                                                                   fullAccessKeys[die][sectionIndex]),
                                                   ret,
                                                   error_config_size);
                    }
                }
            }
        }

        /*-----------------------------------------------------------------------------------------------------*/
        /* configure Global Mapping Table Register (GMT)                                                       */
        /*-----------------------------------------------------------------------------------------------------*/
        if (sectionTable != NULL)
        {
            BOOL gmtChange = FALSE;
            QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC_configGMT_L(qlibContext, deviceMasterKey, sectionTable[die], &gmtChange),
                                       ret,
                                       error_config_size);
            if (gmtChange == TRUE)
            {
                resetRequired = TRUE;
            }
            QLIB_STATUS_RET_CHECK(QLIB_SEC_GetSectionsSize_L(qlibContext));
        }
    }
    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform reset                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    if (resetRequired == TRUE)
    {
        QLIB_STATUS_RET_CHECK(QLIB_ResetFlash(qlibContext));
    }


    /*-----------------------------------------------------------------------------------------------------*/
    /* Configure Reset Response                                                                            */
    /*-----------------------------------------------------------------------------------------------------*/
    if (W77Q_RST_RESP(qlibContext) != 0u)
    {
        if (deviceConf != NULL)
        {
            QLIB_RESET_RESPONSE_T resetResp_test = {0};

            if (0 != memcmp((const U8*)(&deviceConf->resetResp), (const U8*)(&resetResp_test), sizeof(QLIB_RESET_RESPONSE_T)))
            {
                // Reset response should be set if non zero
                QLIB_STATUS_RET_CHECK(
                    QLIB_SEC_OpenSessionInternal_L(qlibContext, (QLIB_KID_T)QLIB_KID__DEVICE_MASTER, deviceMasterKey, FALSE));
                QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__set_RST_RESP(qlibContext, TRUE, deviceConf->resetResp.response1),
                                           ret,
                                           error_session);
                QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__set_RST_RESP(qlibContext, FALSE, deviceConf->resetResp.response2),
                                           ret,
                                           error_session);
                QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

                QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_RST_RESP(qlibContext, resetResp_test.response1));
                QLIB_ASSERT_RET(0 == memcmp(deviceConf->resetResp.response1, resetResp_test.response1, sizeof(_512BIT)),
                                QLIB_STATUS__COMMAND_FAIL);
                QLIB_ASSERT_RET(0 == memcmp(deviceConf->resetResp.response2, resetResp_test.response2, sizeof(_512BIT)),
                                QLIB_STATUS__COMMAND_FAIL);
            }
        }
    }
    else
    {
        QLIB_RESET_RESPONSE_T disabledResetResp = {0};
        if (deviceConf != NULL)
        {
            QLIB_ASSERT_RET(memcmp((const U8*)(&deviceConf->resetResp),
                                   (const U8*)(&disabledResetResp),
                                   sizeof(QLIB_RESET_RESPONSE_T)) == 0,
                            QLIB_STATUS__NOT_SUPPORTED);
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set Section Configuration Registers (SCRn) for sections that their policy was not configured before */
    /*-----------------------------------------------------------------------------------------------------*/
    if (sectionTable != NULL)
    {
        for (die = 0; die < QLIB_NUM_OF_DIES; die++)
        {
#if QLIB_NUM_OF_DIES > 1
            QLIB_STATUS_RET_CHECK(QLIB_SetActiveDie(qlibContext, die));
#endif
            for (sectionIndex = 0;
                 sectionIndex < ((W77Q_VAULT(qlibContext) != 0u) ? QLIB_NUM_OF_SECTIONS : QLIB_NUM_OF_MAIN_SECTIONS);
                 sectionIndex++)
            {
                if (((sectionTable[die][sectionIndex].size != 0u) &&
                     ((configSectionPolicyAfterSize[die][sectionIndex] == TRUE) ||
                      (sectionTable[die][sectionIndex].policy.checksumIntegrity == 1u) ||
                      ((Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) &&
                       (sectionTable[die][sectionIndex].policy.digestIntegrityOnAccess == 1u)) ||
                      (sectionTable[die][sectionIndex].policy.digestIntegrity == 1u))) ||
                    ((sectionTable[die][sectionIndex].size == 0u) &&
                     QLIB_KEY_MNGR__IS_KEY_VALID(fullAccessKeys[die][sectionIndex]) &&
                     (W77Q_CONFIG_ZERO_SECTION_ALLOWED(qlibContext) != 0u)))
                {
                    QLIB_STATUS_RET_CHECK(QLIB_SEC_ConfigInitialSection_L(qlibContext,
                                                                          (U32)sectionIndex,
                                                                          &sectionTable[die][sectionIndex].policy,
                                                                          sectionTable[die][sectionIndex].crc,
                                                                          sectionTable[die][sectionIndex].digest,
                                                                          fullAccessKeys[die][sectionIndex]));
                }
            }
        }
    }

#if QLIB_NUM_OF_DIES > 1
    QLIB_STATUS_RET_CHECK(QLIB_SetActiveDie(qlibContext, QLIB_INIT_DIE_ID));
#endif
    goto exit;

error_session:
    (void)QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE);
    return ret;

error_config_size:
    (void)QLIB_SEC_GetSectionsSize_L(qlibContext);
    if (W77Q_VAULT(qlibContext) != 0u)
    {
        (void)QLIB_SEC_GetVaultSize_L(qlibContext);
    }
    (void)QLIB_SEC_GetStdAddrSize_L(qlibContext);
    return ret;

exit:
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_GetSectionConfiguration(QLIB_CONTEXT_T* qlibContext,
                                               U32             sectionID,
                                               U32*            baseAddr,
                                               U32*            size,
                                               QLIB_POLICY_T*  policy,
                                               U64*            digest,
                                               U32*            crc,
                                               U32*            version)
{
    SCRn_T  SCRn;
    SSPRn_T SSPRn = 0;
    GMT_T   GMT;
    U32     sectionSize;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);

    sectionSize = QLIB_CALC_SECTION_SIZE(qlibContext, sectionID);

    (void)memset(&GMT, 0, sizeof(GMT));

    /****************************************************************************************************
         * If flash is in lock state, it means the configuration is missing (flash was formatted)
    ****************************************************************************************************/
    if ((0u == sectionSize) ||
        (READ_VAR_FIELD(QLIB_GET_LAST_SEC_STATUS_FIELD(qlibContext), QLIB_REG_SSR__STATE) == QLIB_REG_SSR__STATE_LOCKED))
    {
        if (NULL != baseAddr)
        {
            *baseAddr = (QLIB_SECTION_ID_VAULT == sectionID) ? MAX_U32 : 0u;
        }
        if (NULL != size)
        {
            *size = sectionSize;
        }
        if (NULL != policy)
        {
            (void)memset(policy, 0, sizeof(QLIB_POLICY_T));
        }
        if (NULL != version)
        {
            *version = 0;
        }
        if (NULL != crc)
        {
            *crc = 0;
        }
        if (NULL != digest)
        {
            *digest = 0;
        }
        return QLIB_STATUS__OK;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read the SCR                                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_SCRn(qlibContext, sectionID, SCRn));

    if (NULL != version)
    {
        *version = QLIB_REG_SCRn_GET_VER(SCRn);
    }

    if (NULL != crc)
    {
        *crc = QLIB_REG_SCRn_GET_CHECKSUM(SCRn);
    }

    if (NULL != digest)
    {
        *digest = QLIB_REG_SCRn_GET_DIGEST(SCRn);
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Retrieve the section configurations (policy)                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    if (NULL != policy)
    {
        SSPRn = QLIB_REG_SCRn_GET_SSPRn(SCRn);

        (void)memset(policy, 0, sizeof(QLIB_POLICY_T));
        policy->digestIntegrity        = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__AUTH_CFG);
        policy->checksumIntegrity      = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__INTEGRITY_AC);
        policy->writeProt              = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__WP_EN);
        policy->rollbackProt           = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__ROLLBACK_EN);
        policy->plainAccessReadEnable  = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__PA_RD_EN);
        policy->plainAccessWriteEnable = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__PA_WR_EN);
        policy->authPlainAccess        = (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__AUTH_PA);
        policy->digestIntegrityOnAccess =
            (Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) ? (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__AUTH_AC) : 0u;
        policy->slog = (W77Q_SECURE_LOG(qlibContext) != 0u ? (U8)READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__SLOG) : 0u);
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Retrieve the section base address and size                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    if (NULL != baseAddr)
    {
        if (QLIB_SECTION_ID_VAULT == sectionID)
        {
            *baseAddr = MAX_U32;
        }
        else
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMT(qlibContext, &GMT));
            *baseAddr = QLIB_REG_SMRn__BASE_IN_TAG_TO_BYTES(QLIB_REG_GMT_GET_BASE(qlibContext, GMT, sectionID));
        }
    }
    if (NULL != size)
    {
        *size = sectionSize;
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_ConfigSection(QLIB_CONTEXT_T*            qlibContext,
                                     U32                        sectionID,
                                     const QLIB_POLICY_T*       policy,
                                     const U64*                 digest,
                                     const U32*                 crc,
                                     const U32*                 newVersion,
                                     BOOL                       swap,
                                     QLIB_SECTION_CONF_ACTION_T action)
{
    SCRn_T        SCRn;
    SCRn_T        SCRn_test;
    SSPRn_T       SSPRn       = 0;
    U32           ver         = 0;
    BOOL          reload      = FALSE;
    U32           numCommands = 0;
    U32           numRetries  = (Q3_BYPASS_HW_ISSUE_SET_CMD_FAIL(qlibContext) == 1u ? SET_CMD_HW_BYPASS_NUM_RETRIES : 1u);
    QLIB_STATUS_T ret;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(sectionID < QLIB_NUM_OF_SECTIONS, QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
    QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID), QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
    if (NULL != policy)
    {
        QLIB_ASSERT_RET(!(QLIB_SECTION_ID_VAULT == sectionID &&
                          (1u == policy->plainAccessReadEnable || 1u == policy->plainAccessWriteEnable ||
                           1u == policy->authPlainAccess)),
                        QLIB_STATUS__INVALID_PARAMETER);

#ifndef Q2_API
        QLIB_ASSERT_RET((W77Q_SECURE_LOG(qlibContext) != 0u) || (policy->slog == 0u), QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET(!(1u == policy->slog &&
                          (1u == policy->rollbackProt || 1u == policy->writeProt || 1u == policy->digestIntegrityOnAccess ||
                           1u == policy->checksumIntegrity || 1u == policy->digestIntegrity)),
                        QLIB_STATUS__INVALID_PARAMETER);
        QLIB_ASSERT_RET((Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) || (policy->digestIntegrityOnAccess == 0u),
                        QLIB_STATUS__INVALID_PARAMETER);
#endif

        // make sure all plain sections are accessible with plain access
        QLIB_ASSERT_RET((policy->plainAccessReadEnable == 0u && policy->plainAccessWriteEnable == 0u) ||
                            (QLIB_CALC_SECTION_SIZE(qlibContext, sectionID) <= _QLIB_MAX_LEGACY_OFFSET(qlibContext)),
                        QLIB_STATUS__INVALID_PARAMETER);
        if (Q2_BYPASS_HW_ISSUE_49(qlibContext) != 0u)
        {
            if (policy->checksumIntegrity == 1u && policy->rollbackProt == 1u && sectionID == (U8)W77Q_BOOT_SECTION_FALLBACK)
            {
                GMC_T    GMC;
                DEVCFG_T DEVCFG = 0;
                QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC));
                DEVCFG = QLIB_REG_GMC_GET_DEVCFG(GMC);
                QLIB_ASSERT_RET(READ_VAR_FIELD(DEVCFG, QLIB_REG_DEVCFG__FB_EN) == 0u, QLIB_STATUS__INVALID_PARAMETER);
            }
        }

        // Make sure that rollback Protected section have at least 2 blocks
        if ((W77Q_VAULT(qlibContext) != 0u) && (sectionID == QLIB_SECTION_ID_VAULT))
        {
            if (policy->rollbackProt == 1u)
            {
                // Make sure that rollback Protected section have at least 2 blocks
                QLIB_ASSERT_RET(QLIB_VAULT_128KB_RPMC_DISABLED == QLIB_ACTIVE_DIE_STATE(qlibContext).vaultSize,
                                QLIB_STATUS__INVALID_PARAMETER);
            }
        }
        else
        {
            // section 0..7
            QLIB_ASSERT_RET(sectionID < QLIB_NUM_OF_MAIN_SECTIONS, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
            if ((policy->rollbackProt != 0u) || ((W77Q_SECURE_LOG(qlibContext) != 0u) && (policy->slog != 0u)))
            {
                U8 sizeTag = QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].sizeTag;

                if (W77Q_SEC_SIZE_SCALE(qlibContext) != 0u)
                {
                    QLIB_ASSERT_RET((sizeTag & (sizeTag + 1u)) == 0u, QLIB_STATUS__INVALID_PARAMETER);
                }
                if (policy->rollbackProt != 0u)
                {
                    // value is at least 2 blocks
                    QLIB_ASSERT_RET(0u < sizeTag, QLIB_STATUS__INVALID_PARAMETER);
                }
            }
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Build the new SCR value                                                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_SCRn_UNSIGNED(qlibContext, sectionID, SCRn));

    ver = QLIB_REG_SCRn_GET_VER(SCRn);
    if (NULL != newVersion)
    {
        QLIB_REG_SCRn_SET_VER(SCRn, *newVersion);
    }
    else if (0xFFFFFFFFu == ver)
    {
        QLIB_REG_SCRn_SET_VER(SCRn, 0);
    }
    else
    {
        // Lint fix
    }

    if (NULL != crc)
    {
        QLIB_REG_SCRn_SET_CHECKSUM(SCRn, *crc);
    }

    if (NULL != digest)
    {
        QLIB_REG_SCRn_SET_DIGEST(SCRn, *digest);
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set the section configurations (policy)                                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    if (NULL != policy)
    {
        SSPRn = 0;
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__AUTH_CFG, policy->digestIntegrity);
        SET_VAR_FIELD_32(SSPRn,
                         QLIB_REG_SSPRn__AUTH_AC,
                         (Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) ? policy->digestIntegrityOnAccess : 0u);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__INTEGRITY_AC, policy->checksumIntegrity);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__WP_EN, policy->writeProt);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__ROLLBACK_EN, policy->rollbackProt);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__PA_RD_EN, policy->plainAccessReadEnable);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__PA_WR_EN, policy->plainAccessWriteEnable);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__AUTH_PA, policy->authPlainAccess);
        SET_VAR_FIELD_32(SSPRn, QLIB_REG_SSPRn__SLOG, W77Q_SECURE_LOG(qlibContext) != 0u ? policy->slog : 0u);
        QLIB_REG_SCRn_SET_SSPRn(SCRn, SSPRn);
    }
    else
    {
        SSPRn = QLIB_REG_SCRn_GET_SSPRn(SCRn);
    }

    if ((action == QLIB_SECTION_CONF_ACTION__RELOAD) &&
        ((W77Q_SET_SCR_MODE(qlibContext) != 0u) ||
         (((READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__PA_RD_EN) == 1u) || (READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__PA_WR_EN)) == 1u) &&
          !(READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__AUTH_PA) == 1u) && (sectionID < QLIB_SECTION_ID_VAULT) &&
          (QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled != QLIB_SECTION_PLAIN_EN_NO))))
    {
        reload = TRUE;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform (SCRn) write                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    do
    {
        if (swap == FALSE)
        {
            ret = QLIB_CMD_PROC__set_SCRn(qlibContext,
                                          sectionID,
                                          SCRn,
                                          action == QLIB_SECTION_CONF_ACTION__RESET ? TRUE : FALSE,
                                          reload);
        }
        else
        {
            ret = QLIB_CMD_PROC__set_SCRn_swap(qlibContext,
                                               sectionID,
                                               SCRn,
                                               action == QLIB_SECTION_CONF_ACTION__RESET ? TRUE : FALSE,
                                               reload);
        }
        numCommands++;
        if ((ret == QLIB_STATUS__DEVICE_SYSTEM_ERR) &&
            (READ_VAR_FIELD(QLIB_GET_LAST_SEC_STATUS_FIELD(qlibContext), QLIB_REG_SSR__SES_READY) == 0u))

        {
            U8 kid = QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid;
            QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);
            QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSessionInternal_L(qlibContext, kid, NULL, FALSE));
        }
    } while ((ret == QLIB_STATUS__DEVICE_SYSTEM_ERR) && (numCommands < numRetries));
    QLIB_STATUS_RET_CHECK(ret);

    if (action == QLIB_SECTION_CONF_ACTION__RESET)
    {
        /****************************************************************************************************
         * Sync after flash reset
        ****************************************************************************************************/
        QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncAfterFlashReset(qlibContext));
    }
    else if ((action == QLIB_SECTION_CONF_ACTION__NO) || (W77Q_SET_SCR_MODE(qlibContext) == 0u))
    {
        QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);

        if (sectionID < QLIB_SECTION_ID_VAULT)
        {
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled = QLIB_SECTION_PLAIN_EN_NO;
        }
    }
    else
    {
        // QLIB_SECTION_CONF_ACTION__RELOAD
        if (sectionID < QLIB_SECTION_ID_VAULT)
        {
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled = QLIB_SECTION_PLAIN_EN_NO;
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled |=
                ((READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__PA_RD_EN) == 1u) ? QLIB_SECTION_PLAIN_EN_RD : 0u);
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled |=
                ((READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__PA_WR_EN) == 1u) ? QLIB_SECTION_PLAIN_EN_WR : 0u);
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Confirm operation success                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_SCRn_UNSIGNED(qlibContext, sectionID, SCRn_test));
    QLIB_ASSERT_RET(0 == memcmp(SCRn, SCRn_test, sizeof(SCRn_T)), QLIB_STATUS__COMMAND_FAIL);

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_OpenSession(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_SESSION_ACCESS_T sessionAccess)
{
    BOOL       configOnly = FALSE;
    QLIB_KID_T kid        = (QLIB_KID_T)QLIB_KID__INVALID;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(!QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Define the key description                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    if (QLIB_SESSION_ACCESS_FULL == sessionAccess)
    {
        kid = (QLIB_KID_T)QLIB_KEY_MNGR__KID_WITH_SECTION((U32)QLIB_KID__FULL_ACCESS_SECTION, sectionID);
    }
    else if (QLIB_SESSION_ACCESS_CONFIG_ONLY == sessionAccess)
    {
        kid        = (QLIB_KID_T)QLIB_KEY_MNGR__KID_WITH_SECTION((U32)QLIB_KID__FULL_ACCESS_SECTION, sectionID);
        configOnly = TRUE;
    }
    else if (QLIB_SESSION_ACCESS_RESTRICTED == sessionAccess)
    {
        kid = (U8)QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__RESTRICTED_ACCESS_SECTION, sectionID);
    }
    else
    {
        return QLIB_STATUS__INVALID_PARAMETER;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Open session                                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSessionInternal_L(qlibContext, kid, NULL, configOnly));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_CloseSession(QLIB_CONTEXT_T* qlibContext, U32 sectionID)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID) ||
                        QLIB_KEY_MNGR_IS_SECTION_RESTRICTED_ACCESS(qlibContext, sectionID),
                    QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Close session                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_AuthPlainAccess_Grant(QLIB_CONTEXT_T* qlibContext, U32 sectionID)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    if (W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_HwAuthPlainAccess_Grant_L(qlibContext, sectionID));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_SwGrantRevokePA_L(qlibContext, sectionID, TRUE));
    }
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_PlainAccess_Revoke(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_PA_REVOKE_TYPE_T revokeType)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(qlibContext->dieState[QLIB_INIT_DIE_ID].isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    if (W77Q_CMD_PA_GRANT_REVOKE(qlibContext) != 0u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__PA_revoke(qlibContext, sectionID, revokeType));
    }
    else
    {
        QLIB_ASSERT_RET(revokeType != QLIB_PA_REVOKE_WRITE_ACCESS, QLIB_STATUS__NOT_SUPPORTED);
        QLIB_STATUS_RET_CHECK(QLIB_SEC_SwGrantRevokePA_L(qlibContext, sectionID, FALSE));
    }
    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function perform secure reads data from the flash.
 *              It can generate Secure and Secure + Authenticated reads. A session must be open first
 *
 * @param       qlibContext-   QLIB state object
 * @param       buf            Pointer to output buffer
 * @param       sectionID      Section index
 * @param       offset         Section offset
 * @param       size           Size of read data
 * @param       auth           if TRUE, read operation will be authenticated
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SEC_Read(QLIB_CONTEXT_T* qlibContext, U8* buf, U32 sectionID, U32 offset, U32 size, BOOL auth)
{
    U32           offsetInPage = 0;
    QLIB_STATUS_T ret          = QLIB_STATUS__OK;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != buf, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
    QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID) ||
                        QLIB_KEY_MNGR_IS_SECTION_RESTRICTED_ACCESS(qlibContext, sectionID),
                    QLIB_STATUS__DEVICE_PRIVILEGE_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Mark multi-transaction started                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/

    qlibContext->multiTransactionCmd = TRUE;
#ifdef QLIB_SPI_OPTIMIZATION_ENABLED
    PLAT_SPI_MultiTransactionStart();
#endif //QLIB_SPI_OPTIMIZATION_ENABLED
    offsetInPage = (offset % QLIB_SEC_READ_PAGE_SIZE_BYTE);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if we can use aligned access optimization while flash is busy                                 */
    /*-----------------------------------------------------------------------------------------------------*/
#ifndef QLIB_SUPPORT_XIP
    if ((offsetInPage == 0u) && ((size % QLIB_SEC_READ_PAGE_SIZE_BYTE) == 0u) &&
        ADDRESS_ALIGNED32(buf) //Lint check if address aligned32
#if defined QLIB_SUPPORT_QPI
        && ((qlibContext->busInterface.busMode != QLIB_BUS_MODE_4_4_4) || (Q2_BYPASS_HW_ISSUE_23(qlibContext) == 0u))
#endif
    )
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Access is aligned                                                                               */
        /*-------------------------------------------------------------------------------------------------*/
        if (auth == TRUE)
        {
            ret = QLIB_CMD_PROC__SARD_Multi(qlibContext, offset, (U32*)buf, size);
        }
        else
        {
            ret = QLIB_CMD_PROC__SRD_Multi(qlibContext, offset, (U32*)buf, size);
        }
    }
    else
#endif // QLIB_SUPPORT_XIP
    {
        U32              dataPage[QLIB_SEC_READ_PAGE_SIZE_BYTE / sizeof(U32)];
        QLIB_READ_FUNC_T readFunc = (TRUE == auth) ? QLIB_CMD_PROC__SARD : QLIB_CMD_PROC__SRD;
        U32              iterSize = MIN(size, (QLIB_SEC_READ_PAGE_SIZE_BYTE - offsetInPage));

        offset = offset - offsetInPage;

        while (0u != size)
        {
            /*---------------------------------------------------------------------------------------------*/
            /* One page Read                                                                               */
            /*---------------------------------------------------------------------------------------------*/
            if (QLIB_SEC_READ_PAGE_SIZE_BYTE == iterSize && ADDRESS_ALIGNED32(buf))
            {
                QLIB_STATUS_RET_CHECK_GOTO(readFunc(qlibContext, offset, (U32*)buf), ret, finish);
            }
            else
            {
                QLIB_STATUS_RET_CHECK_GOTO(readFunc(qlibContext, offset, dataPage), ret, finish);
                (void)memcpy(buf, (U8*)(dataPage) + offsetInPage, iterSize);
            }

            /*---------------------------------------------------------------------------------------------*/
            /* Prepare pointers for next iteration                                                         */
            /*---------------------------------------------------------------------------------------------*/
            size         = size - iterSize;
            buf          = buf + iterSize;
            offset       = offset + QLIB_SEC_READ_PAGE_SIZE_BYTE;
            offsetInPage = 0;
            iterSize     = MIN(size, QLIB_SEC_READ_PAGE_SIZE_BYTE);
        }
    }

finish:
    /*-----------------------------------------------------------------------------------------------------*/
    /* Mark multi-transaction ended                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    qlibContext->multiTransactionCmd = FALSE;

#ifdef QLIB_SPI_OPTIMIZATION_ENABLED
    PLAT_SPI_MultiTransactionStop();
#endif //QLIB_SPI_OPTIMIZATION_ENABLED

    return ret;
}

/************************************************************************************************************
 * @brief       This function perform secure write data to the flash.
 *
 * @param       qlibContext   QLIB state object
 * @param       buf           Pointer to input buffer
 * @param       sectionID     Section index
 * @param       offset        Section offset
 * @param       size          Data size
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
QLIB_STATUS_T QLIB_SEC_Write(QLIB_CONTEXT_T* qlibContext, const U8* buf, U32 sectionID, U32 offset, U32 size)
{
    U32           iterSize     = 0;
    U32           offsetInPage = 0;
    U32           pageBuf[QLIB_SEC_WRITE_PAGE_SIZE_BYTE / sizeof(U32)];
    QLIB_STATUS_T ret = QLIB_STATUS__OK;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(NULL != buf, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
    QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID), QLIB_STATUS__DEVICE_PRIVILEGE_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Mark multi-transaction command                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    qlibContext->multiTransactionCmd = TRUE;

#ifdef QLIB_SPI_OPTIMIZATION_ENABLED
    PLAT_SPI_MultiTransactionStart();
#endif //QLIB_SPI_OPTIMIZATION_ENABLED

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set variables                                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    offsetInPage = (offset % QLIB_SEC_WRITE_PAGE_SIZE_BYTE);
    offset       = offset - offsetInPage;
    iterSize     = MIN(size, (QLIB_SEC_WRITE_PAGE_SIZE_BYTE - offsetInPage));

    while (0u != size)
    {
        if (QLIB_SEC_WRITE_PAGE_SIZE_BYTE != iterSize)
        {
            (void)memset(pageBuf, 0xFF, QLIB_SEC_WRITE_PAGE_SIZE_BYTE);
        }

        (void)memcpy((U8*)pageBuf + offsetInPage, buf, iterSize);

        /*-------------------------------------------------------------------------------------------------*/
        /* One page write                                                                                  */
        /* Address must be aligned to 32B (5 LS-bits are *ignored*)                                        */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__SAWR(qlibContext, offset, pageBuf), ret, finish);

        /*-------------------------------------------------------------------------------------------------*/
        /* Prepare pointers for next iteration                                                             */
        /*-------------------------------------------------------------------------------------------------*/
        size         = size - iterSize;
        buf          = buf + iterSize;
        offset       = offset + QLIB_SEC_WRITE_PAGE_SIZE_BYTE;
        offsetInPage = 0;
        iterSize     = MIN(size, QLIB_SEC_WRITE_PAGE_SIZE_BYTE);
    }
finish:
    /*-----------------------------------------------------------------------------------------------------*/
    /* Multi-transaction ended                                                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    if (qlibContext->multiTransactionCmd == 1u)
    {
        qlibContext->multiTransactionCmd = 0u;

#ifdef QLIB_SPI_OPTIMIZATION_ENABLED
        PLAT_SPI_MultiTransactionStop();
#endif //QLIB_SPI_OPTIMIZATION_ENABLED
    }
    return ret;
}

QLIB_STATUS_T QLIB_SEC_Erase(QLIB_CONTEXT_T* qlibContext, U32 sectionID, U32 offset, U32 size)
{
    U32          eraseSize = 0;
    QLIB_ERASE_T eraseType = QLIB_ERASE_FIRST;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(0u == (offset % FLASH_SECTOR_SIZE), QLIB_STATUS__INVALID_DATA_ALIGNMENT);
    QLIB_ASSERT_RET(0u == (size % FLASH_SECTOR_SIZE), QLIB_STATUS__INVALID_DATA_SIZE);
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
    QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID), QLIB_STATUS__DEVICE_PRIVILEGE_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Start erasing with optimal command                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    while (0u < size)
    {
        if (_64KB_ <= size && 0u == (offset % _64KB_))
        {
            eraseSize = _64KB_;
            eraseType = QLIB_ERASE_BLOCK_64K;
        }
        else if (_32KB_ <= size && 0u == (offset % _32KB_))
        {
            eraseSize = _32KB_;
            eraseType = QLIB_ERASE_BLOCK_32K;
        }
        else
        {
            eraseSize = _4KB_;
            eraseType = QLIB_ERASE_SECTOR_4K;
        }

        /*-------------------------------------------------------------------------------------------------*/
        /* Perform the erase                                                                               */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__SERASE(qlibContext, eraseType, offset));

        /*-------------------------------------------------------------------------------------------------*/
        /* Prepare pointers for next iteration                                                             */
        /*-------------------------------------------------------------------------------------------------*/
        offset = offset + eraseSize;
        size   = size - eraseSize;
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_MemCopy(QLIB_CONTEXT_T* qlibContext, U32 dest, U32 src, U32 len, U32 sectionID)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    len  = ROUND_DOWN(len, QLIB_SEC_READ_PAGE_SIZE_BYTE);
    src  = ROUND_DOWN(src, QLIB_SEC_READ_PAGE_SIZE_BYTE);
    dest = ROUND_DOWN(dest, QLIB_SEC_READ_PAGE_SIZE_BYTE);
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
    QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID), QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
    QLIB_ASSERT_RET(dest + len <= src || src + len <= dest,
                    QLIB_STATUS__PARAMETER_OUT_OF_RANGE); // src and dest shall not overlap

    /********************************************************************************************************
     * Perform the copy
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__MEM_COPY(qlibContext, dest, src, len));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_MemCrc(QLIB_CONTEXT_T* qlibContext, U32* crc32, U32 sectionID, U32 offset, U32 size)
{
    U32 mask = 0xff000000u;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    size   = ROUND_DOWN(size, QLIB_SEC_READ_PAGE_SIZE_BYTE);
    offset = ROUND_DOWN(offset, QLIB_SEC_READ_PAGE_SIZE_BYTE);

    QLIB_ASSERT_RET((size & mask) == 0u, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((offset & mask) == 0u, QLIB_STATUS__INVALID_PARAMETER);

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__MEM_CRC(qlibContext, sectionID, offset, size, crc32));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_EraseSection(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL secure)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if plain or secure section erase                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    if (secure == TRUE)
    {
        QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
        QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, sectionID), QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__SERASE(qlibContext, QLIB_ERASE_SECTION, 0));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__ERASE_SECT_PLAIN(qlibContext, sectionID));
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_ConfigAccess(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL readEnable, BOOL writeEnable)
{
    ACLR_T aclr      = 0;
    U32    readMask  = 0;
    U32    writeMask = 0;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(sectionID < QLIB_NUM_OF_SECTIONS, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read ACLR                                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_ACLR(qlibContext, &aclr));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Update section configuration                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    if (sectionID < QLIB_NUM_OF_MAIN_SECTIONS)
    {
        writeMask = (U32)READ_VAR_FIELD(aclr, QLIB_REG_ACLR__WR_LOCK);
        readMask  = (U32)READ_VAR_FIELD(aclr, QLIB_REG_ACLR__RD_LOCK);
        WRITE_VAR_BIT_32(writeMask, sectionID, writeEnable == FALSE);
        WRITE_VAR_BIT_32(readMask, sectionID, readEnable == FALSE);
        SET_VAR_FIELD_32(aclr, QLIB_REG_ACLR__WR_LOCK, writeMask);
        SET_VAR_FIELD_32(aclr, QLIB_REG_ACLR__RD_LOCK, readMask);
    }
    else
    {
        SET_VAR_FIELD_32(aclr, QLIB_REG_ACLR__WR_LOCK_VAULT, (writeEnable == FALSE) ? 1u : 0u);
        SET_VAR_FIELD_32(aclr, QLIB_REG_ACLR__RD_LOCK_VAULT, (readEnable == FALSE) ? 1u : 0u);
    }
    /*-----------------------------------------------------------------------------------------------------*/
    /* Write ACLR                                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__set_ACLR(qlibContext, (U32)(aclr & ~(QLIB_REG_ACLR_RESERVED_MASK))));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_LoadKey(QLIB_CONTEXT_T* qlibContext, U32 sectionID, const KEY_T key, BOOL fullAccess)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__IS_KEY_VALID(key), QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (sectionID != QLIB_SECTION_ID_VAULT), QLIB_STATUS__INVALID_PARAMETER);

    QLIB_KEYMNGR_SetKey(&QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr, key, sectionID, fullAccess);
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_RemoveKey(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL fullAccess)
{
    QLIB_KID_TYPE_T kid_type = fullAccess == TRUE ? QLIB_KID__FULL_ACCESS_SECTION : QLIB_KID__RESTRICTED_ACCESS_SECTION;
    QLIB_KID_T      kid      = (U8)QLIB_KEY_MNGR__KID_WITH_SECTION((U32)kid_type, sectionID);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (sectionID != QLIB_SECTION_ID_VAULT), QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Prevent key removal if session with this key is currently open                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid != kid, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    QLIB_KEYMNGR_RemoveKey(&QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr, sectionID, fullAccess);
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_CheckIntegrity(QLIB_CONTEXT_T* qlibContext, U32 sectionID, QLIB_INTEGRITY_T integrityType)
{
    QLIB_POLICY_T policy;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error checking                                                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_NUM_OF_SECTIONS > sectionID, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((W77Q_VAULT(qlibContext) != 0u) || (QLIB_SECTION_ID_VAULT != sectionID), QLIB_STATUS__INVALID_PARAMETER);

    (void)memset(&policy, 0, sizeof(QLIB_POLICY_T));

    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetSectionConfiguration(qlibContext, sectionID, NULL, NULL, &policy, NULL, NULL, NULL));

    if (QLIB_INTEGRITY_DIGEST == integrityType)
    {
        QLIB_ASSERT_RET((policy.digestIntegrity == 1u) ||
                            ((Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) && (policy.digestIntegrityOnAccess == 1u)),
                        QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
        if (W77Q_VER_INTG_DIGEST(qlibContext) == 0u)
        {
            U64    digest = 0;
            SCRn_T SCRn;

            QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
            // Perform CALC_SIG command for secure integrity check

            QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__CALC_SIG(qlibContext,
                                                          QLIB_SIGNED_DATA_TYPE_SECTION_DIGEST,
                                                          sectionID,
                                                          NULL,
                                                          0,
                                                          &digest,
                                                          sizeof(digest),
                                                          NULL));
            QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__CALC_SIG(qlibContext,
                                                          QLIB_SIGNED_DATA_TYPE_SECTION_CONFIG,
                                                          sectionID,
                                                          NULL,
                                                          0,
                                                          SCRn,
                                                          sizeof(SCRn),
                                                          NULL));

            if (0 != memcmp((U8*)&digest, (U8*)QLIB_REG_SCRn_GET_DIGEST_PTR(SCRn), sizeof(digest)))
            {
                return QLIB_STATUS__SECURITY_ERR;
            }
        }
        else
        {
            QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__Check_Integrity(qlibContext, sectionID, TRUE));
        }
    }
    else if (QLIB_INTEGRITY_CRC == integrityType)
    {
        // Perform VER_INTG for faster (but less secure) check
        QLIB_ASSERT_RET(policy.checksumIntegrity == 1u, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__Check_Integrity(qlibContext, sectionID, FALSE));
    }
    else
    {
        return QLIB_STATUS__INVALID_PARAMETER;
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_CalcCDI(QLIB_CONTEXT_T* qlibContext, _256BIT nextCdi, const _256BIT prevCdi, U32 sectionId)
{
    _512BIT       hashData;
    U8*           hashDataP = (U8*)hashData;
    QLIB_POLICY_T policy;
    U64           digest = 0;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    (void)memset(&policy, 0, sizeof(QLIB_POLICY_T));
    if (sectionId == 0u)
    {
        QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, 0u) ||
                            QLIB_KEY_MNGR_IS_SECTION_RESTRICTED_ACCESS(qlibContext, 0u),
                        QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
        return QLIB_CMD_PROC__CALC_CDI(qlibContext, 0, nextCdi);
    }
    else
    {
        QLIB_ASSERT_RET(NULL != prevCdi, QLIB_STATUS__INVALID_PARAMETER);
        QLIB_STATUS_RET_CHECK(QLIB_SEC_GetSectionConfiguration(qlibContext, sectionId, NULL, NULL, &policy, &digest, NULL, NULL));

        if (((policy.digestIntegrity == 1u) ||
             ((Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) && (policy.digestIntegrityOnAccess == 1u))) &&
            ((policy.writeProt == 1u) || (policy.rollbackProt == 1u)))
        {
            /*---------------------------------------------------------------------------------------------*/
            /* Using stored digest                                                                         */
            /*---------------------------------------------------------------------------------------------*/
            QLIB_ASSERT_RET(digest != 0u, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
        }
        else
        {
            /*---------------------------------------------------------------------------------------------*/
            /* recalculating digest                                                                        */
            /*---------------------------------------------------------------------------------------------*/
            QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__CALC_SIG(qlibContext,
                                                          QLIB_SIGNED_DATA_TYPE_SECTION_DIGEST,
                                                          sectionId,
                                                          NULL,
                                                          0,
                                                          &digest,
                                                          sizeof(digest),
                                                          NULL));
        }

        /*-------------------------------------------------------------------------------------------------*/
        /* data consists of the following                                                                  */
        /* 256 bit  => prevCdi                                                                             */
        /* 64  bit  => digest                                                                              */
        /* 64  bit  => zero bits                                                                           */
        /* 48  bit  => zero bits                                                                           */
        /* 8   bit  => index                                                                               */
        /*-------------------------------------------------------------------------------------------------*/
        (void)memcpy((void*)hashDataP, (const void*)prevCdi, BITS_TO_BYTES(256u));
        hashDataP += BITS_TO_BYTES(256u);

        (void)memcpy((void*)hashDataP, (void*)&digest, BITS_TO_BYTES(64u));
        hashDataP += BITS_TO_BYTES(64u);

        (void)memset(hashDataP, 0, BITS_TO_BYTES(112u));
        hashDataP += BITS_TO_BYTES(112u);

        (void)memcpy((void*)hashDataP, (void*)&sectionId, BITS_TO_BYTES(8u));

        QLIB_STATUS_RET_CHECK(QLIB_HASH(nextCdi, hashData, BITS_TO_BYTES(256u + 64u + 112u + 8u)));
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_Watchdog_ConfigSet(QLIB_CONTEXT_T* qlibContext, const QLIB_WATCHDOG_CONF_T* watchdogCFG)
{
    AWDTCFG_T AWDTCFG      = 0;
    AWDTCFG_T AWDTCFG_test = 0;
    U32       AWDTCFG_KID  = 0;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read AWDTCFG register and check the state                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_AWDTCNFG(qlibContext, &AWDTCFG));

    QLIB_ASSERT_RET(0u == READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__LOCK), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    qlibContext->watchdogIsSecure = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__AUTH_WDT);

    AWDTCFG_KID = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__KID);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Configure the new parameters                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__AWDT_EN, BOOLEAN_TO_INT(watchdogCFG->enable));
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__LFOSC_EN, BOOLEAN_TO_INT(watchdogCFG->lfOscEn));
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__SRST_EN, BOOLEAN_TO_INT(watchdogCFG->swResetEn));
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__AUTH_WDT, BOOLEAN_TO_INT(watchdogCFG->authenticated));
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__KID, watchdogCFG->sectionID);
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__TH, (U32)watchdogCFG->threshold);
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__LOCK, BOOLEAN_TO_INT(watchdogCFG->lock));

    if (0u != watchdogCFG->oscRateHz)
    {
        SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__OSC_RATE_KHZ, watchdogCFG->oscRateHz >> 10u);
        SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__OSC_RATE_FRAC, (watchdogCFG->oscRateHz >> 6u));
    }

    if (Q2_SUPPORT_AWDTCFG_FALLBACK(qlibContext) != 0u)
    {
        QLIB_ASSERT_RET((watchdogCFG->enable == FALSE) || (watchdogCFG->fallbackEn == FALSE) || (watchdogCFG->swResetEn == TRUE),
                        QLIB_STATUS__INVALID_PARAMETER);
    }
    else
    {
        QLIB_ASSERT_RET((watchdogCFG->enable == FALSE) || (watchdogCFG->fallbackEn == FALSE), QLIB_STATUS__NOT_SUPPORTED);
    }
    SET_VAR_FIELD_32(AWDTCFG, QLIB_REG_AWDTCFG__FB_EN, BOOLEAN_TO_INT(watchdogCFG->fallbackEn));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Write the new configurations to the flash                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    AWDTCFG = (U32)(AWDTCFG & (~QLIB_REG_AWDTCFG_RESERVED_MASK));

    if (1u == qlibContext->watchdogIsSecure)
    {
        QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__DEVICE_SESSION_ERR);
        QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS(qlibContext, AWDTCFG_KID), QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__set_AWDT(qlibContext, AWDTCFG));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__set_AWDT_PLAIN(qlibContext, AWDTCFG));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read AWDTCFG register and verify the change                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_AWDTCNFG(qlibContext, &AWDTCFG_test));
    QLIB_ASSERT_RET(AWDTCFG == AWDTCFG_test, QLIB_STATUS__COMMAND_FAIL);
    qlibContext->watchdogIsSecure  = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__AUTH_WDT);
    qlibContext->watchdogSectionId = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__KID);

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_Watchdog_ConfigGet(QLIB_CONTEXT_T* qlibContext, QLIB_WATCHDOG_CONF_T* watchdogCFG)
{
    AWDTCFG_T AWDTCFG = 0;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read AWDTCFG register and check the state                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_AWDTCNFG(qlibContext, &AWDTCFG));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Fill the user struct                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    watchdogCFG->enable        = INT_TO_BOOLEAN(READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__AWDT_EN));
    watchdogCFG->lfOscEn       = INT_TO_BOOLEAN(READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__LFOSC_EN));
    watchdogCFG->swResetEn     = INT_TO_BOOLEAN(READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__SRST_EN));
    watchdogCFG->authenticated = INT_TO_BOOLEAN(READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__AUTH_WDT));
    watchdogCFG->sectionID     = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__KID);
    watchdogCFG->threshold = (QLIB_AWDT_TH_T)MIN((U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__TH), (U32)QLIB_AWDT_TH_12_DAYS);
    watchdogCFG->lock      = INT_TO_BOOLEAN(READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__LOCK));

    watchdogCFG->oscRateHz =
        ((U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__OSC_RATE_KHZ) << 10u) +
        (W77Q_AWDTCFG_OSC_RATE_FRAC(qlibContext) != 0u ? ((U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__OSC_RATE_FRAC) << 6u)
                                                       : 0u);

    watchdogCFG->fallbackEn = (Q2_SUPPORT_AWDTCFG_FALLBACK(qlibContext) != 0u)
                                  ? INT_TO_BOOLEAN(READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__FB_EN))
                                  : FALSE;

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_Watchdog_Touch(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    if (1u == qlibContext->watchdogIsSecure)
    {
        QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN((qlibContext)), QLIB_STATUS__DEVICE_SESSION_ERR);
        QLIB_ASSERT_RET(QLIB_KEYMNGR_IS_SECTION_FULL_ACCESS((qlibContext), qlibContext->watchdogSectionId) ||
                            QLIB_KEY_MNGR_IS_SECTION_RESTRICTED_ACCESS((qlibContext), qlibContext->watchdogSectionId),
                        QLIB_STATUS__DEVICE_PRIVILEGE_ERR);

        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__AWDT_TOUCH(qlibContext));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__AWDT_TOUCH_PLAIN(qlibContext));
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_Watchdog_Trigger(QLIB_CONTEXT_T* qlibContext)
{
    QLIB_WATCHDOG_CONF_T watchdogCFG;
    BOOL                 watchdogResetEnabled;
    QLIB_STATUS_T        ret;
    QLIB_STATUS_T        sync_ret = QLIB_STATUS__OK;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    (void)memset(&watchdogCFG, 0, sizeof(QLIB_WATCHDOG_CONF_T));
    QLIB_STATUS_RET_CHECK(QLIB_SEC_Watchdog_ConfigGet(qlibContext, &watchdogCFG));
    watchdogResetEnabled = ((watchdogCFG.enable == TRUE) && (watchdogCFG.swResetEn == TRUE)) ? TRUE : FALSE;

    ret = QLIB_CMD_PROC__AWDT_expire(qlibContext);

    QLIB_ASSERT_RET(READ_VAR_FIELD(QLIB_GET_LAST_SEC_STATUS_FIELD(qlibContext), QLIB_REG_SSR__AWDT_EXP) == 1u,
                    (ret == QLIB_STATUS__OK ? QLIB_STATUS__COMMAND_IGNORED : ret));

    if (watchdogResetEnabled == TRUE)
    {
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC_SyncAfterFlashReset(qlibContext), sync_ret, sync_err);
    }

sync_err:
    if (ret == QLIB_STATUS__OK)
    {
        return sync_ret;
    }
    return ret;
}

QLIB_STATUS_T QLIB_SEC_Watchdog_Get(QLIB_CONTEXT_T* qlibContext, U32* milliSecondsPassed, BOOL* expired)
{
    AWDTSR_T             AWDTSR = 0;
    U32                  ticksResidue;
    QLIB_WATCHDOG_CONF_T watchdogCFG = {0};

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_AWDTSR(qlibContext, &AWDTSR));

    if (NULL != milliSecondsPassed)
    {
        if (W77Q_AWDT_VAL_SEC_FRACT(qlibContext) != 0u)
        {
            *milliSecondsPassed = (U32)(READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_VAL(qlibContext)) * 250u);
        }
        else
        {
            *milliSecondsPassed = (U32)(READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_VAL(qlibContext)) * 1000u);
        }

        QLIB_STATUS_RET_CHECK(QLIB_SEC_Watchdog_ConfigGet(qlibContext, &watchdogCFG));
        ticksResidue = (U32)READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_RES(qlibContext));
        if (watchdogCFG.oscRateHz != 0u)
        {
            *milliSecondsPassed = *milliSecondsPassed + ((ticksResidue * 64u * 1000u) / watchdogCFG.oscRateHz);
        }
    }

    if (NULL != expired)
    {
        *expired = (1u == READ_VAR_FIELD(AWDTSR, QLIB_REG_AWDTSR__AWDT_EXP_S)) ? TRUE : FALSE;
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_GetWID(QLIB_CONTEXT_T* qlibContext, QLIB_WID_T id)
{
    QLIB_ASSERT_RET(id != NULL, QLIB_STATUS__INVALID_PARAMETER);
    (void)memcpy(id, qlibContext->wid, sizeof(QLIB_WID_T));
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_GetHWVersion(QLIB_CONTEXT_T* qlibContext, QLIB_SEC_HW_VER_T* hwVer)
{
    HW_VER_T hwVerReg;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_HW_VER(qlibContext, &hwVerReg));
    hwVer->flashVersion    = (U8)READ_VAR_FIELD(hwVerReg, QLIB_REG_HW_VER__FLASH_VER);
    hwVer->securityVersion = (U8)READ_VAR_FIELD(hwVerReg, QLIB_REG_HW_VER__SEC_VER);
    hwVer->revision        = (U8)READ_VAR_FIELD(hwVerReg, QLIB_REG_HW_VER__REVISION);
    hwVer->hashVersion     = (U8)READ_VAR_FIELD(hwVerReg, QLIB_REG_HW_VER__HASH_VER);

    if (Q2_BYPASS_HW_ISSUE_263(qlibContext) == 0u)
    {
        hwVer->flashSize = (U8)READ_VAR_FIELD(hwVerReg, QLIB_REG_HW_VER__FLASH_SIZE);
    }
    else
    {
        hwVer->flashSize = 0;
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_GetId(QLIB_CONTEXT_T* qlibContext, QLIB_SEC_ID_T* id_p)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    QLIB_STATUS_RET_CHECK(QLIB_SEC_GetWID(qlibContext, id_p->wid));
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_SUID(qlibContext, id_p->suid));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_GetStatus(QLIB_CONTEXT_T* qlibContext)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* GET_SSR command is ignored if power is down                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform SSR read with error check                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    if (W77Q_ECC(qlibContext) != 0u)
    {
        QLIB_REG_ESSR_T essr;
        QLIB_STATUS_RET_CHECK(((qlibContext->isSuspended == 1u) ? QLIB_CMD_PROC__get_ESSR_UNSIGNED(qlibContext, &essr)
                                                                : QLIB_SEC__get_ESSR(qlibContext, &essr)));

        /****************************************************************************************************
         * Check ECC indications
        ****************************************************************************************************/
        QLIB_ASSERT_RET(0u == READ_VAR_FIELD(essr.asUint64, QLIB_REG_ESSR__ECC_SEC), QLIB_STATUS__WARNING_SINGLE_ERROR_CORRECTED);
        QLIB_ASSERT_RET(0u == READ_VAR_FIELD(essr.asUint64, QLIB_REG_ESSR__ECC_DIS), QLIB_STATUS__WARNING_MULTIPLE_PROGRAMMING);

        return QLIB_STATUS__OK;
    }
    else
    {
        return qlibContext->isSuspended == 1u ? QLIB_CMD_PROC__get_SSR_UNSIGNED(qlibContext, NULL, SSR_MASK__ALL_ERRORS)
                                              : QLIB_SEC__get_SSR(qlibContext, NULL, SSR_MASK__ALL_ERRORS);
    }
}

QLIB_STATUS_T
    QLIB_SEC_SetInterface(QLIB_CONTEXT_T* qlibContext, QLIB_BUS_FORMAT_T busFormat)
{
    QLIB_BUS_MODE_T format = QLIB_BUS_FORMAT_GET_MODE(busFormat);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    QLIB_SEC_SetInterface_L(qlibContext, format);
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_SyncAfterFlashReset(QLIB_CONTEXT_T* qlibContext)
{
    QLIB_STATUS_T  status = QLIB_STATUS__TEST_FAIL;
    QLIB_REG_SSR_T ssr;
    U8             dieId;
    U32            fallbackStatus = 0;
    U32            sectionID;
#ifndef EXCLUDE_Q2_DEVCFG_CTAG_MODE
    QLIB_BUS_MODE_T format = qlibContext->busInterface.secureCmdsFormat;
#endif
    /*-----------------------------------------------------------------------------------------------------*/
    /* refresh the out-dated information                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    for (dieId = 0; dieId < QLIB_NUM_OF_DIES; dieId++)
    {
        QLIB_SEC_MarkSessionClose_L(qlibContext, dieId);
        /*-----------------------------------------------------------------------------------------------------*/
        /* Plain sessions got closed after reset                                                               */
        /*-----------------------------------------------------------------------------------------------------*/
        for (sectionID = 0; sectionID < QLIB_NUM_OF_MAIN_SECTIONS; sectionID++)
        {
            qlibContext->dieState[dieId].sectionsState[sectionID].plainEnabled = QLIB_SECTION_PLAIN_EN_NO;
        }
    }

    qlibContext->activeDie    = 0; //after sw reset the active die is 0
    qlibContext->extendedAddr = 0; //after sw reset the extended address register is 0

#ifndef EXCLUDE_Q2_DEVCFG_CTAG_MODE
    if (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u)
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Reset might load new CTAG mode from GMC register                                                */
        /*-------------------------------------------------------------------------------------------------*/
        if (format == QLIB_BUS_MODE_1_1_4 || format == QLIB_BUS_MODE_1_4_4
#ifdef QLIB_SUPPORT_DUAL_SPI
            || format == QLIB_BUS_MODE_1_1_2 || format == QLIB_BUS_MODE_1_2_2
#endif
        )
        {
            // set interface to single mode for GET_GMC and GET_MC command, since single SPI is not affected by CTAG mode
            QLIB_SEC_SetInterface_L(qlibContext, QLIB_BUS_MODE_1_1_1);
        }
    }
#endif

    /*-----------------------------------------------------------------------------------------------------*/
    /* Wait while secure module is not-ready. It will also clear errors on SSR                             */
    /*-----------------------------------------------------------------------------------------------------*/
    do
    {
        status = QLIB_SEC__get_SSR(qlibContext, &ssr, SSR_MASK__ALL_ERRORS);
    } while (QLIB_STATUS__OK != status || (READ_VAR_FIELD(ssr.asUint, QLIB_REG_SSR__BUSY) == 1u));

    /********************************************************************************************************
     * Sync standard state - address mode and Dummy cycles
    ********************************************************************************************************/
    if (Q2_4_BYTES_ADDRESS_MODE(qlibContext) != 0u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_STD_GetAddressMode(qlibContext, &qlibContext->addrMode)); //reset loads default address mode
    }

    if (W77Q_FAST_READ_DUMMY_CONFIG(qlibContext) != 0u)
    {
        QLIB_STATUS_RET_CHECK(
            QLIB_STD_GetFastReadDummyCycles(qlibContext, &qlibContext->fastReadDummy)); //reset loads default dummy cycles
    }
#if (QLIB_NUM_OF_DIES > 1)
    for (dieId = 0; dieId < QLIB_NUM_OF_DIES; dieId++)
    {
        U8 nextDie = (dieId + 1) % QLIB_NUM_OF_DIES;

        fallbackStatus |= ((U32)READ_VAR_FIELD(QLIB_GET_LAST_SEC_STATUS_FIELD(qlibContext), QLIB_REG_SSR__FB_REMAP) << dieId);
        QLIB_STATUS_RET_CHECK(QLIB_STD_SetActiveDie(qlibContext, nextDie, TRUE));
    }
#else
    fallbackStatus = (U32)READ_VAR_FIELD(QLIB_GET_LAST_SEC_STATUS_FIELD(qlibContext), QLIB_REG_SSR__FB_REMAP);
#endif

#ifndef EXCLUDE_Q2_DEVCFG_CTAG_MODE
    if (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u)
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Sync context with new CTAG mode and update the SPI interface accordingly                        */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_SEC_InitCtagMode(qlibContext));
        if (format != qlibContext->busInterface.secureCmdsFormat)
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_SetInterface(qlibContext, QLIB_BUS_FORMAT(format, qlibContext->busInterface.dtr)));
        }
    }
#endif

    /*-----------------------------------------------------------------------------------------------------*/
    /* Cache reset status                                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    qlibContext->resetStatus.powerOnReset      = (U32)READ_VAR_FIELD(ssr.asUint, QLIB_REG_SSR__POR);
    qlibContext->resetStatus.fallbackRemapping = fallbackStatus;
    qlibContext->resetStatus.watchdogReset     = (U32)READ_VAR_FIELD(ssr.asUint, QLIB_REG_SSR__AWDT_EXP);
    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_EnablePlainAccess(QLIB_CONTEXT_T* qlibContext, U32 sectionID)
{
    QLIB_REG_SSR_T ssr;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Get SSR, to check chip state                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_SSR(qlibContext, &ssr, SSR_MASK__ALL_ERRORS));

    /*-----------------------------------------------------------------------------------------------------*/
    /* We open plain session only when the flash is in working mode                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET((READ_VAR_FIELD(ssr.asUint, QLIB_REG_SSR__STATE) & (U8)QLIB_REG_SSR__STATE_WORKING_MASK) ==
                        (U8)QLIB_REG_SSR__STATE_WORKING,
                    QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Enable plain access                                                                                 */
    /*-----------------------------------------------------------------------------------------------------*/
    if (W77Q_CMD_PA_GRANT_REVOKE(qlibContext) == 1u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__PA_grant_plain(qlibContext, sectionID));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__init_section_PA(qlibContext, sectionID));

        /*-----------------------------------------------------------------------------------------------------*/
        /* Re-open secure session                                                                              */
        /*-----------------------------------------------------------------------------------------------------*/
        if (QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext))
        {
            QLIB_STATUS_RET_CHECK(
                QLIB_SEC_OpenSessionInternal_L(qlibContext, QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid, NULL, FALSE));
        }
    }
    return QLIB_STATUS__OK;
}


#ifdef QLIB_SIGN_DATA_BY_FLASH
QLIB_STATUS_T QLIB_SEC_SignVerify(QLIB_CONTEXT_T* qlibContext,
                                  U32             sectionID,
                                  U8*             dataIn,
                                  U32             dataSize,
                                  _256BIT         signature,
                                  BOOL            verify)
{
    const U32               sec_addr_size    = 3;
    U32                     i                = 0;
    U32                     enc_addr         = 0;
    U32                     offset           = 0;
    BOOL                    need_compression = TRUE;
    _64BIT                  sig64            = {0};
    U32                     cache[32]        = {0};
    QLIB_SIGN_VERIFY_FUNC_T signFunc         = (verify == FALSE) ? QLIB_CMD_PROC__SARD_Sign : QLIB_CMD_PROC__SARD_Verify;
    U32                     numOfIter        = DIV_CEIL(dataSize, sec_addr_size);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Unused parameters                                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    TOUCH(sectionID);

    for (i = 0; i < numOfIter; ++i)
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Construct an address out of the given data                                                      */
        /*-------------------------------------------------------------------------------------------------*/
        enc_addr = MAKE_32_BIT(dataIn[i * sec_addr_size],
                               i * sec_addr_size + 1u < dataSize ? dataIn[i * sec_addr_size + 1u] : 0u,
                               i * sec_addr_size + 2u < dataSize ? dataIn[i * sec_addr_size + 2u] : 0u,
                               0);
        /*-------------------------------------------------------------------------------------------------*/
        /* Sign the 'address' using Flash commands                                                         */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(signFunc(qlibContext, enc_addr, sig64));

        /*-------------------------------------------------------------------------------------------------*/
        /* Cache the signature                                                                             */
        /*-------------------------------------------------------------------------------------------------*/
        (void)memcpy(&cache[offset], sig64, sizeof(_64BIT));
        offset += 2u;
        need_compression = TRUE;

        /*-------------------------------------------------------------------------------------------------*/
        /* Compress the cache if needed                                                                    */
        /*-------------------------------------------------------------------------------------------------*/
        if (offset >= ARRAY_SIZE(cache))
        {
            QLIB_STATUS_RET_CHECK(QLIB_HASH(cache, cache, sizeof(cache)));
            offset           = sizeof(_256BIT) / sizeof(U32); // The 1st 256bit are occupied by the sha256 output
            need_compression = FALSE;
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Final compression                                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    if (need_compression == TRUE)
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Final compression                                                                               */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_HASH(cache, cache, offset * sizeof(U32)));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if we sign or verify                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    if (verify == FALSE)
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* On sign, export the signature                                                                   */
        /*-------------------------------------------------------------------------------------------------*/
        (void)memcpy(signature, cache, sizeof(_256BIT));
    }
    else
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* On verify, compare the given signature                                                          */
        /*-------------------------------------------------------------------------------------------------*/
        if (memcmp(signature, cache, sizeof(_256BIT)) != 0)
        {
            return QLIB_STATUS__DEVICE_AUTHENTICATION_ERR;
        }
    }

    return QLIB_STATUS__OK;
}
#endif

#ifndef EXCLUDE_LMS
QLIB_STATUS_T QLIB_SEC_SendLMSCommand(QLIB_CONTEXT_T* qlibContext, const U32* cmd, U32 cmdSize, U32 sectionID)
{
    _256BIT hashOutput;
    U32     cmdCtag;
    BOOL    plainAccess;
    BOOL    reset;
    U8      mode;

    plainAccess = FALSE;
    reset       = FALSE;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    // Calculate digest of cmd data
    QLIB_STATUS_RET_CHECK(QLIB_HASH(hashOutput, cmd, cmdSize));

    // cmdCtag = cmd[0]; // TODO once CTAG is in correct byte order
    cmdCtag = QLIB_CMD_PROC__MAKE_CTAG_PARAMS(BYTE(cmd[0], 3), BYTE(cmd[0], 2), BYTE(cmd[0], 1), BYTE(cmd[0], 0));

    QLIB_ASSERT_RET((QLIB_CMD_PROC__CTAG_GET_CMD(cmdCtag) == (U8)QLIB_CMD_SEC_SET_SCR_SWAP) ||
                        (QLIB_CMD_PROC__CTAG_GET_CMD(cmdCtag) == (U8)QLIB_CMD_SEC_SET_SCR),
                    QLIB_STATUS__NOT_SUPPORTED);

    // check whether the LMS command enables/revokes Plain Access
    mode = BYTE(cmdCtag, 2);
    if (READ_VAR_FIELD(mode, QLIB_SEC_CMD_SET_SCR_MODE_FIELD_RELOAD) == 1u)
    {
        SSPRn_T SSPRn = cmd[4];
        QLIB_ASSERT_RET(READ_VAR_FIELD(SSPRn, QLIB_REG_SSPRn__AUTH_PA) == 0u, QLIB_STATUS__DEVICE_PRIVILEGE_ERR);
        plainAccess = TRUE;
    }

    if (READ_VAR_FIELD(mode, QLIB_SEC_CMD_SET_SCR_MODE_FIELD_RESET) == 1u)
    {
        reset = TRUE;
    }

    QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Write_L(qlibContext, cmd, sectionID, cmdSize));
    QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Execute_L(qlibContext, sectionID, &hashOutput[6], reset, plainAccess));

    return QLIB_STATUS__OK;
}
#endif

QLIB_STATUS_T QLIB_SEC_GetRandom(QLIB_CONTEXT_T* qlibContext, void* random, U32 randomSize)
{
    RNGR_T rngr;

    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    while (randomSize > 0u)
    {
        U32             size = MIN(randomSize, sizeof(U32));
        QLIB_REG_ESSR_T essr;
        do
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC__get_ESSR(qlibContext, &essr));
        } while (READ_VAR_FIELD(essr.asUint64, QLIB_REG_ESSR__RNG_RDY) == 0u);

        QLIB_STATUS_RET_CHECK(QLIB_SEC__get_RNGR(qlibContext, rngr));
        (void)memcpy(random, (void*)(&QLIB_REG_RNGR_GET_RND(rngr)), size);
        randomSize = randomSize - size;
        random     = (void*)(((U8*)(random)) + size);
    }

    return QLIB_STATUS__OK;
}

#if !defined EXCLUDE_LMS_ATTESTATION && !defined Q2_API
QLIB_STATUS_T                                    QLIB_SEC_LMS_Attest_SetPrivateKey(QLIB_CONTEXT_T*                 qlibContext,
                                                                                   const LMS_ATTEST_PRIVATE_SEED_T seed,
                                                                                   const LMS_ATTEST_KEY_ID_T       keyId)
{
    /*-----------------------------------------------------------------------------------------------------*/
    /* Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    return QLIB_CMD_PROC__OTS_SET_KEY(qlibContext, seed, keyId);
}

QLIB_STATUS_T QLIB_SEC_LMS_Attest_Sign(QLIB_CONTEXT_T*          qlibContext,
                                       const U8*                msg,
                                       U32                      msgSize,
                                       const LMS_ATTEST_NONCE_T nonce,
                                       LMS_ATTEST_CHUNK_T       pubCache[],
                                       U32                      pubCacheLen,
                                       QLIB_OTS_SIG_T*          sig)
{
    LMS_ATTEST_CHUNK_T msgHash;
    U32                i, r;
    U32                index;

    /*-----------------------------------------------------------------------------------------------------* /
     * Secure command is ignored if power is down or suspended                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Init OTS sign and get the leaf number and key ID
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__OTS_INIT(qlibContext, &sig->leafNum, sig->keyId));
    QLIB_ASSERT_RET(sig->leafNum < QLIB_LMS_ATTEST_NUM_OF_LEAVES, QLIB_STATUS__SECURITY_ERR);

    /********************************************************************************************************
     * Hash the msg
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Attest_CalcMsgHash(sig->keyId, sig->leafNum, nonce, msg, msgSize, msgHash));

    /********************************************************************************************************
     * Generate OTS signature
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Attest_Sign_L(qlibContext, msgHash, sig->otsSig));

    /********************************************************************************************************
     * Calculate path
    ********************************************************************************************************/
    r = QLIB_LMS_ATTEST_LEAF_NODES_START_INDEX + sig->leafNum;

    for (i = 0; i < QLIB_LMS_ATTEST_TREE_HEIGHT; ++i)
    {
        index = (r / ((U32)1 << i)) ^ (U32)1;
        QLIB_STATUS_RET_CHECK(
            QLIB_SEC_LMS_Attest_GetRoot_L(qlibContext, sig->keyId, index, pubCache, pubCacheLen, sig->path[i], FALSE));
    }

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_LMS_Attest_GetPublicKey(QLIB_CONTEXT_T*    qlibContext,
                                               LMS_ATTEST_CHUNK_T pubKey,
                                               LMS_ATTEST_CHUNK_T pubCache[],
                                               U32                pubCacheLen)
{
    LMS_ATTEST_KEY_ID_T keyId;

    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Get key ID from the flash
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__OTS_GET_ID(qlibContext, NULL, keyId));

    /********************************************************************************************************
     * Invalidate cache
    ********************************************************************************************************/
    if (pubCache != NULL)
    {
        (void)memset(pubCache, 0, pubCacheLen * sizeof(LMS_ATTEST_CHUNK_T));
    }

    /********************************************************************************************************
     * Get LMS Merkle tree
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Attest_GetRoot_L(qlibContext, keyId, 1, pubCache, pubCacheLen, pubKey, FALSE));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_LMS_Attest_CalcMsgHash(const LMS_ATTEST_KEY_ID_T keyId,
                                              U32                       leafIndex,
                                              const LMS_ATTEST_NONCE_T  nonce,
                                              const U8*                 msg,
                                              U32                       msgSize,
                                              LMS_ATTEST_CHUNK_T        msgHash)
{
    QLIB_SEC_OTS_MSG_T msgStr;
    _256BIT            hash;
    QLIB_STATUS_T      ret = QLIB_STATUS__SECURITY_ERR;
    void*              hashCtx;

    (void)memcpy(msgStr.keyId, keyId, sizeof(LMS_ATTEST_KEY_ID_T));
    msgStr.q     = REVERSE_BYTES_32_BIT(leafIndex);
    msgStr.d_msg = LMS_ATTEST_D_MESG;
    (void)memcpy(msgStr.nonce, nonce, sizeof(LMS_ATTEST_NONCE_T));

    QLIB_ASSERT_RET(PLAT_HASH_Init(&hashCtx, QLIB_HASH_OPT_NONE) == 0, QLIB_STATUS__HARDWARE_FAILURE);
    QLIB_ASSERT_WITH_ERROR_GOTO(PLAT_HASH_Update(hashCtx, &msgStr, sizeof(QLIB_SEC_OTS_MSG_T)) == 0,
                                QLIB_STATUS__HARDWARE_FAILURE,
                                ret,
                                error);
    QLIB_ASSERT_WITH_ERROR_GOTO(PLAT_HASH_Update(hashCtx, msg, msgSize) == 0, QLIB_STATUS__HARDWARE_FAILURE, ret, error);
    QLIB_ASSERT_WITH_ERROR_GOTO(PLAT_HASH_Finish(hashCtx, hash) == 0, QLIB_STATUS__HARDWARE_FAILURE, ret, error);

    (void)memcpy(msgHash, (U8*)hash, sizeof(LMS_ATTEST_CHUNK_T));

    return QLIB_STATUS__OK;

error:
    (void)PLAT_HASH_Finish(hashCtx, hash); // to erase the context
    return ret;
}
#endif // EXCLUDE_LMS_ATTESTATION

QLIB_STATUS_T QLIB_SEC_ClearSSR(QLIB_CONTEXT_T* qlibContext)
{
    // Read SSR to clear all sticky (ROC) error bits in SSR but do not consider any bit as error.
    // This function will also implicit perform OP1 to clear the Non-sticky ERR bit if exist
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_SSR_UNSIGNED(qlibContext, NULL, 0));

    // Read SSR again to verify all errors have been cleared
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_SSR(qlibContext, NULL, SSR_MASK__ALL_ERRORS));

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_IsKeyProvisioned(QLIB_CONTEXT_T* qlibContext,
                                        QLIB_KID_TYPE_T keyIdType,
                                        U32             sectionID,
                                        BOOL*           isProvisioned)
{
    U64 keysStatus = 0;

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_KEYS_STATUS_UNSIGNED(qlibContext, &keysStatus));

    if (keyIdType == QLIB_KID__RESTRICTED_ACCESS_SECTION)
    {
        *isProvisioned = INT_TO_BOOLEAN(READ_VAR_BIT(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__RESTRICTED), sectionID));
    }
    else if (keyIdType == QLIB_KID__FULL_ACCESS_SECTION)
    {
        *isProvisioned = INT_TO_BOOLEAN(READ_VAR_BIT(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__FULL), sectionID));
    }
    else if (keyIdType == QLIB_KID__SECTION_LMS)
    {
        *isProvisioned = INT_TO_BOOLEAN(READ_VAR_BIT(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__LMS_PUBLIC), sectionID));
    }
    else if (keyIdType == QLIB_KID__DEVICE_SECRET)
    {
        *isProvisioned = INT_TO_BOOLEAN(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__SECRET));
    }
    else if (keyIdType == QLIB_KID__DEVICE_MASTER)
    {
        *isProvisioned = INT_TO_BOOLEAN(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__MASTER));
    }
    else if (keyIdType == QLIB_KID__DEVICE_KEY_PROVISIONING)
    {
        *isProvisioned = INT_TO_BOOLEAN(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__PRE_PROV_MASTER));
    }
    else
    {
        return QLIB_STATUS__INVALID_PARAMETER;
    }

    return QLIB_STATUS__OK;
}

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                            LOCAL FUNCTIONS                                              */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

static QLIB_STATUS_T QLIB_SEC_KeyProvisioning_L(QLIB_CONTEXT_T*        qlibContext,
                                                const KEY_T            Kd,
                                                QLIB_KID_T             new_kid,
                                                const KEY_T            new_key,
                                                QLIB_SEC_PROV_ACTION_T action)
{
    QLIB_KID_T    prov_kid = (QLIB_KID_T)QLIB_KID__INVALID;
    KEY_T         prov_key;
    QLIB_STATUS_T ret = QLIB_STATUS__COMMAND_FAIL;

    if (action != QLIB_SEC_PROV_CONFIG_ONLY)
    {
        /*-----------------------------------------------------------------------------------------------------*/
        /* Check if key is already configured: assume key was already provisioned, verify that open session    */
        /* succeeded with that key                                                                             */
        /*-----------------------------------------------------------------------------------------------------*/
        ret = QLIB_SEC_OpenSessionInternal_L(qlibContext, new_kid, new_key, TRUE);
        if (ret == QLIB_STATUS__OK)
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));
        }

        if (action == QLIB_SEC_PROV_VERIFY_ONLY)
        {
            // ignore other open_session errors caused for example by incorrect section configuration
            QLIB_ASSERT_RET(ret != QLIB_STATUS__DEVICE_AUTHENTICATION_ERR, QLIB_STATUS__DEVICE_AUTHENTICATION_ERR);
            return QLIB_STATUS__OK;
        }
        else
        {
            if (ret == QLIB_STATUS__OK)
            {
                // if verify succeeded, nothing more to do. on verify error - proceed to key provisioning
                return QLIB_STATUS__OK;
            }
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Calculate provisioning key descriptor                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    switch (QLIB_KEY_MNGR__GET_KEY_TYPE(new_kid))
    {
        case (QLIB_KID_T)QLIB_KID__RESTRICTED_ACCESS_SECTION:
        case (QLIB_KID_T)QLIB_KID__FULL_ACCESS_SECTION:
            prov_kid = (QLIB_KID_T)QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__SECTION_PROVISIONING,
                                                                   QLIB_KEY_MNGR__GET_KEY_SECTION(new_kid));
            break;

        case (QLIB_KID_T)QLIB_KID__DEVICE_SECRET:
        case (QLIB_KID_T)QLIB_KID__DEVICE_MASTER:
            prov_kid = (QLIB_KID_T)(QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__DEVICE_KEY_PROVISIONING,
                                                                    QLIB_KEY_MNGR__GET_KEY_SECTION(new_kid)) &
                                    0xffu);
            break;

        default:
            prov_kid = (QLIB_KID_T)QLIB_KID__INVALID; // Set prov_kid to QLIB_KID__INVALID to indicate we have invalid parameter
            // It's a PC-Lint require to put a default and break in any switch case
            break;
    }
    if (prov_kid == (QLIB_KID_T)QLIB_KID__INVALID)
    {
        return QLIB_STATUS__PARAMETER_OUT_OF_RANGE;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Calculate provisioning key                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_CRYPTO_GetProvisionKey(prov_kid, Kd, TRUE, FALSE, prov_key);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Open session with provisioning key                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSessionInternal_L(qlibContext, prov_kid, prov_key, FALSE));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set the Key                                                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__set_KEY(qlibContext, new_kid, new_key), ret, close_session);

close_session:
    QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

    return ret;
}

static QLIB_STATUS_T QLIB_SEC_LmsKeyProvisioning_L(QLIB_CONTEXT_T*      qlibContext,
                                                   const KEY_T          Kd,
                                                   QLIB_KID_T           new_kid,
                                                   const QLIB_LMS_KEY_T publicKey)
{
    QLIB_KID_T    prov_kid;
    KEY_T         prov_key;
    QLIB_STATUS_T ret;

    QLIB_ASSERT_RET((U8)QLIB_KID__SECTION_LMS == QLIB_KEY_MNGR__GET_KEY_TYPE(new_kid), QLIB_STATUS__INVALID_PARAMETER);

    /********************************************************************************************************
     * Calculate provisioning key
    ********************************************************************************************************/
    prov_kid = QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__SECTION_PROVISIONING, QLIB_KEY_MNGR__GET_KEY_SECTION(new_kid));
    QLIB_CRYPTO_GetProvisionKey(prov_kid, Kd, TRUE, FALSE, prov_key);

    /********************************************************************************************************
     * Open session with provisioning key
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSessionInternal_L(qlibContext, prov_kid, prov_key, FALSE));

    /********************************************************************************************************
     * Set the Key
    ********************************************************************************************************/
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__LMS_set_KEY(qlibContext, new_kid, publicKey), ret, close_session);

close_session:
    QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

    return ret;
}

static QLIB_STATUS_T QLIB_SEC_setAllKeys_L(QLIB_CONTEXT_T*            qlibContext,
                                           const KEY_T                deviceMasterKey,
                                           const KEY_T                deviceSecretKey,
                                           const KEY_ARRAY_T          restrictedKeys,
                                           const KEY_ARRAY_T          fullAccessKeys,
                                           const QLIB_LMS_KEY_ARRAY_T lmsKeys,
                                           const KEY_T                preProvisionedMasterKey)
{
    QLIB_KID_T             kid          = (U8)QLIB_KID__INVALID;
    U8                     sectionIndex = 0;
    KEY_T                  key_buff;
    U64                    keysStatus = 0;
    QLIB_SEC_PROV_ACTION_T kd2_prov_action;

    if (W77Q_CMD_GET_KEYS_STATUS(qlibContext) != 0u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_KEYS_STATUS_UNSIGNED(qlibContext, &keysStatus));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* This function cannot work without device key                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__IS_KEY_VALID(deviceMasterKey), QLIB_STATUS__INVALID_PARAMETER);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set device Master Key (use the default K_d)                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    kd2_prov_action = W77Q_CMD_GET_KEYS_STATUS(qlibContext) == 0u
                          ? QLIB_SEC_PROV_CONFIG_IF_VERIFY_FAIL
                          : ((READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__MASTER) == 1u) ||
                                     ((READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__PRE_PROV_MASTER) == 1u) &&
                                      !QLIB_KEY_MNGR__IS_KEY_VALID(preProvisionedMasterKey))
                                 ? QLIB_SEC_PROV_VERIFY_ONLY
                                 : QLIB_SEC_PROV_CONFIG_ONLY);

    if ((W77Q_PRE_PROV_MASTER_KEY(qlibContext) == 0u) ||
        ((W77Q_CMD_GET_KEYS_STATUS(qlibContext) != 0u) &&
         (READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__PRE_PROV_MASTER) == 0u)))
    {
        (void)memset(key_buff, 0xFF, sizeof(KEY_T)); ///< deviceMasterKey initial value
    }
    else
    {
        QLIB_ASSERT_RET(QLIB_KEY_MNGR__IS_KEY_VALID(preProvisionedMasterKey) || (QLIB_SEC_PROV_VERIFY_ONLY == kd2_prov_action),
                        QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
        if (NULL != preProvisionedMasterKey)
        {
            (void)memcpy(key_buff, preProvisionedMasterKey, sizeof(KEY_T));
        }
    }

    QLIB_STATUS_RET_CHECK(
        QLIB_SEC_KeyProvisioning_L(qlibContext, key_buff, (QLIB_KID_T)QLIB_KID__DEVICE_MASTER, deviceMasterKey, kd2_prov_action));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set device Secret Key                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    if (QLIB_KEY_MNGR__IS_KEY_VALID(deviceSecretKey) &&
        ((W77Q_CMD_GET_KEYS_STATUS(qlibContext) == 0u) || (READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__SECRET) == 0u)))
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_KeyProvisioning_L(qlibContext,
                                                         deviceMasterKey,
                                                         (QLIB_KID_T)QLIB_KID__DEVICE_SECRET,
                                                         deviceSecretKey,
                                                         QLIB_SEC_PROV_CONFIG_ONLY));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set sections Keys                                                                                   */
    /*-----------------------------------------------------------------------------------------------------*/
    if ((restrictedKeys != NULL) || (fullAccessKeys != NULL))
    {
#ifndef Q2_API
        for (sectionIndex = 0; sectionIndex < QLIB_NUM_OF_SECTIONS; sectionIndex++)
#else
        for (sectionIndex = 0; sectionIndex < QLIB_NUM_OF_MAIN_SECTIONS; sectionIndex++)
#endif
        {
            if (restrictedKeys != NULL)
            {
                if (QLIB_KEY_MNGR__IS_KEY_VALID(restrictedKeys[sectionIndex]))
                {
                    kid = (QLIB_KID_T)QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__RESTRICTED_ACCESS_SECTION, sectionIndex);

                    QLIB_STATUS_RET_CHECK(
                        QLIB_SEC_KeyProvisioning_L(qlibContext,
                                                   deviceMasterKey,
                                                   kid,
                                                   (restrictedKeys[sectionIndex]),
                                                   (W77Q_CMD_GET_KEYS_STATUS(qlibContext) == 0u) ||
                                                           (READ_VAR_BIT(READ_VAR_FIELD(keysStatus,
                                                                                        QLIB_REG_KEYS_STAT__RESTRICTED),
                                                                         sectionIndex) == 0u)
                                                       ? QLIB_SEC_PROV_CONFIG_ONLY
                                                       : QLIB_SEC_PROV_VERIFY_ONLY));
                }
            }
            if (fullAccessKeys != NULL)
            {
                if (QLIB_KEY_MNGR__IS_KEY_VALID(fullAccessKeys[sectionIndex]))
                {
                    kid = (QLIB_KID_T)QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__FULL_ACCESS_SECTION, sectionIndex);
                    QLIB_STATUS_RET_CHECK(
                        QLIB_SEC_KeyProvisioning_L(qlibContext,
                                                   deviceMasterKey,
                                                   kid,
                                                   (fullAccessKeys[sectionIndex]),
                                                   (W77Q_CMD_GET_KEYS_STATUS(qlibContext) == 0u) ||
                                                           (READ_VAR_BIT(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__FULL),
                                                                         sectionIndex) == 0u)
                                                       ? QLIB_SEC_PROV_CONFIG_ONLY
                                                       : QLIB_SEC_PROV_VERIFY_ONLY));
                }
            }
            if (lmsKeys != NULL)
            {
                if (QLIB_KEY_MNGR__IS_LMS_KEY_VALID(lmsKeys[sectionIndex]))
                {
                    if (W77Q_SUPPORT_LMS(qlibContext) == 0u)
                    {
                        return QLIB_STATUS__INVALID_PARAMETER;
                    }
                    else
                    {
                        if ((W77Q_CMD_GET_KEYS_STATUS(qlibContext) == 0u) ||
                            (READ_VAR_BIT(READ_VAR_FIELD(keysStatus, QLIB_REG_KEYS_STAT__LMS_PUBLIC), sectionIndex) == 0u))
                        {
                            kid = QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__SECTION_LMS, sectionIndex);
                            QLIB_STATUS_RET_CHECK(
                                QLIB_SEC_LmsKeyProvisioning_L(qlibContext, deviceMasterKey, kid, (lmsKeys[sectionIndex])));
                        }
                    }
                }
            }
        }
    }

    return QLIB_STATUS__OK;
}

static QLIB_STATUS_T QLIB_SEC_configGMC_L(QLIB_CONTEXT_T*             qlibContext,
                                          const KEY_T                 deviceMasterKey,
                                          const QLIB_WATCHDOG_CONF_T* watchdogDefault,
                                          const QLIB_DEVICE_CONF_T*   deviceConf,
                                          BOOL*                       gmcChanged)
{
    GMC_T                GMC;
    GMC_T                GMC_test;
    GMC_T                GMC_orig;
    AWDTCFG_T            AWDT   = 0;
    DEVCFG_T             DEVCFG = 0;
    U32                  ver    = 0;
    QLIB_STATUS_T        ret    = QLIB_STATUS__COMMAND_FAIL;
    QLIB_WATCHDOG_CONF_T initWatchdogConf;
    U32                  sectionIndex;
    U8                   resetPlainAccess;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read the previous value of Global Configuration Register (GMC)                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC));
    (void)memcpy(GMC_orig, GMC, sizeof(GMC_T));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Prepare the Global Configuration Register (GMC)                                                     */
    /*-----------------------------------------------------------------------------------------------------*/

    /*-----------------------------------------------------------------------------------------------------*/
    /* build AWDTCFG defaults                                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    AWDT = QLIB_REG_GMC_GET_AWDT_DFLT(GMC);

    if ((READ_VAR_FIELD(AWDT, QLIB_REG_AWDTCFG__RESERVED1) > 0u) && (watchdogDefault == NULL))
    {
        // Watchdog default was not set yet - Use valid default values
        watchdogDefault                = &initWatchdogConf;
        initWatchdogConf.enable        = FALSE;
        initWatchdogConf.authenticated = TRUE;
        initWatchdogConf.lfOscEn       = TRUE;
        initWatchdogConf.lock          = FALSE;
        initWatchdogConf.oscRateHz     = 0;
        initWatchdogConf.sectionID     = 0;
        initWatchdogConf.swResetEn     = FALSE;
        initWatchdogConf.threshold     = QLIB_AWDT_TH_12_DAYS;
        initWatchdogConf.fallbackEn    = FALSE;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set watchdog configuration                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    if (watchdogDefault != NULL)
    {
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__AWDT_EN, BOOLEAN_TO_INT(watchdogDefault->enable));
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__LFOSC_EN, BOOLEAN_TO_INT(watchdogDefault->lfOscEn));
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__SRST_EN, BOOLEAN_TO_INT(watchdogDefault->swResetEn));
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__AUTH_WDT, BOOLEAN_TO_INT(watchdogDefault->authenticated));
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__KID, watchdogDefault->sectionID);
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__TH, (U8)watchdogDefault->threshold);

        if (Q2_SUPPORT_AWDTCFG_FALLBACK(qlibContext) != 0u)
        {
            QLIB_ASSERT_RET((watchdogDefault->enable == FALSE) || (watchdogDefault->fallbackEn == FALSE) ||
                                (watchdogDefault->swResetEn == TRUE),
                            QLIB_STATUS__INVALID_PARAMETER);
        }
        else
        {
            QLIB_ASSERT_RET((watchdogDefault->enable == FALSE) || (watchdogDefault->fallbackEn == FALSE),
                            QLIB_STATUS__NOT_SUPPORTED);
        }
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__FB_EN, BOOLEAN_TO_INT(watchdogDefault->fallbackEn));
#ifdef W77Q_AWDT_IS_CALIBRATED
        // Use the existing calibration value
#else
        if (0u != watchdogDefault->oscRateHz)
        {
            // Set the WD LF-oscillator calibration value from user
            SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__OSC_RATE_KHZ, DIV_BY_1000_32BIT(watchdogDefault->oscRateHz));
            SET_VAR_FIELD_32(AWDT,
                             QLIB_REG_AWDTCFG__OSC_RATE_FRAC,
                             W77Q_AWDTCFG_OSC_RATE_FRAC(qlibContext) != 0u ? watchdogDefault->oscRateHz >> 6u : 0u);
        }
        else
        {
            // Set the WD LF-oscillator calibration value to default
            SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__OSC_RATE_KHZ, (U8)QLIB_AWDTCFG__OSC_RATE_KHZ_DEFAULT);
            SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__OSC_RATE_FRAC, 0u);
        }
#endif // W77Q_AWDT_IS_CALIBRATED

        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__LOCK, BOOLEAN_TO_INT(watchdogDefault->lock));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Set pin-mux configuration                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    if (deviceConf != NULL)
    {
        BOOL quadEnable = FALSE;

        /*-------------------------------------------------------------------------------------------------*/
        /* Set IO2/IO3 pin-mux                                                                             */
        /*-------------------------------------------------------------------------------------------------*/
        switch (deviceConf->pinMux.io23Mux)
        {
            /*---------------------------------------------------------------------------------------------*/
            /* Legacy mode: QE=0, RSTI_OVRD=0, RSTO=0                                                      */
            /*---------------------------------------------------------------------------------------------*/
            case QLIB_IO23_MODE__LEGACY_WP_HOLD:
                quadEnable = FALSE;
                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTI_OVRD, 0u);
                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTO_EN, 0u);
                break;
            /*---------------------------------------------------------------------------------------------*/
            /* RESET mode, QE=0, RSTI_OVRD=1, RSTI=1, RSTO=1                                               */
            /*---------------------------------------------------------------------------------------------*/
            case QLIB_IO23_MODE__RESET_IN_OUT:
                quadEnable = FALSE;

                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTI_OVRD, 1u);
                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTI_EN, 1u);
                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTO_EN, 1u);
                break;
            /*---------------------------------------------------------------------------------------------*/
            /* QUAD mode (QE=1, RSTI_OVRD=0, RSTO=0                                                        */
            /*---------------------------------------------------------------------------------------------*/
            case QLIB_IO23_MODE__QUAD:
                quadEnable = TRUE;
                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTI_OVRD, 0u);
                SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RSTO_EN, 0u);
                break;
            case QLIB_IO23_MODE__NONE:
                break;
            default:
                //Lint
                break;
        }

        /*-------------------------------------------------------------------------------------------------*/
        /* Set dedicated reset_in pin-mux                                                                  */
        /*-------------------------------------------------------------------------------------------------*/
        SET_VAR_FIELD_32(AWDT, QLIB_REG_AWDTCFG__RST_IN_EN, BOOLEAN_TO_INT(deviceConf->pinMux.dedicatedResetInEn));

        if (deviceConf->pinMux.io23Mux != QLIB_IO23_MODE__NONE && qlibContext->activeDie == QLIB_INIT_DIE_ID)
        {
            /*---------------------------------------------------------------------------------------------*/
            /* Set QE value                                                                                */
            /*---------------------------------------------------------------------------------------------*/
                QLIB_STATUS_RET_CHECK(QLIB_STD_SetQuadEnable(qlibContext, quadEnable));

            if (Q2_HOLD_PIN(qlibContext) != 0u)
            {
                /*-----------------------------------------------------------------------------------------*/
                /* Set hold/reset value to 0, we always control the RESET via RSTI_OVRD                    */
                /*-----------------------------------------------------------------------------------------*/
                QLIB_STATUS_RET_CHECK(QLIB_STD_SetResetInEnable(qlibContext, FALSE));
            }
        }
    }

    QLIB_REG_GMC_SET_AWDT_DFLT(GMC, (U32)(AWDT & (~QLIB_REG_AWDTCFG_RESERVED_MASK)));

    /*-----------------------------------------------------------------------------------------------------*/
    /* build DEVCFG register                                                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    DEVCFG = QLIB_REG_GMC_GET_DEVCFG(GMC);
    if (deviceConf != NULL)
    {
        QLIB_RESET_RESPONSE_T disabledResetResp = {0};

        /*-------------------------------------------------------------------------------------------------*/
        /* Update standard address size                                                                    */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ASSERT_RET((Q2_LIMITED_SECT_SEL_MODES(qlibContext) == 0u) ||
                            (deviceConf->stdAddrSize.addrLen <= QLIB_STD_ADDR_LEN__25_BIT),
                        QLIB_STATUS__INVALID_PARAMETER);
        qlibContext->addrSize = QLIB_STD_ADDR_LEN_TO_ADDRESS_OFFSET_SIZE(deviceConf->stdAddrSize.addrLen);
        QLIB_ASSERT_RET(LOG2(QLIB_MIN_SECTION_SIZE) <= qlibContext->addrSize, QLIB_STATUS__INVALID_PARAMETER);
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__SECT_SEL, qlibContext->addrSize - LOG2(QLIB_MIN_SECTION_SIZE));

        if (0 == memcmp((const U8*)(&deviceConf->resetResp), (const U8*)(&disabledResetResp), sizeof(QLIB_RESET_RESPONSE_T)))
        {
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RST_RESP_EN, 0u);
        }
        else
        {
            if (W77Q_RST_RESP(qlibContext) == 0u)
            {
                return QLIB_STATUS__NOT_SUPPORTED;
            }
            else
            {
                SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RST_RESP_EN, 1u);
            }
        }
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__FB_EN, BOOLEAN_TO_INT(deviceConf->safeFB));
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__CK_SPECUL, BOOLEAN_TO_INT(deviceConf->speculCK));
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__FORMAT_EN, BOOLEAN_TO_INT(deviceConf->nonSecureFormatEn));
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__STM_EN, 0u);

#ifndef Q2_API
        QLIB_ASSERT_RET((W77Q_BOOT_FAIL_RESET(qlibContext) != 0u) || (deviceConf->bootFailReset == FALSE),
                        QLIB_STATUS__INVALID_PARAMETER);
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__BOOT_FAIL_RST, BOOLEAN_TO_INT(deviceConf->bootFailReset));
#else
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__BOOT_FAIL_RST, 0u);
#endif
        SET_VAR_FIELD_32(DEVCFG,
                         QLIB_REG_DEVCFG__CTAG_MODE,
                         (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u) ? BOOLEAN_TO_INT(deviceConf->ctagModeMulti) : 0u);

        SET_VAR_FIELD_32(DEVCFG,
                         QLIB_REG_DEVCFG__VAULT_MEM,
                         (W77Q_VAULT(qlibContext) != 0u) ? (U8)(deviceConf->vaultSize[qlibContext->activeDie]) : 0u);

#ifndef Q2_API
        QLIB_ASSERT_RET((W77Q_RNG_FEATURE(qlibContext) != 0u) || (deviceConf->rngPAEn == FALSE), QLIB_STATUS__INVALID_PARAMETER);
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RNG_PA_EN, BOOLEAN_TO_INT(deviceConf->rngPAEn));
#else
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RNG_PA_EN, 0u);
#endif
        resetPlainAccess = 0u;
        for (sectionIndex = 0; sectionIndex < QLIB_NUM_OF_MAIN_SECTIONS; sectionIndex++)
        {
            resetPlainAccess |= (BOOLEAN_TO_INT(deviceConf->resetPA[qlibContext->activeDie][sectionIndex]) << sectionIndex);
        }
        if (W77Q_RST_PA(qlibContext) != 0u)
        {
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RST_PA, resetPlainAccess);
        }
        else
        {
#ifndef Q2_API
            QLIB_ASSERT_RET((resetPlainAccess == 0u) || (resetPlainAccess == 1u), QLIB_STATUS__INVALID_PARAMETER);
#endif
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RST_PA, 0u);
        }

#ifndef Q2_API
        QLIB_ASSERT_RET((W77Q_DEVCFG_LOCK(qlibContext) != 0u) || (deviceConf->lock == FALSE), QLIB_STATUS__INVALID_PARAMETER);
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__CFG_LOCK, BOOLEAN_TO_INT(deviceConf->lock));
#else
        SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__CFG_LOCK, 0u);
#endif
    }
    else
    {
        if (READ_VAR_FIELD(DEVCFG, QLIB_REG_DEVCFG__RESERVED_1) > 0u)
        {
            // DEVCFG was not set yet - Use valid default values
            qlibContext->addrSize = QLIB_STD_ADDR_LEN_TO_ADDRESS_OFFSET_SIZE(QLIB_STD_ADDR_LEN__25_BIT);
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__SECT_SEL, 3u);
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__FB_EN, 0u);
#ifndef Q3_TEST_MODE
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__STM_EN, 0u);
#endif
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__RST_PA, 1u);
            SET_VAR_FIELD_32(DEVCFG, QLIB_REG_DEVCFG__CFG_LOCK, 0u);
        }
    }
    QLIB_REG_GMC_SET_DEVCFG(GMC, (DEVCFG | (U32)QLIB_REG_DEVCFG_RESERVED_ONE_MASK) & ~(U32)QLIB_REG_DEVCFG_RESERVED_ZERO_MASK);

    *gmcChanged = (memcmp(GMC, GMC_orig, sizeof(GMC_T)) == 0) ? FALSE : TRUE;
    if (*gmcChanged == TRUE)
    {
        U32 numCommands = 0;
        U32 numRetries  = (Q3_BYPASS_HW_ISSUE_SET_CMD_FAIL(qlibContext) == 1u ? SET_CMD_HW_BYPASS_NUM_RETRIES : 1u);

        // Increase the version value
        ver = QLIB_REG_GMC_GET_VER(GMC) + 1u;
        QLIB_REG_GMC_SET_VER(GMC, ver);

        /*-------------------------------------------------------------------------------------------------*/
        /* Write the new Global Configuration Register (GMC)                                               */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(
            QLIB_SEC_OpenSessionInternal_L(qlibContext, (QLIB_KID_T)QLIB_KID__DEVICE_MASTER, deviceMasterKey, FALSE));
        do
        {
            ret = QLIB_CMD_PROC__set_GMC(qlibContext, GMC);
            numCommands++;
        } while ((ret == QLIB_STATUS__DEVICE_SYSTEM_ERR) && (numCommands < numRetries));
        QLIB_STATUS_RET_CHECK_GOTO(ret, ret, error_session);
        QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

        /*-------------------------------------------------------------------------------------------------*/
        /* Confirm operation success                                                                       */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC_test));
        QLIB_ASSERT_RET(0 == memcmp(GMC, GMC_test, sizeof(GMC_T)), QLIB_STATUS__COMMAND_FAIL);
    }

    ret = QLIB_STATUS__OK;

    goto exit;

error_session:
    QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

exit:
    return ret;
}

static QLIB_STATUS_T QLIB_SEC_configGMT_L(QLIB_CONTEXT_T*                   qlibContext,
                                          const KEY_T                       deviceMasterKey,
                                          const QLIB_SECTION_CONFIG_TABLE_T sectionTable,
                                          BOOL*                             gmtChanged)
{
    GMT_T         GMT;
    GMT_T         GMT_test;
    GMT_T         GMT_orig;
    U16           sectionIndex = 0;
    U32           ver          = 0;
    QLIB_STATUS_T ret          = QLIB_STATUS__COMMAND_FAIL;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Read the previews value of Global Mapping Table (GMT)                                               */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_GMT_UNSIGNED(qlibContext, &GMT));
    (void)memcpy(GMT_orig.asArray, GMT.asArray, sizeof(GMT_T));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Prepare the Global Mapping Table (GMT)                                                              */
    /*-----------------------------------------------------------------------------------------------------*/
    for (sectionIndex = 0; sectionIndex < QLIB_SECTION_ID_VAULT; sectionIndex++)
    {
        U32 sectionBase     = sectionTable[sectionIndex].baseAddr;
        U32 sectionLen      = sectionTable[sectionIndex].size;
        U32 sectionBaseTag  = QLIB_REG_SMRn__BASE_IN_BYTES_TO_TAG(sectionBase);
        U32 sectionLenTag   = QLIB_REG_SMRn__LEN_IN_BYTES_TO_TAG(qlibContext, sectionLen);
        U32 sectionLenScale = (W77Q_SEC_SIZE_SCALE(qlibContext) != 0u) ? QLIB_REG_SMRn__LEN_IN_BYTES_TO_SCALE(sectionLen) : 0u;

        /*-------------------------------------------------------------------------------------------------*/
        /* Error checking                                                                                  */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_ASSERT_RET((sectionBase + sectionLen) <= QLIB_GET_FLASH_SIZE(qlibContext), QLIB_STATUS__PARAMETER_OUT_OF_RANGE);
        QLIB_ASSERT_RET((sectionBase + sectionLen) >= sectionLen, QLIB_STATUS__INVALID_PARAMETER);

        if (sectionLen != 0u)
        {
            if (Q2_BYPASS_HW_ISSUE_105(qlibContext) != 0u)
            {
                QLIB_ASSERT_RET(ALIGNED_TO(sectionBase, _256KB_), QLIB_STATUS__INVALID_PARAMETER);
                QLIB_ASSERT_RET(ALIGNED_TO(sectionLen, _256KB_), QLIB_STATUS__INVALID_PARAMETER);
            }
            QLIB_ASSERT_RET(QLIB_REG_SMRn__BASE_IN_TAG_TO_BYTES(sectionBaseTag) == sectionBase, QLIB_STATUS__INVALID_PARAMETER);
            QLIB_ASSERT_RET(QLIB_REG_SMRn__LEN_IN_TAG_TO_BYTES(qlibContext, sectionLenTag, sectionLenScale) == sectionLen,
                            QLIB_STATUS__INVALID_PARAMETER);
        }

        /*-------------------------------------------------------------------------------------------------*/
        /* Set the section mapping                                                                         */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_REG_GMT_SET_BASE(qlibContext, GMT, sectionIndex, sectionBaseTag);
        QLIB_REG_GMT_SET_LEN(qlibContext, GMT, sectionIndex, sectionLenTag);

        if (W77Q_SEC_SIZE_SCALE(qlibContext) != 0u)
        {
            QLIB_REG_GMT_SET_SCALE(GMT, sectionIndex, sectionLenScale);
        }
        else
        {
            QLIB_REG_GMT_SET_ENABLE(GMT, sectionIndex, (U8)(sectionLen != 0u));
        }
    }

    *gmtChanged = (memcmp(GMT.asArray, GMT_orig.asArray, sizeof(GMT_T)) == 0) ? FALSE : TRUE;
    if (*gmtChanged == TRUE)
    {
        U32 numCommands = 0;
        U32 numRetries  = (Q3_BYPASS_HW_ISSUE_SET_CMD_FAIL(qlibContext) == 1u ? SET_CMD_HW_BYPASS_NUM_RETRIES : 1u);
        /*-------------------------------------------------------------------------------------------------*/
        /* Increase the version value                                                                      */
        /*-------------------------------------------------------------------------------------------------*/
        ver = QLIB_REG_GMT_GET_VER(GMT) + 1u;
        QLIB_REG_GMT_SET_VER(GMT, ver);

        /*-------------------------------------------------------------------------------------------------*/
        /* Write the new Global Mapping Table (GMT)                                                        */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(
            QLIB_SEC_OpenSessionInternal_L(qlibContext, (QLIB_KID_T)QLIB_KID__DEVICE_MASTER, deviceMasterKey, FALSE));
        do
        {
            ret = QLIB_CMD_PROC__set_GMT(qlibContext, &GMT);
            numCommands++;
        } while ((ret == QLIB_STATUS__DEVICE_SYSTEM_ERR) && (numCommands < numRetries));
        QLIB_STATUS_RET_CHECK_GOTO(ret, ret, error_session);
        QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

        /*-------------------------------------------------------------------------------------------------*/
        /* Confirm operation success                                                                       */
        /*-------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_GMT_UNSIGNED(qlibContext, &GMT_test));
        QLIB_ASSERT_RET(0 == memcmp(GMT.asArray, GMT_test.asArray, sizeof(GMT_T)), QLIB_STATUS__COMMAND_FAIL);
    }

    ret = QLIB_STATUS__OK;

    goto exit;

error_session:
    QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));

exit:
    return ret;
}

static QLIB_STATUS_T QLIB_SEC_OpenSessionInternal_L(QLIB_CONTEXT_T* qlibContext,
                                                    QLIB_KID_T      kid,
                                                    const KEY_T     keyBuf,
                                                    BOOL            ignoreScrValidity)
{
    QLIB_STATUS_T ret;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Refresh the monotonic counter                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__synch_MC(qlibContext));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Open session                                                                                        */
    /*-----------------------------------------------------------------------------------------------------*/
    ret = QLIB_CMD_PROC__Session_Open(qlibContext, kid, keyBuf, TRUE, ignoreScrValidity);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Open session to a section also enables plain access to this section                                 */
    /*-----------------------------------------------------------------------------------------------------*/
    if (((QLIB_KID_T)QLIB_KID__FULL_ACCESS_SECTION == QLIB_KEY_MNGR__GET_KEY_TYPE(kid) ||
         (QLIB_KID_T)QLIB_KID__RESTRICTED_ACCESS_SECTION == QLIB_KEY_MNGR__GET_KEY_TYPE(kid)) &&
        (QLIB_STATUS__OK == ret || QLIB_STATUS__DEVICE_INTEGRITY_ERR == ret))
    {
        U8 sectionId   = QLIB_KEY_MNGR__GET_KEY_SECTION(kid);
        U8 plainAccess = QLIB_SECTION_PLAIN_EN_NO;

        if (sectionId < QLIB_NUM_OF_MAIN_SECTIONS)
        {
        }
        if (sectionId < QLIB_NUM_OF_MAIN_SECTIONS)
        {
            QLIB_POLICY_T policy = {0};

            QLIB_STATUS_RET_CHECK(
                QLIB_SEC_GetSectionConfiguration(qlibContext, (U32)sectionId, NULL, NULL, &policy, NULL, NULL, NULL));

            if (policy.plainAccessReadEnable == 1u && QLIB_STATUS__DEVICE_INTEGRITY_ERR != ret)
            {
                plainAccess |= QLIB_SECTION_PLAIN_EN_RD;
            }
            if (policy.plainAccessWriteEnable == 1u)
            {
                plainAccess |= QLIB_SECTION_PLAIN_EN_WR;
            }
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionId].plainEnabled = plainAccess;
        }
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Reseed prng for every session                                                                       */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_CRYPTO_Reseed(&qlibContext->prng);

    return ret;
}

/************************************************************************************************************
 * @brief This function updates the context about a closed session
 *
 * @param qlibContext   QLIB context
 * @param die           die in which the session is closed
************************************************************************************************************/
static void QLIB_SEC_MarkSessionClose_L(QLIB_CONTEXT_T* qlibContext, U8 die)
{
    (void)memset(qlibContext->dieState[die].keyMngr.sessionKey, 0xFF, sizeof(_128BIT));
    (void)memset(QLIB_HASH_BUF_GET__KEY(qlibContext->dieState[die].keyMngr.cmdContexArr[0].hashBuf), 0xFF, sizeof(_128BIT));
    (void)memset(QLIB_HASH_BUF_GET__KEY(qlibContext->dieState[die].keyMngr.cmdContexArr[1].hashBuf), 0xFF, sizeof(_128BIT));
    qlibContext->dieState[die].keyMngr.kid = (QLIB_KID_T)QLIB_KID__INVALID;
    qlibContext->dieState[die].mcInSync    = 0u;
}

/************************************************************************************************************
 * @brief This function closes the session
 *
 * @param qlibContext   QLIB context
 * @param revokePA      Set to TRUE in order to revoke plain-access privileges to restricted or full access section
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_CloseSessionInternal_L(QLIB_CONTEXT_T* qlibContext, BOOL revokePA)
{
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext), QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
    QLIB_ASSERT_RET((revokePA == FALSE) ||
                        (QLIB_KEY_MNGR__GET_KEY_TYPE(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid) ==
                         (QLIB_KID_T)QLIB_KID__FULL_ACCESS_SECTION) ||
                        (QLIB_KEY_MNGR__GET_KEY_TYPE(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid) ==
                         (QLIB_KID_T)QLIB_KID__RESTRICTED_ACCESS_SECTION),
                    QLIB_STATUS__INVALID_PARAMETER);

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__Session_Close(qlibContext, QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid, revokePA));
    QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief The function reads Winbond ID
 *
 * @param qlibContext  QLIB context
 * @param id           Returned Winbond ID
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_GetWID_L(QLIB_CONTEXT_T* qlibContext, QLIB_WID_T id)
{
    return QLIB_CMD_PROC__get_WID_UNSIGNED(qlibContext, id);
}

/************************************************************************************************************
 * @brief       This function reads the standard address size from device
 *
 * @param       qlibContext   QLIB state object
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_GetStdAddrSize_L(QLIB_CONTEXT_T* qlibContext)
{
    GMC_T    GMC;
    DEVCFG_T DEVCFG = 0;

    // Get GMC
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC));
    // Get DEVCFG
    DEVCFG = QLIB_REG_GMC_GET_DEVCFG(GMC);
    // Get SECT_SEL
    qlibContext->addrSize = (U32)READ_VAR_FIELD(DEVCFG, QLIB_REG_DEVCFG__SECT_SEL) + LOG2(QLIB_MIN_SECTION_SIZE);
    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function reads the Global Mapping Table and saves the sections sizes in context
 *
 * @param       qlibContext   QLIB state object
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_GetSectionsSize_L(QLIB_CONTEXT_T* qlibContext)
{
    GMT_T gmt;
    U32   sectionID;

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__get_GMT_UNSIGNED(qlibContext, &gmt));

    for (sectionID = 0; sectionID < QLIB_NUM_OF_MAIN_SECTIONS; sectionID++)
    {
        if (!QLIB_REG_GMT_IS_CONFIGURED(gmt))
        {
            // device was formatted and there is no section configuration yet
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].sizeTag = 0;
            if (W77Q_SEC_SIZE_SCALE(qlibContext) != 0u)
            {
                QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].scale = 0;
            }
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].enabled = 0;
        }
        else
        {
            QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].sizeTag =
                (U8)QLIB_REG_GMT_GET_LEN(qlibContext, gmt, sectionID);
            if (W77Q_SEC_SIZE_SCALE(qlibContext) != 0u)
            {
                QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].scale = (U8)QLIB_REG_GMT_GET_SCALE(gmt, sectionID);
                QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].enabled =
                    (QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].scale != 0u) ||
                            (QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].sizeTag != 0u)
                        ? 1u
                        : 0u;
            }
            else
            {
                QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].enabled = (U8)QLIB_REG_GMT_GET_ENABLE(gmt, sectionID);
            }
        }
    }

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function reads the watchdog configuration from the device
 *
 * @param       qlibContext   QLIB state object
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_GetWatchdogConfig_L(QLIB_CONTEXT_T* qlibContext)
{
    AWDTCFG_T AWDTCFG;

    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_AWDTCNFG(qlibContext, &AWDTCFG));
    qlibContext->watchdogIsSecure  = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__AUTH_WDT);
    qlibContext->watchdogSectionId = (U32)READ_VAR_FIELD(AWDTCFG, QLIB_REG_AWDTCFG__KID);

    return QLIB_STATUS__OK;
}


QLIB_STATUS_T QLIB_SEC_SecureLogRead(QLIB_CONTEXT_T* qlibContext, U8* buf, U32* addr, U32 sectionID, BOOL secure)
{
    U32 alignedLogEntry[QLIB_SEC_LOG_ENTRY_SIZE / sizeof(U32)];

    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != buf, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(NULL != addr, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((FALSE == secure) || (QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext)), QLIB_STATUS__DEVICE_SESSION_ERR);

    if (TRUE == secure)
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__LOG_SRD(qlibContext, addr, alignedLogEntry));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__LOG_PRD(qlibContext, sectionID, addr, alignedLogEntry));
    }

    (void)memcpy(buf, (U8*)alignedLogEntry, QLIB_SEC_LOG_ENTRY_SIZE);

    return QLIB_STATUS__OK;
}

QLIB_STATUS_T QLIB_SEC_SecureLogWrite(QLIB_CONTEXT_T* qlibContext, const U8* buf, U32 sectionID, U32 size, BOOL secure)
{
    U32 offset;
    U32 alignedLogEntry[QLIB_SEC_LOG_ENTRY_SIZE / sizeof(U32)];

    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != buf, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET((FALSE == secure) || (QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext)), QLIB_STATUS__DEVICE_SESSION_ERR);
    QLIB_ASSERT_RET(ALIGNED_TO(size, QLIB_SEC_LOG_ENTRY_SIZE), QLIB_STATUS__INVALID_DATA_SIZE);

    offset = 0;
    while (0u != size)
    {
        (void)memcpy((U8*)alignedLogEntry, (const U8*)(buf + offset), QLIB_SEC_LOG_ENTRY_SIZE);

        if (TRUE == secure)
        {
            QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__LOG_SAWR(qlibContext, alignedLogEntry));
        }
        else
        {
            QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__LOG_PWR(qlibContext, sectionID, alignedLogEntry));
        }
        offset += QLIB_SEC_LOG_ENTRY_SIZE;
        size -= QLIB_SEC_LOG_ENTRY_SIZE;
    }

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function performs initial section configuration
 *
 * @param[in,out]   qlibContext         QLIB state object
 * @param[in]       sectionIndex        Section configuration table
 * @param[in]       policy              Section policy to configure
 * @param[in]       crc                 Section CRC
 * @param[in]       digest              Section digest
 * @param[in]       fullAccessKey       Full-access key of the section
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_ConfigInitialSection_L(QLIB_CONTEXT_T*      qlibContext,
                                                     U32                  sectionIndex,
                                                     const QLIB_POLICY_T* policy,
                                                     U32                  crc,
                                                     U64                  digest,
                                                     const KEY_T          fullAccessKey)
{
    QLIB_STATUS_T ret       = QLIB_STATUS__OK;
    QLIB_KID_T    kid       = (QLIB_KID_T)QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__FULL_ACCESS_SECTION, sectionIndex);
    U64*          digestPtr = (((policy->digestIntegrity == 1u) ||
                       ((Q2_POLICY_AUTH_PROT_AC_BIT(qlibContext) != 0u) && (policy->digestIntegrityOnAccess == 1u)))
                                   ? &digest
                                   : NULL);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Must have fullAccessKey in order to write SCRn                                                      */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(QLIB_KEY_MNGR__IS_KEY_VALID(fullAccessKey), QLIB_STATUS__INVALID_PARAMETER);

    if (W77Q_SECURE_LOG(qlibContext) != 0u)
    {
        /****************************************************************************************************
         * Secure log section shall not be write protected, rollback protected or integrity protected
        ****************************************************************************************************/
        QLIB_ASSERT_RET((0u == policy->slog) ||
                            ((0u == policy->writeProt) && (0u == policy->rollbackProt) && (0u == policy->digestIntegrity) &&
                             (0u == policy->checksumIntegrity) && (0u == policy->digestIntegrityOnAccess)),
                        QLIB_STATUS__INVALID_PARAMETER);
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Perform (SCRn) write                                                                                */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSessionInternal_L(qlibContext, kid, fullAccessKey, TRUE));
    QLIB_STATUS_RET_CHECK_GOTO(QLIB_SEC_ConfigSection(qlibContext,
                                                      sectionIndex,
                                                      policy,
                                                      digestPtr,
                                                      policy->checksumIntegrity == 1u ? &crc : NULL,
                                                      NULL,
                                                      FALSE,
                                                      QLIB_SECTION_CONF_ACTION__RELOAD),
                               ret,
                               error_session);
    // After QLIB_SEC_ConfigSection the session is closed automatically

    return QLIB_STATUS__OK;

error_session:
    (void)QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE);
    return ret;
}

/************************************************************************************************************
 * @brief       This function checks if the section policy should be configured after GMT configuration or before
 *
 * @param[in,out]   qlibContext         QLIB state object
 * @param[in]       sectionIndex        Section index
 * @param[in]       config              Section configuration table
 *
 * @return      TRUE if section policy should be configured only after GMT. FALSE to configure before GMT
************************************************************************************************************/
static BOOL QLIB_SEC_ConfigSectionPolicyAfterSize_L(QLIB_CONTEXT_T*              qlibContext,
                                                    U32                          sectionIndex,
                                                    const QLIB_SECTION_CONFIG_T* config)
{
    if (QLIB_SECTION_ID_VAULT == sectionIndex)
    {
        /****************************************************************************************************
         * If the section was not configured yet - it needs to first be set in GMC.
         * If section rollback protection is enabled, size must be 128KB
         ****************************************************************************************************/
        QLIB_VAULT_RPMC_CONFIG_T sectionSize = QLIB_ACTIVE_DIE_STATE(qlibContext).vaultSize;
        if (sectionSize != QLIB_VAULT_128KB_RPMC_DISABLED)
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }
    else
    {
        /****************************************************************************************************
         * If the section was not configured yet - it needs to first be set in GMT.
         * If section rollback protection is enabled, the allowed section size is 2,4,8 or 16 blocks.
         * For secure log section, allowed section size is 1,2,4,8 or 16 blocks (Q3) or at least 2 blocks (Q2)
         *. Therefore, in case the section is currently configured with other block counts, first section 
         * size should be set and only then, the policy.
        ****************************************************************************************************/
        if (W77Q_SEC_SIZE_SCALE(qlibContext) != 0u)
        {
            U8   sizeTag     = QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionIndex].sizeTag;
            U8   scale       = QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionIndex].scale;
            BOOL mIsPowerOf2 = ((sizeTag & (sizeTag + 1u)) == 0u) ? TRUE : FALSE;

            if (((0u == sizeTag) && (0u == scale)) || (mIsPowerOf2 == FALSE))
            {
                return TRUE;
            }
            else
            {
                if (sizeTag == 0u)
                {
                    /***********************************************************************************************
                 * When current block count is 2,4,8,16 all functions related to the Section are supported
                 * so first set new policy
                ***********************************************************************************************/
                    U8 newSizeTag = (U8)QLIB_REG_SMRn__LEN_IN_BYTES_TO_TAG(qlibContext, config->size);
                    return ((newSizeTag & (newSizeTag + 1u)) == 0u) ? TRUE : FALSE;
                }
            }
            return FALSE;
        }
        else
        {
            if ((QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionIndex].enabled == 0u) ||
                (QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionIndex].sizeTag == 0u))
            {
                return TRUE;
            }
            return FALSE;
        }
    }
}

static QLIB_STATUS_T QLIB_SEC_HwAuthPlainAccess_Grant_L(QLIB_CONTEXT_T* qlibContext, U32 sectionID)
{
    QLIB_KID_T kid;
    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    if (NULL != QLIB_KEY_MNGR__GET_SECTION_KEY_RESTRICTED(qlibContext, sectionID))
    {
        kid = QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__RESTRICTED_ACCESS_SECTION, sectionID);
    }
    else if (NULL != QLIB_KEY_MNGR__GET_SECTION_KEY_FULL_ACCESS(qlibContext, sectionID))
    {
        kid = QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__FULL_ACCESS_SECTION, sectionID);
    }
    else
    {
        return QLIB_STATUS__DEVICE_PRIVILEGE_ERR;
    }

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__PA_grant(qlibContext, kid));

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function Opens a session to a section if it is not already open.
 *              If another session is open, the function closes it first and optionally returns its ID.
 *
 * @param[in,out]   qlibContext         QLIB state object
 * @param[in]       sectionID           Section to open
 * @param[in]       grant               TRUE to grant authenticated plain access. FALSE to revoke it.
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_SwGrantRevokePA_L(QLIB_CONTEXT_T* qlibContext, U32 sectionID, BOOL grant)
{
    U32 sectionOpened = QLIB_NUM_OF_SECTIONS; //invalid value
    U32 keyType       = (U32)QLIB_KID__INVALID;
    U8  temp          = 0;

    /*-----------------------------------------------------------------------------------------------------*/
    /* If session is open on section other then sectionID, we close it                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    if (QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext))
    {
        temp    = QLIB_KEY_MNGR__GET_KEY_TYPE(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid);
        keyType = (U32)temp;

        if ((U32)QLIB_KID__FULL_ACCESS_SECTION == keyType || (U32)QLIB_KID__RESTRICTED_ACCESS_SECTION == keyType)
        {
            temp          = QLIB_KEY_MNGR__GET_KEY_SECTION(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid);
            sectionOpened = (U32)temp;

            if (sectionOpened == sectionID)
            {
                if (grant == FALSE)
                {
                    QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, TRUE));
                }
                return QLIB_STATUS__OK;
            }

            if ((Q2_SESSION_CLOSE_NOT_SUPPORTED(qlibContext) == 0u) || (grant == TRUE))
            {
                QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSession(qlibContext, sectionOpened));
            }
        }
    }

    if ((Q2_SESSION_CLOSE_NOT_SUPPORTED(qlibContext) == 0u) || (grant == TRUE))
    {
        /*-------------------------------------------------------------------------------------------------*/
        /* Here no section is open, so we open the session to the section                                  */
        /*-------------------------------------------------------------------------------------------------*/
        if (QLIB_KEY_MNGR__IS_KEY_VALID(QLIB_KEY_MNGR__GET_SECTION_KEY_RESTRICTED(qlibContext, sectionID)))
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSession(qlibContext, sectionID, QLIB_SESSION_ACCESS_RESTRICTED));
        }
        else if (QLIB_KEY_MNGR__IS_KEY_VALID(QLIB_KEY_MNGR__GET_SECTION_KEY_FULL_ACCESS(qlibContext, sectionID)))
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSession(qlibContext, sectionID, QLIB_SESSION_ACCESS_FULL));
        }
        else
        {
            return QLIB_STATUS__DEVICE_PRIVILEGE_ERR;
        }
    }

    if (grant == TRUE)
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, FALSE));
    }
    else if (Q2_SESSION_CLOSE_NOT_SUPPORTED(qlibContext) == 0u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_CloseSessionInternal_L(qlibContext, TRUE));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__init_section_PA(qlibContext, sectionID));
        QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);
        QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled = QLIB_SECTION_PLAIN_EN_NO;
    }
    /*-----------------------------------------------------------------------------------------------------*/
    /* If session X was open before it must be reopened                                                    */
    /*-----------------------------------------------------------------------------------------------------*/
    if (sectionOpened != QLIB_NUM_OF_SECTIONS)
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC_OpenSession(qlibContext,
                                                   sectionOpened,
                                                   keyType == (U32)QLIB_KID__FULL_ACCESS_SECTION
                                                       ? QLIB_SESSION_ACCESS_FULL
                                                       : QLIB_SESSION_ACCESS_RESTRICTED));
    }

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This function verifies that all plain access sections are accessible according to the configured address size
 *
 * @param[in,out]   qlibContext         QLIB state object
 * @param[in]       addrSizeConf        Address size configuration
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_VerifyAddressSizeConfig_L(QLIB_CONTEXT_T* qlibContext, const QLIB_STD_ADDR_SIZE_T* addrSizeConf)
{
    U8            sectionIndex = 0;
    QLIB_POLICY_T policy;

    for (sectionIndex = 0; sectionIndex < QLIB_NUM_OF_MAIN_SECTIONS; sectionIndex++)
    {
        if (QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionIndex].enabled == 1u)
        {
            QLIB_STATUS_RET_CHECK(
                QLIB_SEC_GetSectionConfiguration(qlibContext, sectionIndex, NULL, NULL, &policy, NULL, NULL, NULL));

            if (policy.plainAccessReadEnable == 1u || policy.plainAccessWriteEnable == 1u)
            {
                QLIB_ASSERT_RET(QLIB_CALC_SECTION_SIZE(qlibContext, sectionIndex) <=
                                    _QLIB_MAX_LEGACY_OFFSET_BY_ADDR_SIZE(
                                        QLIB_STD_ADDR_LEN_TO_ADDRESS_OFFSET_SIZE(addrSizeConf->addrLen)),
                                QLIB_STATUS__INVALID_PARAMETER);
            }
        }
    }
    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief       This routine configures Flash interface configuration for secure commands.
 *              This function do not handle switching from or to QPI mode,
 *              this is assumed to be completed by the standard module, see @ref QLIB_STD_SetInterface.
 *
 * @param       qlibContext   qlib context object
 * @param[in]   format        SPI bus mode
 *
************************************************************************************************************/
static void
    QLIB_SEC_SetInterface_L(QLIB_CONTEXT_T* qlibContext, QLIB_BUS_MODE_T format)
{
    QLIB_BUS_MODE_T secureFormat;
    /*-----------------------------------------------------------------------------------------------------*/
    /* Match the format with the supported formats for secure commands                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    switch (format)
    {
#ifdef QLIB_SUPPORT_DUAL_SPI
        case QLIB_BUS_MODE_1_1_2:
        case QLIB_BUS_MODE_1_2_2:
            secureFormat = (Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u) && (qlibContext->ctagMode == 1u) ? QLIB_BUS_MODE_1_2_2
                                                                                                     : QLIB_BUS_MODE_1_1_2;
            break;
#endif
        case QLIB_BUS_MODE_1_1_4:
        case QLIB_BUS_MODE_1_4_4:
            secureFormat = (((Q2_DEVCFG_CTAG_MODE(qlibContext) != 0u) && (qlibContext->ctagMode == 1u)) ||
                            (W77Q_SUPPORT__1_1_4_SPI(qlibContext) == 0u))
                               ? QLIB_BUS_MODE_1_4_4
                               : QLIB_BUS_MODE_1_1_4;
            break;
        default:
            secureFormat = format;
            break;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Update the globals                                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    qlibContext->busInterface.secureCmdsFormat = secureFormat;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Config OPs                                                                                          */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_SEC_configOPS(qlibContext);
}

QLIB_STATUS_T QLIB_SEC_InitCtagMode(QLIB_CONTEXT_T* qlibContext)
{
    GMC_T    GMC;
    DEVCFG_T DEVCFG;

    if (Q2_DEVCFG_CTAG_MODE(qlibContext) == 0u)
    {
        return QLIB_STATUS__NOT_SUPPORTED;
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC));
        DEVCFG = QLIB_REG_GMC_GET_DEVCFG(GMC);
        if (DEVCFG == 0xFFFFFFFFu)
        {
            // Flash is after format, so ctag mode is 0
            qlibContext->ctagMode = 0;
        }
        else
        {
            qlibContext->ctagMode = (U32)READ_VAR_FIELD(DEVCFG, QLIB_REG_DEVCFG__CTAG_MODE);
        }

        return QLIB_STATUS__OK;
    }
}

U8 QLIB_SEC_BusModeToSecInstLines(QLIB_BUS_MODE_T busMode)
{
    U8 secureInstruction = 0;

    switch (busMode)
    {
        case QLIB_BUS_MODE_1_1_1:
            secureInstruction = W77Q_SEC_INST__SINGLE;
            break;
        case QLIB_BUS_MODE_1_1_2:
        case QLIB_BUS_MODE_1_2_2:
            secureInstruction = W77Q_SEC_INST__DUAL;
            break;
        case QLIB_BUS_MODE_1_1_4:
        case QLIB_BUS_MODE_1_4_4:
        case QLIB_BUS_MODE_4_4_4:
            secureInstruction = W77Q_SEC_INST__QUAD;
            break;
#ifndef Q2_API
        case QLIB_BUS_MODE_1_8_8:
        case QLIB_BUS_MODE_8_8_8:
            secureInstruction = W77Q_SEC_INST__OCTAL;
            break;
#endif
        default:
            secureInstruction = W77Q_SEC_INST__INVALID;
            break;
    }
    return secureInstruction;
}

#ifndef EXCLUDE_LMS
/************************************************************************************************************
 * @brief       This function writes LMS data structure to the flash.
 *
 * @param       qlibContext   QLIB state object
 * @param       buf           Pointer to input data
 * @param       sectionID     Section index
 * @param       size          Data size
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_LMS_Write_L(QLIB_CONTEXT_T* qlibContext, const U32* buf, U32 sectionID, U32 size)
{
    U32           iterSize = MIN(size, QLIB_SEC_LMS_PAGE_MAX_SIZE);
    U32           offset   = 0;
    QLIB_STATUS_T ret      = QLIB_STATUS__OK;
    QLIB_KID_T    kid      = QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__SECTION_LMS, sectionID);

    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Error checking
    ********************************************************************************************************/
    QLIB_ASSERT_RET(NULL != buf, QLIB_STATUS__INVALID_PARAMETER);
    QLIB_ASSERT_RET(ALIGNED_TO(size, QLIB_SEC_LMS_PAGE_WORD_SIZE), QLIB_STATUS__INVALID_PARAMETER);

    while (0u != size)
    {
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_CMD_PROC__LMS_write(qlibContext, kid, offset, buf, iterSize), ret, finish);

        /****************************************************************************************************
         * Prepare pointers for next iteration
        ****************************************************************************************************/
        size     = size - iterSize;
        buf      = buf + (iterSize / sizeof(U32));
        offset   = offset + QLIB_SEC_LMS_PAGE_MAX_SIZE;
        iterSize = MIN(size, QLIB_SEC_LMS_PAGE_MAX_SIZE);
    }

finish:
    return ret;
}

/************************************************************************************************************
 * @brief       This function initiates execution of an LMS Command, after the entire LMS Command Data Structure was received by the flash
 *
 * @param       qlibContext   QLIB state object
 * @param       sectionID     Section index
 * @param       digest        Digest of the LMS command data structure
 * @param       reset         Reset the device after command execution
 * @param       grantPA       Grant plain access to the section after command execution
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_LMS_Execute_L(QLIB_CONTEXT_T* qlibContext,
                                            U32             sectionID,
                                            const _64BIT    digest,
                                            BOOL            reset,
                                            BOOL            grantPA)
{
    QLIB_KID_T    kid = QLIB_KEY_MNGR__KID_WITH_SECTION(QLIB_KID__SECTION_LMS, sectionID);
    QLIB_STATUS_T ret;
    U8            sectionKidToReopen = (U8)QLIB_KID__INVALID;
    U32           numCommands        = 0;
    U32           numRetries         = (Q3_BYPASS_HW_ISSUE_SET_CMD_FAIL(qlibContext) == 1u ? SET_CMD_HW_BYPASS_NUM_RETRIES : 1u);

    /********************************************************************************************************
     * Secure command is ignored if power is down or suspended
    ********************************************************************************************************/
    QLIB_ASSERT_RET(QLIB_ACTIVE_DIE_STATE(qlibContext).isPoweredDown == 0u, QLIB_STATUS__COMMAND_IGNORED);
    QLIB_ASSERT_RET(qlibContext->isSuspended == 0u, QLIB_STATUS__COMMAND_IGNORED);

    /********************************************************************************************************
     * Save currently open session
    ********************************************************************************************************/
    if (QLIB_KEY_MNGR__SESSION_IS_OPEN(qlibContext))
    {
        if ((QLIB_KID_T)QLIB_KID__FULL_ACCESS_SECTION ==
                QLIB_KEY_MNGR__GET_KEY_TYPE(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid) ||
            (QLIB_KID_T)QLIB_KID__RESTRICTED_ACCESS_SECTION ==
                QLIB_KEY_MNGR__GET_KEY_TYPE(QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid))
        {
            sectionKidToReopen = QLIB_ACTIVE_DIE_STATE(qlibContext).keyMngr.kid;
        }
    }

    /********************************************************************************************************
     * Execute the command
    ********************************************************************************************************/
    do
    {
        ret = QLIB_CMD_PROC__LMS_execute(qlibContext, kid, digest, reset, grantPA);
        numCommands++;
    } while ((ret == QLIB_STATUS__DEVICE_SYSTEM_ERR) && (numCommands < numRetries));

    if (ret == QLIB_STATUS__OK)
    {
        if (reset == TRUE)
        {
            QLIB_STATUS_RET_CHECK(QLIB_SEC_SyncAfterFlashReset(qlibContext));
        }
        else
        {
            QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);
            // update plain access state
            if (sectionID < QLIB_SECTION_ID_VAULT)
            {
                QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled = QLIB_SECTION_PLAIN_EN_NO;
                if (grantPA == TRUE)
                {
                    QLIB_POLICY_T policy;
                    (void)memset(&policy, 0, sizeof(QLIB_POLICY_T));
                    QLIB_STATUS_RET_CHECK(
                        QLIB_SEC_GetSectionConfiguration(qlibContext, sectionID, NULL, NULL, &policy, NULL, NULL, NULL));
                    if (policy.authPlainAccess == 0u)
                    {
                        QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled |=
                            ((policy.plainAccessReadEnable == 1u) ? QLIB_SECTION_PLAIN_EN_RD : 0u);
                        QLIB_ACTIVE_DIE_STATE(qlibContext).sectionsState[sectionID].plainEnabled |=
                            ((policy.plainAccessWriteEnable == 1u) ? QLIB_SECTION_PLAIN_EN_WR : 0u);
                    }
                }
            }
        }
    }

    if (READ_VAR_FIELD(QLIB_GET_LAST_SEC_STATUS_FIELD(qlibContext), QLIB_REG_SSR__SES_READY) == 0u)
    {
        /****************************************************************************************************
         * Reopen the session since LMS_EXEC closes the session in flash after integrity check pass
        ****************************************************************************************************/
        QLIB_SEC_MarkSessionClose_L(qlibContext, qlibContext->activeDie);
        if (sectionKidToReopen != (U8)QLIB_KID__INVALID)
        {
            U8 sectIdToReopen = QLIB_KEY_MNGR__GET_KEY_SECTION(sectionKidToReopen);
            QLIB_STATUS_RET_CHECK(
                QLIB_SEC_OpenSession(qlibContext,
                                     (U32)sectIdToReopen,
                                     (QLIB_KID_T)QLIB_KID__FULL_ACCESS_SECTION == QLIB_KEY_MNGR__GET_KEY_TYPE(sectionKidToReopen)
                                         ? QLIB_SESSION_ACCESS_FULL
                                         : QLIB_SESSION_ACCESS_RESTRICTED));
        }
    }
    QLIB_STATUS_RET_CHECK(ret);

    return QLIB_STATUS__OK;
}
#endif

/************************************************************************************************************
 * @brief       This function reads the GMC register and updates vault size in context
 *
 * @param       qlibContext   QLIB state object
 *
 * @return      QLIB_STATUS__OK on success or QLIB_STATUS__[ERROR] otherwise
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_GetVaultSize_L(QLIB_CONTEXT_T* qlibContext)
{
    GMC_T    GMC;
    DEVCFG_T DEVCFG;
    U32      vaultSize;
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC));
    DEVCFG                                       = QLIB_REG_GMC_GET_DEVCFG(GMC);
    vaultSize                                    = (U32)READ_VAR_FIELD(DEVCFG, QLIB_REG_DEVCFG__VAULT_MEM);
    QLIB_ACTIVE_DIE_STATE(qlibContext).vaultSize = (QLIB_VAULT_RPMC_CONFIG_T)vaultSize;

    return QLIB_STATUS__OK;
}

#if !defined EXCLUDE_LMS_ATTESTATION && !defined Q2_API
/************************************************************************************************************
 * @brief This function calculates the OTS signature for give message hash using internal flash state
 *
 * @param       qlibContext    QLIB state object
 * @param[in]   msgHash        Message hash to sign
 * @param[out]  otsSig         OTS signature
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_LMS_Attest_Sign_L(QLIB_CONTEXT_T*          qlibContext,
                                                const LMS_ATTEST_CHUNK_T msgHash,
                                                LMS_ATTEST_OTS_SIG_T     otsSig)
{
    U32 i;
    U8  digit;
    U32 chainId;

    for (i = 0; i < LMS_ATTEST_PARAM_P; ++i)
    {
        if (i < LMS_ATTEST_NUM_OF_CHAINS)
        {
            digit = QLIB_LMS_ATTEST_COEF(msgHash, i);
        }
        else
        {
            digit = 0;
        }

        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__OTS_SIGN_DIGIT(qlibContext, digit, &chainId, otsSig[i]));
    }
    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief This function calculates the root of Merkle tree, optionally populating node cache
 *
 * @param           qlibContext        QLIB state object
 * @param[in]       keyId              LMS key id
 * @param[in]       rootIndex          Required root index
 * @param[in,out]   pubCache           Optional Merkle tree cache
 * @param[in]       pubCacheLen        Merkle tree cache size
 * @param[out]      root               Output Merkle tree root
 * @param[in]       cacheRO            if true, cache used in read-only mode
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_LMS_Attest_GetRoot_L(QLIB_CONTEXT_T*           qlibContext,
                                                   const LMS_ATTEST_KEY_ID_T keyId,
                                                   U32                       rootIndex,
                                                   LMS_ATTEST_CHUNK_T        pubCache[],
                                                   U32                       pubCacheLen,
                                                   LMS_ATTEST_CHUNK_T        root,
                                                   BOOL                      cacheRO)
{
    _256BIT hashOutput;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error check                                                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_ASSERT_RET(rootIndex < QLIB_LMS_ATTEST_ALL_NODES, QLIB_STATUS__SECURITY_ERR);

    /*-----------------------------------------------------------------------------------------------------*/
    /* Check if node is cached                                                                             */
    /*-----------------------------------------------------------------------------------------------------*/
    if ((pubCache != NULL) && (rootIndex < pubCacheLen) && (QLIB_SEC_LMS_ATTEST_NODE_IS_EMPTY(pubCache[rootIndex]) == FALSE))
    {
        (void)memcpy(root, pubCache[rootIndex], sizeof(LMS_ATTEST_CHUNK_T));
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* if not cached - calculate                                                                           */
    /*-----------------------------------------------------------------------------------------------------*/
    else
    {
        U32                             nodesToHash[QLIB_LMS_ATTEST_TREE_HEIGHT + 1u];
        U32                             nodesToHashSize;
        QLIB_SEC_LMS_ATTEST_HASH_NODE_T nodesHashed[QLIB_LMS_ATTEST_TREE_HEIGHT + 1u];
        U32                             nodesHashedSize = 0;
        LMS_ATTEST_CHUNK_T              nodePubKey;
        U32                             nodeIndex;

        nodesToHash[0]  = rootIndex;
        nodesToHashSize = 1u;
        while (nodesToHashSize > 0u)
        {
            // pop one node from stack
            nodeIndex = nodesToHash[nodesToHashSize - 1u];
            nodesToHashSize -= 1u;
            if (nodeIndex >= QLIB_LMS_ATTEST_LEAF_NODES_START_INDEX)
            {
                BOOL loopExit = FALSE;
                // this is a leaf
                QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Attest_GetLeaf_L(qlibContext, keyId, nodeIndex, nodePubKey));
                do
                {
                    // add to hashed nodes stack
                    QLIB_ASSERT_RET(nodesHashedSize <= QLIB_LMS_ATTEST_TREE_HEIGHT, QLIB_STATUS__SYSTEM_IN_INCORRECT_STATE);
                    nodesHashed[nodesHashedSize].nodeIndex = nodeIndex;
                    (void)memcpy(nodesHashed[nodesHashedSize].hash, nodePubKey, sizeof(LMS_ATTEST_CHUNK_T));
                    nodesHashedSize += 1u;

                    // Add result to cache
                    if ((pubCache != NULL) && (nodeIndex < pubCacheLen) && (cacheRO == FALSE))
                    {
                        (void)memcpy(pubCache[nodeIndex], nodePubKey, sizeof(LMS_ATTEST_CHUNK_T));
                    }

                    if ((nodesHashedSize > 1u) &&
                        (nodesHashed[nodesHashedSize - 1u].nodeIndex == (nodesHashed[nodesHashedSize - 2u].nodeIndex + 1u)))
                    {
                        QLIB_LMS_ATTEST_NODE_T node;
                        // if the last 2 nodes in stack are brothers, compute their father node
                        nodeIndex = nodesHashed[nodesHashedSize - 1u].nodeIndex >> 1u;

                        ///Calculate node hash
                        (void)memcpy((U8*)node.keyId, keyId, sizeof(LMS_ATTEST_KEY_ID_T));
                        node.q      = REVERSE_BYTES_32_BIT(nodeIndex);
                        node.d_intr = LMS_ATTEST_D_INTR;
                        (void)memcpy(node.left, nodesHashed[nodesHashedSize - 2u].hash, sizeof(LMS_ATTEST_CHUNK_T));
                        (void)memcpy(node.right, nodesHashed[nodesHashedSize - 1u].hash, sizeof(LMS_ATTEST_CHUNK_T));
                        QLIB_STATUS_RET_CHECK(QLIB_HASH(hashOutput, &node, sizeof(QLIB_LMS_ATTEST_NODE_T)));
                        (void)memcpy(nodePubKey, (U8*)hashOutput, sizeof(LMS_ATTEST_CHUNK_T));

                        // pop
                        nodesHashedSize -= 2u;
                    }
                    else
                    {
                        loopExit = TRUE;
                    }
                } while (loopExit == FALSE);
            }
            else
            {
                // internal node - add sons to stack
                nodesToHash[nodesToHashSize++] = 2u * nodeIndex + 1u;
                nodesToHash[nodesToHashSize++] = 2u * nodeIndex;
            }
        }

        // set result
        (void)memcpy(root, nodePubKey, sizeof(LMS_ATTEST_CHUNK_T));
    }

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief This function calculates a public leaf of Merkle tree
 *
 * @param      qlibContext   QLIB state object
 * @param[in]  keyId         key id
 * @param[in]  leafIndex     Leaf index
 * @param[out] leafHash      Output public leaf hash
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_LMS_Attest_GetLeaf_L(QLIB_CONTEXT_T*           qlibContext,
                                                   const LMS_ATTEST_KEY_ID_T keyId,
                                                   U32                       leafIndex,
                                                   LMS_ATTEST_CHUNK_T        leafHash)
{
    QLIB_LMS_ATTEST_LEAF_T leaf;
    U32                    q;
    _256BIT                hashOutput;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Error check                                                                                         */
    /*-----------------------------------------------------------------------------------------------------*/
    if (leafIndex < QLIB_LMS_ATTEST_LEAF_NODES_START_INDEX)
    {
        return QLIB_STATUS__SECURITY_ERR;
    }

    /*-----------------------------------------------------------------------------------------------------*/
    /* Get leaf number                                                                                     */
    /*-----------------------------------------------------------------------------------------------------*/
    q = leafIndex - QLIB_LMS_ATTEST_LEAF_NODES_START_INDEX;

    /*-----------------------------------------------------------------------------------------------------*/
    /* Get OTS public key                                                                                  */
    /*-----------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC_LMS_Attest_GetLeafPublicKey_L(qlibContext, q, leaf.otsPub));

    /*-----------------------------------------------------------------------------------------------------*/
    /* Calculate leaf hash                                                                                 */
    /*-----------------------------------------------------------------------------------------------------*/
    (void)memcpy((U8*)leaf.keyId, keyId, sizeof(LMS_ATTEST_KEY_ID_T));
    leaf.nodeIndex = REVERSE_BYTES_32_BIT(leafIndex);
    leaf.d_leaf    = LMS_ATTEST_D_LEAF;
    QLIB_STATUS_RET_CHECK(QLIB_HASH(hashOutput, &leaf, sizeof(QLIB_LMS_ATTEST_LEAF_T)));
    (void)memcpy(leafHash, (U8*)hashOutput, sizeof(LMS_ATTEST_CHUNK_T));

    return QLIB_STATUS__OK;
}

/************************************************************************************************************
 * @brief This function calculates OTS public key for given leaf index
 *
 * @param       qlibContext  QLIB state object
 * @param[in]   leafNum      Leaf number that goes into OTS hash calculations
 * @param[out]  otsPubKey    OTS public key for the given @p leafIndex
************************************************************************************************************/
static QLIB_STATUS_T QLIB_SEC_LMS_Attest_GetLeafPublicKey_L(QLIB_CONTEXT_T*    qlibContext,
                                                            U32                leafNum,
                                                            LMS_ATTEST_CHUNK_T otsPubKey)
{
    QLIB_LMS_ATTEST_PUB_BUF_T pubBuf;
    U32                       i;
    _256BIT                   hashOutput;
    _192BIT                   chunk;

    (void)memset(&pubBuf, 0, sizeof(pubBuf));
    for (i = 0; i < LMS_ATTEST_PARAM_P; ++i)
    {
        QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__OTS_PUB_CHAIN(qlibContext, leafNum, (U16)i, chunk));
        (void)memcpy((void*)pubBuf.pubChunks[i], (void*)chunk, sizeof(LMS_ATTEST_CHUNK_T));
    }

    QLIB_STATUS_RET_CHECK(QLIB_CMD_PROC__OTS_GET_ID(qlibContext, NULL, pubBuf.keyId));

    pubBuf.q      = REVERSE_BYTES_32_BIT(leafNum);
    pubBuf.d_pblc = LMS_ATTEST_D_PBLC;
    QLIB_STATUS_RET_CHECK(QLIB_HASH(hashOutput, &pubBuf, sizeof(QLIB_LMS_ATTEST_PUB_BUF_T)));
    (void)memcpy(otsPubKey, (U8*)hashOutput, sizeof(LMS_ATTEST_CHUNK_T));

    return QLIB_STATUS__OK;
}
#endif
