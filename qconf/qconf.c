/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2019 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qconf.c
* @brief      This file contains (QCONF)[qconf.html] code
*
* ### project qlib
*
-----------------------------------------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------
                                                  INCLUDES
-------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------*/
#define NO_Q2_API_H
#include "qconf.h"
#include "qlib_utils_crc.h"


/*-----------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------
                                             INTERFACE FUNCTIONS
-------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------*/

QLIB_STATUS_T QCONF_Config(QLIB_CONTEXT_T* qlibContext, const QCONF_T* configHeader)
{
    QLIB_STATUS_T ret;
    QCONF_T       ramConfigHeader;
    U32           section;
    U32           dieId;
    /*-------------------------------------------------------------------------------------------------------
     Verify the header
    -------------------------------------------------------------------------------------------------------*/
    if (QCONF_MAGIC_WORD != configHeader->magicWord)
    {
        return QLIB_STATUS__OK;
    }

    /*-------------------------------------------------------------------------------------------------------
     Read the flash configuration header and save in RAM
    -------------------------------------------------------------------------------------------------------*/
    (void)memcpy(&ramConfigHeader, configHeader, sizeof(QCONF_T));

    /*-------------------------------------------------------------------------------------------------------
     Variables initialization
    -------------------------------------------------------------------------------------------------------*/

    /*-------------------------------------------------------------------------------------------------------
     Load all keys
    -------------------------------------------------------------------------------------------------------*/
    for (dieId = QLIB_NUM_OF_DIES; 0u != dieId--;)
    {
#if QLIB_NUM_OF_DIES > 1
        QLIB_STATUS_RET_CHECK(QLIB_SetActiveDie(qlibContext, dieId));
#endif
        for (section = 0; section < ((W77Q_VAULT(qlibContext) != 0u) ? QLIB_NUM_OF_SECTIONS : QLIB_NUM_OF_MAIN_SECTIONS);
             section++)
        {
#ifndef Q2_API
            if (0u != ramConfigHeader.sectionTable[dieId][section].size)
            {
                QLIB_STATUS_RET_CHECK_GOTO(QLIB_LoadKey(qlibContext,
                                                        section,
                                                        ramConfigHeader.otc.fullAccessKeys[dieId][section],
                                                        TRUE),
                                           ret,
                                           exit);
            }
#else
            if (0u != ramConfigHeader.sectionTable[section].size)
            {
                QLIB_STATUS_RET_CHECK_GOTO(QLIB_LoadKey(qlibContext, section, ramConfigHeader.otc.fullAccessKeys[section], TRUE),
                                           ret,
                                           exit);
            }
#endif
        }
    }
#ifndef QCONF_STRUCT_ON_RAM
    /*-------------------------------------------------------------------------------------------------------
     Wipe out all the keys and the magic number in the header. This makes the header sealed.
    -------------------------------------------------------------------------------------------------------*/
    {
        QCONF_T wipedConfigurations = {0};
        QCONF_T verifyConfigurations;
        U32     headerOffsetInFlash;

        QLIB_ASSERT_RET(MAX_U32 > (((UPTR)configHeader) - ramConfigHeader.flashBaseAddr), QLIB_STATUS__INVALID_PARAMETER);
        headerOffsetInFlash = (U32)(((UPTR)configHeader) - ramConfigHeader.flashBaseAddr);

        QLIB_STATUS_RET_CHECK_GOTO(QLIB_Write(qlibContext,
                                              (U8*)&wipedConfigurations,
                                              0,
                                              headerOffsetInFlash,
                                              sizeof(QCONF_T),
                                              FALSE),
                                   ret,
                                   exit);

        /*---------------------------------------------------------------------------------------------------
         Verify that the keys were removed
        ---------------------------------------------------------------------------------------------------*/
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_Read(qlibContext,
                                             (U8*)&verifyConfigurations,
                                             0,
                                             headerOffsetInFlash,
                                             sizeof(QCONF_T),
                                             FALSE,
                                             FALSE),
                                   ret,
                                   exit);
        if (0 != memcmp((U8*)&wipedConfigurations, (U8*)&verifyConfigurations, sizeof(QCONF_T)))
        {
            ret = QLIB_STATUS__COMMAND_FAIL;
            goto exit;
        }
    }
#endif // QCONF_STRUCT_ON_RAM

    /*-------------------------------------------------------------------------------------------------------
     Write the configuration to the flash device
    -------------------------------------------------------------------------------------------------------*/

    {
        const QLIB_LMS_KEY_ARRAY_T* pLmsKeys;
        U32*                        preProvisionedMasterKey;
#ifndef Q2_API
        pLmsKeys = (W77Q_SUPPORT_LMS(qlibContext) != 0u) ? (const QLIB_LMS_KEY_ARRAY_T*)(ramConfigHeader.otc.lmsKeys) : NULL;
        preProvisionedMasterKey =
            (W77Q_PRE_PROV_MASTER_KEY(qlibContext) != 0u) ? (ramConfigHeader.otc.preProvisionedMasterKey) : NULL;
#else
        pLmsKeys = NULL;
        preProvisionedMasterKey = NULL;
#endif
        QLIB_STATUS_RET_CHECK_GOTO(QLIB_ConfigDevice(qlibContext,
                                                     ramConfigHeader.otc.deviceMasterKey,
                                                     ramConfigHeader.otc.deviceSecretKey,
                                                     (const QLIB_SECTION_CONFIG_TABLE_T*)(ramConfigHeader.sectionTable),
                                                     (const KEY_ARRAY_T*)(ramConfigHeader.otc.restrictedKeys),
                                                     (const KEY_ARRAY_T*)(ramConfigHeader.otc.fullAccessKeys),
                                                     pLmsKeys,
                                                     preProvisionedMasterKey,
                                                     &(ramConfigHeader.watchdogDefault),
                                                     &(ramConfigHeader.deviceConf),
                                                     ramConfigHeader.otc.suid),
                                   ret,
                                   exit);
    }

exit:
    /*-------------------------------------------------------------------------------------------------------
     Close the session on error
    -------------------------------------------------------------------------------------------------------*/
    if (QLIB_STATUS__OK != ret)
    {
        (void)QLIB_CloseSession(qlibContext, section);
    }

    /*-------------------------------------------------------------------------------------------------------
     Remove all keys
    -------------------------------------------------------------------------------------------------------*/
    (void)memset(&ramConfigHeader, 0x0, sizeof(QCONF_T));
    for (dieId = QLIB_NUM_OF_DIES; 0u != dieId--;)
    {
#if QLIB_NUM_OF_DIES > 1
        (void)QLIB_SetActiveDie(qlibContext, dieId);
#endif
        for (section = 0; section < ((W77Q_VAULT(qlibContext) != 0u) ? QLIB_NUM_OF_SECTIONS : QLIB_NUM_OF_MAIN_SECTIONS);
             section++)
        {
            (void)QLIB_RemoveKey(qlibContext, section, TRUE);
        }
    }
    return ret;
}

/************************************************************************************************************
 * @brief       This routine initializes the sectionTable and device configuration for legacy flash.
 *
 * @param[in]   qlibContext   [QLIB internal state](md_definitions.html#DEF_CONTEXT)
 * @param[out]  sectionTable  pointer to the flash section configuration table
 * @param[out]  deviceConf    pointer to the device configuration
 *
************************************************************************************************************/
static void QCONF_initLegacyConfig_L(QLIB_CONTEXT_T*             qlibContext,
                                     QLIB_SECTION_CONFIG_TABLE_T sectionTable[QLIB_NUM_OF_DIES],
                                     QLIB_DEVICE_CONF_T*         deviceConf)
{
    U32 dieId = 0;

    // map section 0,1 for legacy access to all the flash size
#define FLASH_DIE_LEGACY_SECTION_TABLE               \
    {                                                \
        /* Section 0 */                              \
        {                                            \
            0, /* baseAddr */                        \
            0, /* size */                            \
            {                                        \
                /* policy */                         \
                0, /* digestIntegrity */             \
                0, /* checksumIntegrity */           \
                0, /* writeProt */                   \
                0, /* rollbackProt */                \
                1, /* plainAccessWriteEnable */      \
                1, /* plainAccessReadEnable */       \
                0, /* authPlainAccess */             \
                0, /* digestIntegrityOnAccess */     \
                0, /* slog */                        \
            },                                       \
            0, /* section crc */                     \
            0, /* section digest */                  \
        },     /* Section 1 */                       \
            {                                        \
                0, /* baseAddr */                    \
                0, /* size */                        \
                {                                    \
                    /* policy */                     \
                    0, /* digestIntegrity */         \
                    0, /* checksumIntegrity */       \
                    0, /* writeProt */               \
                    0, /* rollbackProt */            \
                    1, /* plainAccessWriteEnable */  \
                    1, /* plainAccessReadEnable */   \
                    0, /* authPlainAccess */         \
                    0, /* digestIntegrityOnAccess */ \
                    0, /* slog */                    \
                },                                   \
                0, /* section crc */                 \
                0, /* section digest */              \
            },                                       \
            {0}, /* Section 2 */                     \
            {0}, /* Section 3 */                     \
            {0}, /* Section 4 */                     \
            {0}, /* Section 5 */                     \
            {0}, /* Section 6 */                     \
            {0}, /* Section 7 */                     \
        /* Section 8 (vault) */                      \
        {                                            \
            MAX_U32, /* baseAddr */                  \
                0,   /* size */                      \
                {0}, /* policy */                    \
                0,   /* section crc */               \
                0,   /* section digest */            \
        }                                            \
    }

    QLIB_SECTION_CONFIG_TABLE_T sectionTable_l[QLIB_NUM_OF_DIES] =
    { FLASH_DIE_LEGACY_SECTION_TABLE, // die 0
#if QLIB_NUM_OF_DIES > 1
      FLASH_DIE_LEGACY_SECTION_TABLE, //die 1
#endif
#if QLIB_NUM_OF_DIES == 4
      FLASH_DIE_LEGACY_SECTION_TABLE, //die 2
      FLASH_DIE_LEGACY_SECTION_TABLE, //die 3
#endif
    };

    QLIB_DEVICE_CONF_T deviceConf_l = {
        {{0}, {0}}, // resetResp
        FALSE,      // safeFB
        FALSE,      // speculCK
        TRUE,       // nonSecureFormatEn
        {
            QLIB_IO23_MODE__QUAD, // IO2 and IO3 mux
            TRUE,                 // Dedicated reset-in mux
        },
        {
            QLIB_STD_ADDR_LEN__LAST, // addrLen
#ifdef SPI_INIT_ADDRESS_MODE_4_BYTES
            QLIB_STD_ADDR_MODE__4_BYTE,
#else
            QLIB_STD_ADDR_MODE__3_BYTE,
#endif
        },
        FALSE, // RNG Plain access enabled (in case flash supports W77Q_RNG_FEATURE)
        FALSE, // ctagModeMulti (relevant if the flash supports Q2_DEVCFG_CTAG_MODE)
        FALSE, // lock
        FALSE, // bootFailReset
               // resetPA
        {
            {TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE},
#if QLIB_NUM_OF_DIES > 1
            {TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE},
#endif
#if QLIB_NUM_OF_DIES == 4
            {TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE},
            {TRUE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE},
#endif
        },
        // vaultSize
        {
            QLIB_VAULT_DISABLED_RPMC_8_COUNTERS,
#if QLIB_NUM_OF_DIES > 1
            QLIB_VAULT_DISABLED_RPMC_8_COUNTERS,
#endif
#if QLIB_NUM_OF_DIES == 4
            QLIB_VAULT_DISABLED_RPMC_8_COUNTERS,
            QLIB_VAULT_DISABLED_RPMC_8_COUNTERS,
#endif
        },
        8 // fastReadDummyCycles
    };

    TOUCH(qlibContext);

    if (sectionTable != NULL)
    {
        (void)memcpy((U8*)sectionTable, (U8*)sectionTable_l, sizeof(sectionTable_l));
        for (dieId = 0; dieId < QLIB_NUM_OF_DIES; dieId++)
        {
            sectionTable[dieId][0].size     = MIN(QLIB_GET_FLASH_SIZE(qlibContext), QLIB_MAX_SECTION_SIZE);
            sectionTable[dieId][1].size     = (sectionTable[dieId][0].size == QLIB_GET_FLASH_SIZE(qlibContext))
                                                  ? 0u
                                                  : (QLIB_GET_FLASH_SIZE(qlibContext) - QLIB_MAX_SECTION_SIZE);
            sectionTable[dieId][1].baseAddr = (sectionTable[dieId][1].size > 0u ? QLIB_MAX_SECTION_SIZE : 0u);

            if (W77Q_VAULT(qlibContext) != 0u)
            {
                sectionTable[dieId][QLIB_SECTION_ID_VAULT].size = _128KB_;
            }
        }
    }

    (void)memcpy(deviceConf, &deviceConf_l, sizeof(QLIB_DEVICE_CONF_T));
    for (dieId = 0; dieId < QLIB_NUM_OF_DIES; dieId++)
    {
        if (W77Q_VAULT(qlibContext) != 0u)
        {
            deviceConf->vaultSize[dieId] = QLIB_VAULT_128KB_RPMC_DISABLED;
        }
        if (W77Q_DEVCFG_BOOT_FAIL_RST(qlibContext) != 0u)
        {
            deviceConf->bootFailReset = TRUE;
        }
    }
    deviceConf->stdAddrSize.addrLen =
        (LOG2(QLIB_GET_FLASH_SIZE(qlibContext)) >= 24u
             ? QLIB_STD_ADDR_LEN__27_BIT
             : (LOG2(QLIB_GET_FLASH_SIZE(qlibContext)) == 23u ? QLIB_STD_ADDR_LEN__26_BIT : QLIB_STD_ADDR_LEN__25_BIT));
}

QLIB_STATUS_T QCONF_Recovery(QLIB_CONTEXT_T* qlibContext, const QCONF_OTC_T* otc)
{
    QCONF_OTC_T ramOtc;
    GMC_T       GMC;
    BOOL        nonSecureFormatEn;

    QLIB_SECTION_CONFIG_TABLE_T sectionTable[QLIB_NUM_OF_DIES];
    QLIB_DEVICE_CONF_T          deviceConf = {0};

    QLIB_WATCHDOG_CONF_T watchdogDefault = {
        FALSE,                // enable
        FALSE,                // lfOscEn
        FALSE,                // swResetEn
        FALSE,                // authenticated
        0,                    // sectionID
        QLIB_AWDT_TH_12_DAYS, // threshold
        FALSE,                // lock
        0,                    // oscRateHz
        FALSE,                // fallbackEn (in flash that supports Q2_SUPPORT_AWDTCFG_FALLBACK)
    };
    const QLIB_LMS_KEY_ARRAY_T* pLmsKeys;
    U32*                        preProvisionedMasterKey;

    QCONF_initLegacyConfig_L(qlibContext, (W77Q_FORMAT_MODE(qlibContext) == 1u) ? NULL : sectionTable, &deviceConf);

    /*-------------------------------------------------------------------------------------------------------
     make a local copy of the OTC (in case that configurations are in flash)
    -------------------------------------------------------------------------------------------------------*/
    (void)memcpy(&ramOtc, otc, sizeof(QCONF_OTC_T));

#ifndef Q2_API
    preProvisionedMasterKey = (W77Q_PRE_PROV_MASTER_KEY(qlibContext) != 0u) ? (ramOtc.preProvisionedMasterKey) : NULL;
#else
    preProvisionedMasterKey = NULL;
#endif

    /*-------------------------------------------------------------------------------------------------------
     Ensure device can be formatted and configure if not
     ------------------------------------------------------------------------------------------------------*/
    QLIB_STATUS_RET_CHECK(QLIB_SEC__get_GMC(qlibContext, GMC));
    nonSecureFormatEn = (READ_VAR_FIELD(QLIB_REG_GMC_GET_DEVCFG(GMC), QLIB_REG_DEVCFG__FORMAT_EN) == 1u) ? TRUE : FALSE;
    if (FALSE == nonSecureFormatEn)
    {
        QLIB_STATUS_RET_CHECK(QLIB_ConfigDevice(qlibContext,
                                                ramOtc.deviceMasterKey,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                NULL,
                                                preProvisionedMasterKey,
                                                NULL,
                                                &(deviceConf),
                                                NULL));
    }

    /*-------------------------------------------------------------------------------------------------------
     Format the flash - clean from all it's data and configurations
    -------------------------------------------------------------------------------------------------------*/
    if (W77Q_FORMAT_MODE(qlibContext) == 1u)
    {
        QLIB_STATUS_RET_CHECK(QLIB_Format(qlibContext, NULL, FALSE, TRUE));
    }
    else
    {
        QLIB_STATUS_RET_CHECK(QLIB_Format(qlibContext, NULL, FALSE, FALSE));

        /*---------------------------------------------------------------------------------------------------
         Write the configuration to the flash device
        ---------------------------------------------------------------------------------------------------*/

#ifndef Q2_API
        pLmsKeys = (W77Q_SUPPORT_LMS(qlibContext) != 0u) ? (const QLIB_LMS_KEY_ARRAY_T*)(ramOtc.lmsKeys) : NULL;
#else
        pLmsKeys = NULL;
#endif
        QLIB_STATUS_RET_CHECK(QLIB_ConfigDevice(qlibContext,
                                                ramOtc.deviceMasterKey,
                                                ramOtc.deviceSecretKey,
                                                (const QLIB_SECTION_CONFIG_TABLE_T*)(sectionTable),
                                                (const KEY_ARRAY_T*)(ramOtc.restrictedKeys),
                                                (const KEY_ARRAY_T*)(ramOtc.fullAccessKeys),
                                                pLmsKeys,
                                                preProvisionedMasterKey,
                                                &(watchdogDefault),
                                                &(deviceConf),
                                                ramOtc.suid));
    }

#ifndef EXCLUDE_Q2_4_BYTES_ADDRESS_MODE
    if (Q2_4_BYTES_ADDRESS_MODE(qlibContext) != 0u)
    {
#ifdef SPI_INIT_ADDRESS_MODE_4_BYTES
        QLIB_STATUS_RET_CHECK(QLIB_SetAddressMode(qlibContext, QLIB_STD_ADDR_MODE__4_BYTE));
#else
        QLIB_STATUS_RET_CHECK(QLIB_SetAddressMode(qlibContext, QLIB_STD_ADDR_MODE__3_BYTE));
#endif
    }
#endif

    return QLIB_STATUS__OK;
}

