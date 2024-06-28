/************************************************************************************************************
* @internal
* @remark     Winbond Electronics Corporation - Confidential
* @copyright  Copyright (c) 2023 by Winbond Electronics Corporation . All rights reserved
* @endinternal
*
* @file       qlib_utils_lms.c
* @brief      This file contains LMS utility functions
*
* ### project qlib
*
************************************************************************************************************/

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                                INCLUDES                                                 */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
#include "qlib_utils_lms.h"

#ifndef EXCLUDE_LMS_ATTESTATION
/*-----------------------------------------------------------------------------------------------------------
-------------------------------------------------------------------------------------------------------------
                                                TYPES
-------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------*/

/************************************************************************************************************
 * @brief Buffer used for chain hashing
************************************************************************************************************/
PACKED_START
typedef struct
{
    LMS_ATTEST_KEY_ID_T keyId;
    U32                 q;
    U16                 index;
    U8                  iter;
    LMS_ATTEST_CHUNK_T  prevChunk;
} PACKED QLIB_LMS_Attest_HASH_CHAIN_BUF_T;
PACKED_END

/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/
/*                                           INTERFACE FUNCTIONS                                           */
/*---------------------------------------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------------------------------------*/

QLIB_STATUS_T QLIB_LMS_Attest_HashChain(const LMS_ATTEST_CHUNK_T  input,
                                        const LMS_ATTEST_KEY_ID_T keyId,
                                        U32                       q,
                                        U16                       chainIndex,
                                        U8                        iterStart,
                                        U8                        iter,
                                        LMS_ATTEST_CHUNK_T        output)
{
    QLIB_LMS_Attest_HASH_CHAIN_BUF_T buf;
    _256BIT                          hash;
    U8                               j;

    // Set buffer static parameters
    // I
    (void)memcpy((U8*)buf.keyId, (const U8*)keyId, sizeof(LMS_ATTEST_KEY_ID_T));
    // ots index
    buf.q = REVERSE_BYTES_32_BIT(q);
    // chain index
    buf.index = REVERSE_BYTES_16_BIT(chainIndex);

    // Set OTS private key (Xi) as initial prev chunk
    (void)memcpy(buf.prevChunk, input, sizeof(LMS_ATTEST_CHUNK_T));

    // Perform iterations
    for (j = 0; j < iter; j++)
    {
        buf.iter = j + iterStart;
        QLIB_STATUS_RET_CHECK(QLIB_HASH(hash, &buf, sizeof(QLIB_LMS_Attest_HASH_CHAIN_BUF_T)));
        (void)memcpy((U8*)buf.prevChunk, (U8*)hash, sizeof(LMS_ATTEST_CHUNK_T));
    }

    // signed digit result
    (void)memcpy(output, buf.prevChunk, sizeof(LMS_ATTEST_CHUNK_T));

    return QLIB_STATUS__OK;
}
#endif // EXCLUDE_LMS_ATTESTATION
