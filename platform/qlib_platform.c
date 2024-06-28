#include "qlib_platform.h"

/************************************************************************************************************
 * @brief       This function initialize HASH context\n
 *
 * @param[out]  ctx     Hash context
 * @param[in]   opt     Hash optimization option
 * 
 * @return
 * 0                      - no error occurred\n
 * non-zero               - error occurred
 ************************************************************************************************************/
int PLAT_HASH_Init(void** ctx, QLIB_HASH_OPT_T opt) { return 0; }

/************************************************************************************************************
 * @brief       This function adds data to current HASH calculation.\n
 * This function can be called repeatedly with an arbitrary amount of data to be hashed.\n
 * This function is an implementation of the hash function supported by the W77Q defined in the spec.\n
 * For performance reasons, it is recommended to use HW implementation of this function.\n
 * Test vectors can be found in the spec TBD
 *
 * @param[in,out]  ctx        Hash context
 * @param[in]      data       Input data
 * @param[in]      dataSize   Input data size in bytes
 * 
 * @return
 * 0                      - no error occurred\n
 * non-zero               - error occurred
 ************************************************************************************************************/
int PLAT_HASH_Update(void* ctx, const void* data, uint32_t dataSize) { return 0; }

/************************************************************************************************************
 * @brief       Finalize hashing and erases the context. 
 *
 * @param[in,out]  ctx        Hash context
 * @param[out]     output     digest
 * 
* @return
 * 0                      - no error occurred\n
 * non-zero               - error occurred
 ************************************************************************************************************/
int PLAT_HASH_Finish(void* ctx, uint32_t* output) { return 0; }

/************************************************************************************************************
 * @brief       This function returns non-repeating 'nonce' number.
 * A 'nonce' is a 64bit number that is used in session establishment.\n
 * To prevent replay attacks such nonce must be 'non-repeating' - appear different each function execution.\n
 * Typically implemented as a HW TRNG.
 *
 * @return      64 bit random number
************************************************************************************************************/
uint64_t PLAT_GetNONCE(void) { return 0; }