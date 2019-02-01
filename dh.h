#include <openssl/dh.h>
#include <openssl/bn.h>

#ifndef BD_MPI_DH
#define BD_MPI_DH
 /**
  * Generate Diffie-Hellman Key Agreement keys.
  * 
  * NOTE: Create the DH struct to the MAIN function and then pass it towards this one.
  * 
  * @param [in] encryptionInfo The created Kerys Structure
  * @return 0 on sucess -1 on failure
  */
 int generateKeys(DH *encryptionInfo);

/**
 * Calculate the math equation:
 *  *result = (next/previous)^secret%p;
 * 
 * @param [in] secret The secret key.
 * @param [in] previous The previous participant public key.
 * @param [in] next The next participant public key.
 * @param [out] error Indicator if any error has occured
 * @return 0 on sucess -1 on error
 */
BIGNUM* generateIntermediatekeys(DH *secret, BIGNUM *previous, BIGNUM *next, int *error);

/**
 * Previous index of an N-sized cyclic group from a given rank
 * @param rank [in]
 * @param size [in]
 */
int cyclicGroupPrevious(int rank, int size);

/**
 * Next index of an N-sized cyclic group from a given rank
 * @param rank [in]
 * @param size [in]
 */
int cyclicGroupNext(int rank, int size);
#endif