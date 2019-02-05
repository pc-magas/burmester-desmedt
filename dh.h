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
 * @return The Intermediate Key Ki thaty will be miltiplied on the next step
 */
BIGNUM* generateIntermediatekeys(DH *secret, BIGNUM *previous, BIGNUM *next, int *error);

/**
 * Calculate the: k[i-1]^n*xi
 * @param [in] secret The Secret Key
 * @param [in] previous The previous Key
 * @param [in] size the group size
 * @param [out] error Indicator if any error has occured
 * @return 
 */
BIGNUM* generateKeyFromPreviousParticipant(DH *secret, BIGNUM *previous, int size, int *error);

/**
 * Calculate the final Key
 * @param [in] p Prime number for performing modulo
 * @param [in] previousVal The previous value  
 */
BIGNUM* calculateFinalKey(BIGNUM *p, BIGNUM *previousVal, BIGNUM **intermediateKeys, int size, int rank);

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

/**
 * Get the correct exponient to calculate the intermeiate values 
 * @param [in] rank the rank vof the participant.
 * @param [in] pos the position of the key.
 */
int getExpFroIntermedateKeysIteration(int rank, int pos);
#endif