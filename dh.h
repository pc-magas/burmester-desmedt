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
 * @param [out] result Common key from secret.
 * @param [in] secret The secret key.
 * @param [in] previous The previous participant public key.
 * @param [in] next The next participant public key.
 * @return 0 on sucess -1 on error
 */
int generateIntermediatekeys(BIGNUM *result, BIGNUM secret, BIGNUM previous, BIGNUM next, BIGNUM p);
#endif