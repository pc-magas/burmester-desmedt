#include "dh.h"
#include <openssl/dh.h>

/**
 * Generate Diffie-Hellman Key Agreement keys.
 * @param [out] encryptionInfo The created Kerys Structure
 * @return 0 on sucess -1 on failure
 */
int generateKeys(DH *encryptionInfo) {
 int codes;

 if(1 != DH_generate_parameters_ex(encryptionInfo, 2048, DH_GENERATOR_2, NULL)) return -1;
 if(1 != DH_check(encryptionInfo, &codes)) return -1;
 if(codes != 0) return -1;
 if(1 != DH_generate_key(encryptionInfo)) return -1;
  
 return 0;
}

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
int generateIntermediatekeys(BIGNUM *result, BIGNUM secret, BIGNUM previous, BIGNUM next, BIGNUM p){
 BIGNUM rem;
 BIGNUM dv;
 BN_CTX *ctx = BN_CTX_new();
 
 if(result == NULL) result=BN_new();
 
 if(!BN_div(&rem, &dv, &next, &previous, ctx) ){
    BN_CTX_free(ctx);
    return -1;
 }
 
 if(!BN_mod_exp(result, &dv, &secret, &p, ctx)){
     BN_CTX_free(ctx);
     return -1;
 }

 BN_CTX_free(ctx);
 return 0;
}

