#include "dh.h"
#include "mpi.h"
#include <openssl/dh.h>
#include <openssl/bn.h>

/**
 * Generate Diffie-Hellman Key Agreement keys.
 * @param [in] encryptionInfo The created Kerys Structure
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
 * @param [in] secret The secret key.
 * @param [in] previous The previous participant public key.
 * @param [in] next The next participant public key.
 * @param [out] error Indicator if any error has occured
 * @return 0 on sucess -1 on error
 */
BIGNUM* generateIntermediatekeys(DH *secret, BIGNUM *previous, BIGNUM *next, int *error){
 BIGNUM *dv = BN_new();
 unsigned char *secretBytes; //Calculated Secret Key
 BIGNUM *final;
 int secret_size = 0;
 BN_CTX *ctx = BN_CTX_new();

  if(NULL == (secretBytes = OPENSSL_malloc(sizeof(unsigned char) * (DH_size(secret))))){
     BN_CTX_free(ctx);
     *error=-1;
     return NULL;
  }

 int rank;
 MPI_Comm_rank( MPI_COMM_WORLD, &rank );

 printf("RANK %d Making the division\n", rank);
 fflush(stdout);
 if(previous == NULL) printf("RANK %d Previous NULL",rank);
 if(next == NULL) printf("RANK %d NEXT NULL",rank);
 if(!BN_div(NULL, dv, next, previous, ctx) ){
    BN_CTX_free(ctx);
    OPENSSL_free(secretBytes);
    *error=-1;
    return NULL;
 }
 printf("RANK %d Divided\n", rank);
 fflush(stdout);

//  if(!BN_mod_exp(result, &dv, &secret, &p, ctx)){
//      BN_CTX_free(ctx);
//      *error=-1;
//      return NULL;
//  }

 printf("RANK %d Computing intermediate key. Using Public %s\n", rank, BN_bn2hex(dv));

 if(0 > (secret_size = DH_compute_key(secretBytes, dv, secret))) {
    BN_CTX_free(ctx);
    OPENSSL_free(secretBytes);
    *error=-1;
    return NULL;
 }
 printf("RANK %d Computed intermediate key\n", rank);
 fflush(stdout);

 final=BN_new();
 if(!BN_bin2bn(secretBytes, secret_size, final)){
    BN_free(final);
    OPENSSL_free(secretBytes);
   //  BN_CTX_free(ctx);

    *error=-1;
    return NULL;
 }

 OPENSSL_free(secretBytes);
 BN_CTX_free(ctx);
 return final;
}

/**
 * Calculate the: k[i-1]^n*xi
 * @param [in] secret The Secret Key
 * @param [in] previous The previous Key
 * @param [in] size the group size
 * @param [out] error Indicator if any error has occured
 * @return The Intermediate Key Ki thaty will be miltiplied on the next step
 */
BIGNUM* generateKeyFromPreviousParticipant(DH *secret, BIGNUM *previous, int size, int * error){
   BIGNUM *tmp= NULL;
   BIGNUM *sizeInBigNum = NULL;
   BN_CTX *ctx = NULL;

   if(secret==NULL){
    *error=-1;
    return NULL;
   }
   
   sizeInBigNum=BN_new();
   if(!BN_set_word(sizeInBigNum, (unsigned long) size)){
     OPENSSL_free(sizeInBigNum);
     *error=-1;
     return NULL;
   }

   // We immute the secret from DH*.
   ctx=BN_CTX_new();
   tmp=BN_new();
   puts("Doing Muliplication\n"); fflush(stdout);
   if(!BN_mul(tmp,secret->priv_key,sizeInBigNum,ctx)){
      BN_free(sizeInBigNum);
      BN_free(tmp);
      BN_CTX_free(ctx);
      *error=-1;
      return NULL;
   }

   puts("Raize Into Power\n"); fflush(stdout);
   if(!BN_exp(tmp,previous,tmp,ctx)){
      BN_free(sizeInBigNum);
      BN_free(tmp);
      BN_CTX_free(ctx);
      *error=-1;
      return NULL;
   }

   BN_free(sizeInBigNum);
   BN_CTX_free(ctx);
   return tmp;
}

/**
 * Previous index of an N-sized cyclic group from a given rank
 * @param rank [in]
 * @param size [in]
 */
int cyclicGroupPrevious(int rank, int size) {
  if(rank == 0) return size-1;
  return rank-1;
}

/**
 * Next index of an N-sized cyclic group from a given rank
 * @param rank [in]
 * @param size [in]
 */
int cyclicGroupNext(int rank, int size){
    return (rank+1)%size;
}