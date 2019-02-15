#include "mpi.h"
#include <stdio.h>

// Openssl
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// Custom
#include "message.h"
#include "dh.h"

void cleanup(DH *secret, BIGNUM *intermediate, BIGNUM *previousVal);

void cleanup(DH *secret, BIGNUM *intermediate, BIGNUM *previousVal) {
  if(intermediate != NULL)  BN_free(intermediate);
  if(previousVal != NULL) BN_free(previousVal);
  DH_free(secret);
  // EVP_cleanup();
  // CRYPTO_cleanup_all_ex_data();
  // ERR_free_strings();
}

int main(int argc, char *argv[]) {
  int rank, size, error, previous_index, next_index;
  BIGNUM** numbers = NULL, **intermediate_keys=NULL;
  BIGNUM *previousVal = NULL, *finalKey=NULL;
  BIGNUM *pubKey = NULL;
  BIGNUM *p = NULL;

  MPI_Init( &argc, &argv );
  MPI_Comm_rank( MPI_COMM_WORLD, &rank );
  MPI_Comm_size( MPI_COMM_WORLD, &size );
  
  // /* Load the human readable error strings for libcrypto */
  // ERR_load_crypto_strings();
  // /* Load all digest and cipher algorithms */
  // OpenSSL_add_all_algorithms();
  // /* Load config file, and other important initialisation */
  // OPENSSL_config(NULL);
  
  previous_index=cyclicGroupPrevious(rank,size);
  next_index=cyclicGroupNext(rank,size);

  DH *secret = NULL;

  if(NULL == (secret = DH_get_2048_224())){
      fprintf(stderr, "RANK %d, Could Not Initialize the Diffie Hellman\n",rank);
      fflush(stderr); 
      return -1;
  }


  printf("RANK %d, Generating Diffie Hellman Keys\n", rank);
  fflush(stdout);
  if(-1 == generateKeys(secret)) {
    cleanup(secret, NULL, NULL);
    fprintf(stderr, "RANK %d, Failed to intialize key\n",rank);
    fflush(stderr);
    return -1;
  }

  printf("RANK %d, Keys generated\n",rank);
  fflush(stdout);

  printf("RANK %d, Publishing Keys\n", rank);
  fflush(stdout);

  if(secret == NULL) {
    cleanup(secret, NULL, NULL);
    fprintf(stderr, "RANK %d, Error on Generating the Diffie Hellman\n",rank);
    fflush(stderr);
    return -1;
  }

  pubKey=BN_new();
  DH_get0_key(secret, &pubKey, NULL);
  if(-1 == MPIbcastBigNum(pubKey, rank, "Publishing Public Key")){
   cleanup(secret, NULL, NULL);
   return -1;
  }
  
  numbers = MPIReceiveBigNum(&error, rank, size);
  if(-1 == error){
   cleanup(secret, NULL, NULL);
   return -1;
  }
  // printBigNumArray(numbers,rank,size,"RECEIVED PUBLIC KEYS");

  error=0;
  BIGNUM *intermediate = generateIntermediatekeys(secret,numbers[previous_index],numbers[next_index], &error);
  if(-1==error) {
   cleanup(secret, intermediate, NULL);
   return -1;
  }
  
  printf("RANK %d: Intermediate value %s \n",rank,BN_bn2hex(intermediate));
  fflush(stdin);

  
  if(-1 == MPIbcastBigNum(intermediate, rank, "Publishing Intermediate Key")){
   cleanup(secret, intermediate, NULL);
   return -1;
  }
  
  printf("RANK %d: Receiving Other Intermediate Values\n",rank);
  fflush(stdin);
  error=0;
  intermediate_keys=MPIReceiveBigNum(&error,rank,size);
  printf("RANK %d: Received Other Intermediate Values\n",rank);
  fflush(stdin);
  intermediate_keys[rank]=intermediate;

  printf("RANK %d: Calculating previous Secret Value\n", rank);
  fflush(stdout);
  error=0;
  previousVal=generateKeyFromPreviousParticipant(secret,numbers[previous_index],size, &error);
  if(error == -1){
    cleanup(secret, intermediate, previousVal);
    return -1;
  }
  printf("RANK %d: Calculated previous Secret Value\n", rank);
  printf("RANK %d: Calculating final Key\n", rank);
  fflush(stdout);

  p=BN_new();
  DH_get0_pqg(secret,&p,NULL,NULL);
  finalKey=calculateFinalKey(p, previousVal, intermediate_keys, size, rank);
  
  if(finalKey != NULL){
   printf("RANK %d: Final Key Calculated: %s\n",rank,BN_bn2hex(finalKey));
   BN_free(finalKey);

  } else {
    printf("RANK %d: Final Key Calculation Failure: \n",rank);
  }

  /*Cleanup */
  puts("Cleaning Up");
  fflush(stdin);
  cleanup(secret, intermediate, previousVal);
  MPI_Finalize();
  return 0;
}