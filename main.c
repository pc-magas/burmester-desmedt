#include "mpi.h"
#include <stdio.h>

// Openssl
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// Custom
#include "message.h"
#include "dh.h"

void cleanup(DH *secret, BIGNUM *intermediate);

void cleanup(DH *secret, BIGNUM *intermediate) {
  if(intermediate != NULL)  BN_free(intermediate);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  OPENSSL_free(secret);
  ERR_free_strings();
}

int main(int argc, char *argv[]) {
  int rank, size, error, previous_index, next_index;
  BIGNUM** numbers = NULL;

  MPI_Init( &argc, &argv );
  MPI_Comm_rank( MPI_COMM_WORLD, &rank );
  MPI_Comm_size( MPI_COMM_WORLD, &size );
  
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();
  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);
  
  previous_index=cyclicGroupPrevious(rank,size);
  next_index=cyclicGroupNext(rank,size);

  DH *secret = NULL;

  if(NULL == (secret = DH_new())){
      fprintf(stderr, "RANK %d, Could Not Initialize the Diffie Hellman\n",rank);
      fflush(stderr); 
      return -1;
  }


  printf("RANK %d, Generating Diffie Hellman Keys\n", rank);
  fflush(stdout);
  if(-1 == generateKeys(secret)) {
    cleanup(secret, NULL);
    fprintf(stderr, "RANK %d, Failed to intialize key\n",rank);
    fflush(stderr);
    return -1;
  }

  printf("RANK %d, Keys generated\n",rank);
  fflush(stdout);

  printf("RANK %d, Publishing Keys\n", rank);
  fflush(stdout);

  if(secret == NULL) {
    cleanup(secret, NULL);
    fprintf(stderr, "RANK %d, Error on Generating the Diffie Hellman\n",rank);
    fflush(stderr);
    return -1;
  }

  if(-1 == MPIbcastBigNum(secret->pub_key, rank, "Publishing Public Key")){
   cleanup(secret, NULL);
   return -1;
  }
  
  numbers = MPIReceiveBigNum(&error, rank, size);
  if(-1 == error){
   cleanup(secret, NULL);
   return -1;
  }
  // printBigNumArray(numbers,rank,size,"RECEIVED PUBLIC KEYS");

  error=0;
  BIGNUM *intermediate = generateIntermediatekeys(secret,numbers[previous_index],numbers[next_index], &error);
  if(-1==error) {
   cleanup(secret, intermediate);
   return -1;
  }
  printf("RANK %d: Intermediate value %s \n",rank,BN_bn2hex(intermediate));
  
  /*Cleanup */
  cleanup(secret, intermediate);
  MPI_Finalize();
  return 0;
}