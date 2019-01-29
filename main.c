#include "mpi.h"
#include <stdio.h>

// Openssl
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// Custom
#include "message.h"
#include "dh.h"

void cleanup(DH *secret);

void cleanup(DH *secret) {
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  OPENSSL_free(secret);
  ERR_free_strings();
}

int main(int argc, char *argv[]) {
  int rank, size, error;
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
  
  DH *secret= DH_new();

 if(NULL == (secret = DH_new())){
    fprintf(stderr, "RANK %d, Could Not Initialize the Diffie Hellman\n",rank);
    fflush(stderr); 
    return -1;
 }


  printf("RANK %d, Generating Diffie Hellman Keys\n", rank);
  fflush(stdout);
  if(-1 == generateKeys(secret)) {
    cleanup(secret);
    fprintf(stderr, "RANK %d, Failed to intialize key\n",rank);
    fflush(stderr);
    return -1;
  }

  printf("RANK %d, Keys generated\n",rank);
  fflush(stdout);

  printf("RANK %d, Publishing Keys\n", rank);
  fflush(stdout);

  if(secret == NULL) {
    cleanup(secret);
    fprintf(stderr, "RANK %d, Error on Generating the Diffie Hellman\n",rank);
    fflush(stderr);
    return -1;
  }

  if(-1 == MPIbcastBigNum(secret->pub_key, rank, "Publishing Public Key")){
   cleanup(secret);
   return -1;
  }
  
  numbers = MPIReceiveBigNum(&error, rank, size);
  if(-1 == error){
   cleanup(secret);
   return -1;
  }
  printBigNumArray(numbers,rank,size,"RECEIVED PUBLIC KEYS");

  /*Cleanup */
  cleanup(secret);
  MPI_Finalize();
  return 0;
}