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
  int rank, size;
  DH *secret=NULL;


  MPI_Init( &argc, &argv );
  MPI_Comm_rank( MPI_COMM_WORLD, &rank );
  MPI_Comm_size( MPI_COMM_WORLD, &size );
    
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();
  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();
  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

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

  // Set up Barrier for cpommunications
  MPI_Barrier(MPI_COMM_WORLD);

  printf("RANK %d, Publishing Keys\n",rank);
  fflush(stdout);
  MPIbcastBigNum(secret->pub_key, rank, "Publishing Public Key");
  
  /*Cleanup */
  cleanup(secret);
  MPI_Finalize();
  return 0;
}