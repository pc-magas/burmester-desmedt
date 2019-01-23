#include "mpi.h"
#include "message.h"
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
  int rank, size;
  MPI_Init( &argc, &argv );
  MPI_Comm_rank( MPI_COMM_WORLD, &rank );
  MPI_Comm_size( MPI_COMM_WORLD, &size );
  /* Load the human readable error strings for libcrypto */
  ERR_load_crypto_strings();

  /* Load all digest and cipher algorithms */
  OpenSSL_add_all_algorithms();
  /* Load config file, and other important initialisation */
  OPENSSL_config(NULL);

  /* ... Do some crypto stuff here ... */

  printf( "Cluster size: %d\nTerminal ID: %d\n",size,rank );
  /* Removes all digests and ciphers */
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  /* Remove error strings */
  ERR_free_strings();
  MPI_Finalize();
  return 0;
}