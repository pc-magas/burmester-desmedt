#include <openssl/crypto.h>
#include <openssl/bn.h>

#ifndef BD_MPI_MESSAGE
#define BD_MPI_MESSAGE
/**
 * A common way to handle the 
 */
int handleMPIBCast(int rank, char *purpoce, int errCode);

/**
 * Broadcasts a bignum
 * @param [in] num The number to broadcast
 * @param [in] rank The id of the member
 * @return -1 on error 0 on sucess
 */
int MPIbcastBigNum(BIGNUM *num, int rank, char* purpoce);

/**
 * Allocate a BigNumber array.
 * @param [in] size The number of elements for the array
 */
BIGNUM** allocateBigNumArray(int size);


/**
 * Receive generated Big Number from all participants
 * @param [out] numbers The list of all received Big Numbers
 * @param [in] size The big number list
 * @return -1 on error 0 on sucess
 */
BIGNUM** MPIReceiveBigNum(int *error, int rank, int size);

/**
 * Safely frees a value'
 * @param [in/out] value The value to free afteer freeing we enforce its value as null
 */
void safeFree(unsigned char *value);

/**
 * We set zero to an unsinged char array before changing it size
 * @param [in/out] value The value to change the size
 * @param [in] oldsize The former size of the array
 * @param [in] newsize The new size of the array
 */
unsigned char* safeRealloc(unsigned char *value, int oldsize, int newsize);

#endif