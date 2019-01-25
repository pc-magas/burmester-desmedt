#include <openssl/bn.h>
#include "mpi.h"

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
int MPIReceiveBigNum(BIGNUM **numbers, int size);