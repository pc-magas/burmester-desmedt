#include "message.h"
#include "mpi.h"
#include <stdio.h>

/**
 * Broadcasts a bignum
 * @param [in] num The number to broadcast
 * @param [in] rank The id of the member
 * @return -1 on error 0 on sucess
 */
int MPIbcastBigNum(BIGNUM *num, int rank, char* purpoce){
    int size = BN_num_bytes(num);
    unsigned char *message = OPENSSL_malloc(size);

    if(!BN_bn2bin(num, message)) {
     fprintf(stderr, "RANK %d: Fail to allocate an array for key bytes \"%s\" \n", rank, purpoce);
     fflush(stderr);
     OPENSSL_free(message);
     return -1;    
    }

    //Do the actual Broadcast && Debug
    printf("RANK %d: Broaccasting bignum for purpoce \"%s\" \n", rank, purpoce);
    fflush(stdout);
    int value = MPI_Bcast(message, size, MPI_BYTE, rank, MPI_COMM_WORLD);
    switch(value) {
        case MPI_ERR_COMM:
         fprintf(stderr, "RANK %d: COMMUNICATIPN ERROR on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         OPENSSL_free(message);
         return -1;

        case MPI_ERR_COUNT:
         fprintf(stderr, "RANK %d: Invalid Size Count on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         OPENSSL_free(message);
         return -1;
        
        case MPI_ERR_TYPE:
         fprintf(stderr, "RANK %d: Invalid Data Type on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         OPENSSL_free(message);
         return -1;

        case MPI_ERR_BUFFER:
         fprintf(stderr, "RANK %d: Invalid Buffer on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         OPENSSL_free(message);
         return -1;

        default:
          printf("RANK %d: ALL OK on BIGNUM sending on purpoce \"%s\" \n", rank, purpoce);
          fflush(stdout);
    }
    
    //Cleanups
    OPENSSL_free(message);
    return 0;
}

/**
 * Allocate a BigNumber array.
 * @param [in] size The number of elements for the array
 * @return An array to Store the BigNum
 */
BIGNUM** allocateBigNumArray(int size){
    if(size<=0) return NULL;

    BIGNUM **array = OPENSSL_malloc(size*sizeof(BIGNUM*));

    if(!array) return NULL;

    for(int i=0;i<size;i++){
        array[i]=BN_new();
    }

    return array;
}

/**
 * Receive generated Big Number from all participants
 * @param [out] numbers The list of all received Big Numbers
 * @param [in] size The big number list
 * 
 */
int MPIReceiveBigNum(BIGNUM **numbers, int size) {
    numbers=allocateBigNumArray(size);
    if(numbers == NULL) return -1;
    int remaining = size;
    // do {
    //   char *data
    //   MPI_Recv(data,)
    // } while(remaining>0);

 return 0;
}
