#include "message.h"
#include "mpi.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include <stdio.h>

void safeFree(unsigned char *value, int rank){
    if(value==NULL) return;
    printf("RANK %d: Freeing value\n",rank);
    OPENSSL_free(value);
    value=NULL;
}

int handleMPIBCast(int rank, char *purpoce, int errCode){
     switch(errCode) {
        case MPI_ERR_COMM:
         fprintf(stderr, "RANK %d: COMMUNICATIPN ERROR on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         return -1;

        case MPI_ERR_COUNT:
         fprintf(stderr, "RANK %d: Invalid Size Count on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         return -1;
        
        case MPI_ERR_TYPE:
         fprintf(stderr, "RANK %d: Invalid Data Type on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         return -1;

        case MPI_ERR_BUFFER:
         fprintf(stderr, "RANK %d: Invalid Buffer on BIGNUM sending for purpoce \"%s\" \n", rank, purpoce);
         fflush(stderr);
         return -1;

        default:
          printf("RANK %d: ALL OK on BIGNUM sending on purpoce \"%s\" \n", rank, purpoce);
          fflush(stdout);
          return 0;
    }
}

/**
 * Broadcasts a bignum
 * @param [in] num The number to broadcast
 * @param [in] rank The id of the member
 * @return -1 on error 0 on sucess
 */
int MPIbcastBigNum(BIGNUM *num, int rank, char* purpoce){
    int size = BN_num_bytes(num);
    unsigned char *message = OPENSSL_malloc(size);
    MPI_Barrier(MPI_COMM_WORLD);
    int value = MPI_Bcast(&size, 1, MPI_INT, rank, MPI_COMM_WORLD);
    MPI_Barrier(MPI_COMM_WORLD);
    if(-1 == handleMPIBCast(rank,"Broadcasting the size of the public key",value)){
        OPENSSL_free(message);
        return -1;
    }

    if(!BN_bn2bin(num, message)) {
     fprintf(stderr, "RANK %d: Fail to allocate an array for key bytes \"%s\" \n", rank, purpoce);
     fflush(stderr);
     OPENSSL_free(message);
     return -1;    
    }

    //Do the actual Broadcast && Debug
    printf("RANK %d: Broaccasting bignum for purpoce \"%s\" \n", rank, purpoce);
    fflush(stdout);

    MPI_Barrier(MPI_COMM_WORLD);
    value = MPI_Bcast(message, size, MPI_BYTE, rank, MPI_COMM_WORLD);
    MPI_Barrier(MPI_COMM_WORLD);

    OPENSSL_free(message);
    return handleMPIBCast(rank, purpoce, value);
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
 * @param [in] size The number of participants
 */
 BIGNUM ** MPIReceiveBigNum(int *error, int rank, int size) {
    BIGNUM **numbers = allocateBigNumArray(size);
    int receivedBytes=0,bcastError=0,old_size=0;
    unsigned char *tmp=NULL;

    if(numbers == NULL){
        *error=-1;
        return NULL;
    }
    
    for(int i=0;i < size;i++) {
      if(i==rank) continue;
      receivedBytes=0;

      MPI_Barrier(MPI_COMM_WORLD);
      bcastError = MPI_Bcast(&receivedBytes, 1, MPI_INT, i, MPI_COMM_WORLD);
      MPI_Barrier(MPI_COMM_WORLD);
    
      printf("RANK:%d Receiving Bcast Message for SIZE from %d\n",rank,i);
      if(-1 == handleMPIBCast(rank,"Receiving the Key Size",bcastError)){
        *error=-1;
        return NULL;
      }

      printf("RANK:%d Receiving Bcast Message for a PUBLIC KEY sized %d from %d\n",rank, receivedBytes, i); 
      tmp=(unsigned char *)OPENSSL_realloc((void *)tmp,receivedBytes);
      MPI_Barrier(MPI_COMM_WORLD);
      bcastError = MPI_Bcast(tmp, receivedBytes, MPI_BYTE, i, MPI_COMM_WORLD);
      MPI_Barrier(MPI_COMM_WORLD);
      
      if(-1 == handleMPIBCast(rank,"Receiving the Key",bcastError)){ //Error Handling
        safeFree(tmp,rank);
        *error=-1;
        return NULL;
      }
      
      if(!BN_bin2bn(tmp,receivedBytes,numbers[i])){
        fprintf(stderr,"RANK %d: Cannot handle received key from %d",rank,i);
        fflush(stderr);
        safeFree(tmp,rank);
        *error=-1;
        return NULL;
      }
      printf("RANK %d: Trying to free value: %d",rank,i);
      old_size=receivedBytes;
    }
 printf("RANK %d: final free ", rank);
 safeFree(tmp, rank);
 return numbers;
}
