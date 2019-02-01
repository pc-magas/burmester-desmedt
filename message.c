#include "message.h"
#include "mpi.h"

#include <openssl/crypto.h>
#include <openssl/bn.h>

#include <stdio.h>

/**
 * Safely frees a value'
 * @param [in/out] value The value to free afteer freeing we enforce its value as null
 */
void safeFree(unsigned char *value) {
    if(value==NULL) return;
    OPENSSL_free(value);
    value=NULL;
}

/**
 * We set zero to an unsinged char array before changing it size
 * @param [in/out] value The value to change the size
 * @param [in] oldsize The former size of the array
 * @param [in] newsize The new size of the array
 */
unsigned char* safeRealloc(unsigned char *value, int oldsize, int newsize){
  if(oldsize < 0 || newsize <= 0) {
    safeFree(value);
    return NULL;
  }

  if(oldsize > 0 ) OPENSSL_cleanse(value,oldsize);
  return OPENSSL_realloc((void *)value,newsize);
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
BIGNUM** allocateBigNumArray(int size, int skip){
    if(size<=0) return NULL;

    BIGNUM **array = OPENSSL_malloc(size*sizeof(BIGNUM*));

    if(!array) return NULL;
    for(int i=0;i<size;i++){
        if(skip > 0 && skip==0){
          array[i]=NULL;
          continue;
        }
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
    BIGNUM **numbers = allocateBigNumArray(size, rank);
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
      tmp=safeRealloc(tmp,old_size,receivedBytes);
      MPI_Barrier(MPI_COMM_WORLD);
      bcastError = MPI_Bcast(tmp, receivedBytes, MPI_BYTE, i, MPI_COMM_WORLD);
      MPI_Barrier(MPI_COMM_WORLD);
      
      if(-1 == handleMPIBCast(rank,"Receiving the Key",bcastError)){ //Error Handling
        safeFree(tmp);
        *error=-1;
        return NULL;
      }
      
      if(!BN_bin2bn(tmp,receivedBytes,numbers[i])){
        fprintf(stderr,"RANK %d: Cannot handle received key from %d",rank,i);
        fflush(stderr);
        safeFree(tmp);
        *error=-1;
        return NULL;
      }
      old_size=receivedBytes;
    }
 safeFree(tmp);
 return numbers;
}

/**
 * For Debugging purpoces print.
 * @param [in] array The array to print
 * @param [in] rank the participant Rank
 * @param [in] size How long is the array
 * @param [in] puproce String explaining what bignum array is
 */
void printBigNumArray(BIGNUM **array, int rank, int size, char *puproce){
  MPI_Barrier(MPI_COMM_WORLD); // It makes slower but ensores that all the processes are met to this point
  printf("\n++++++++++++++++++++++++++++++++++++++++\n");
  printf("RANK: %d array size %d\n",rank,size);
  puts(puproce);
  putchar('\n');
  for(int i=0;i<size;i++){
    if(array[i] == NULL){
      printf("RANK:%d Index: %d VALUE: NULL \n",rank,i);
      continue;
    }
    printf("RANK:%d Index: %d VALUE: %s \n",rank,i,BN_bn2hex(array[i]));
  }
  printf("++++++++++++++++++++++++++++++++++++++++\n");
  fflush(stdin);
}