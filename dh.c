#include "dh.h"
#include <openssl/dh.h>

int generateKeys(DH *encryptionInfo) {
 int codes;

 if(NULL == (encryptionInfo = DH_new())) return -1;
 if(1 != DH_generate_parameters_ex(encryptionInfo, 2048, DH_GENERATOR_2, NULL)) return -1;
 if(1 != DH_check(encryptionInfo, &codes)) return -1;
 if(codes != 0) return -1;
 if(1 != DH_generate_key(encryptionInfo)) return -1;
  
 return 0;
}
