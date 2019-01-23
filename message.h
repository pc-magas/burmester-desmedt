
/**
 * Message structure for publishing public keys
 */
typedef struct PubKeyMessage {
 char *publicDiffieHellmanKey;
 char *publicSignatureKey;
} PubKeyMessage;