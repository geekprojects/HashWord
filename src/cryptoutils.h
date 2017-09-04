#ifndef __HASHWORD_CRYPTO_UTILS_H_
#define __HASHWORD_CRYPTO_UTILS_H_

#include "data.h"
#include "securestring.h"

#include "openaes/oaes_lib.h"
#include "sha/sha.h"

#define IV_LENGTH 16

class CryptoUtils
{
 private:
    Random m_random;

    void fillIV(Data* data);

 public:
    CryptoUtils();
    ~CryptoUtils();

    Key* deriveKey(Key* salt, Key* salt2, SecureString ikm);

    SecureString encrypt64(Key* key, uint8_t* in, size_t inLength);
    SecureString encrypt64(Key* key, Data* data);
    Data* encrypt(Key* key, uint8_t* in, size_t inLength);
    Data* encrypt(Key* key, Data* data);
    Data* encryptMultiple(Key* key1, Key* key2, Data* value, int rounds);
    SecureString encryptValue(Key* masterKey, Key* valueKey, SecureString value, int rounds);

    Data* decrypt(Key* key, Data* encData);
    Data* decrypt(Key* key, SecureString enc64);
    Data* decryptMultiple(Key* key1, Key* key2, Data* enc, int rounds);
    Data* decryptMultiple(Key* key1, Key* key2, SecureString enc64, int rounds);
    SecureString decryptValue(Key* masterKey, Key* valueKey, SecureString enc64, int rounds);

    Key* decodeKey(SecureString key64);
    SecureString hash(Key* salt, SecureString str);

    void fillRandom(uint8_t* data, size_t length);

    Key* generateKey();

    SecureString generatePassword(int length, bool useSymbols);

    static void shred(Data* data);
    static void shred(void* data, size_t length);
};

#endif
