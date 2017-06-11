#ifndef __HASHWORD_CRYPTO_UTILS_H_
#define __HASHWORD_CRYPTO_UTILS_H_

#include "data.h"

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

    Key* deriveKey(Key* salt, Key* salt2, std::string ikm);

    std::string encrypt64(Key* key, uint8_t* in, size_t inLength);
    std::string encrypt64(Key* key, Data* data);
    Data* encrypt(Key* key, uint8_t* in, size_t inLength);
    Data* encrypt(Key* key, Data* data);
    Data* encryptMultiple(Key* key1, Key* key2, Data* value, int rounds);
    std::string encryptValue(Key* masterKey, Key* valueKey, std::string value, int rounds);

    Data* decrypt(Key* key, Data* encData);
    Data* decrypt(Key* key, std::string enc64);
    Data* decryptMultiple(Key* key1, Key* key2, Data* enc, int rounds);
    Data* decryptMultiple(Key* key1, Key* key2, std::string enc64, int rounds);
    std::string decryptValue(Key* masterKey, Key* valueKey, std::string enc64, int rounds);

    Key* decodeKey(std::string key64);
    std::string hash(Key* salt, std::string str);

    void fillRandom(uint8_t* data, size_t length);

    Key* generateKey();

    std::string generatePassword(int length);

    void shred(Data* data);
};

#endif
