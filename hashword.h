#ifndef __HASHWORD_H_
#define __HASHWORD_H_

#include "database.h"
#include "data.h"

#include "openaes/oaes_lib.h"
#include "sha/sha.h"

class HashWord
{
 private:
    Database* m_database;

    std::string m_username;
    uint8_t m_iv[OAES_BLOCK_SIZE];
    Key* m_globalSalt;

    Key* deriveKey(Key* salt, std::string password);

    std::string encrypt64(Key* key, uint8_t* in, size_t inLength);
    std::string encrypt64(Key* key, Data* data);
    Data* encrypt(Key* key, uint8_t* in, size_t inLength);
    Data* encrypt(Key* key, Data* data);
    Data* encryptMultiple(Key* key1, Key* key2, Data* value);
    std::string encryptValue(Key* masterKey, Key* valueKey, std::string value);

    Data* decrypt(Key* key, Data* encData);
    Data* decrypt(Key* key, std::string enc64);
    Data* decryptMultiple(Key* key1, Key* key2, Data* enc);
    Data* decryptMultiple(Key* key1, Key* key2, std::string enc64);
    std::string decryptValue(Key* masterKey, Key* valueKey, std::string enc64);

    Key* decodeKey(std::string key64);
    std::string hash(Key* salt, std::string str);

    void fillRandom(uint8_t* data, size_t length);

    std::string getConfig(std::string name);
    void setConfig(std::string name, std::string value);

 public:
    HashWord(std::string username);
    ~HashWord();

    bool open();

    Key* generateKey();

    bool hasMasterKey();
    bool saveMasterKey(Key* masterKey, std::string password);
    Key* getMasterKey(std::string password);

    bool savePassword(Key* masterKey, std::string domain, std::string domainUser, std::string domainPassword);
    bool savePassword(Key* masterKey, std::string domain, std::string domainPassword);
    bool getPassword(Key* masterKey, std::string domain);
};

#endif
