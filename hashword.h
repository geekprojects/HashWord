#ifndef __HASHWORD_H_
#define __HASHWORD_H_

#include "database.h"

#include "openaes/oaes_lib.h"
#include "sha/sha.h"

struct Data
{
    size_t length;
    uint8_t data[0];
};

struct Key
{
    size_t length;
    uint8_t key[0];
};

class HashWord
{
 private:
    Database* m_database;

    std::string m_username;
    uint8_t m_iv[OAES_BLOCK_SIZE];

    Key* deriveKey(Key* salt, std::string password);

    std::string encrypt64(Key* key, uint8_t* in, size_t inLength);
    std::string encrypt64(Key* key, Data* data);
    Data* encrypt(Key* key, uint8_t* in, size_t inLength);
    Data* encrypt(Key* key, Data* data);
    Data* decrypt(Key* key, Data* encData);
    Data* decrypt(Key* key, std::string enc64);
    std::string hash(Key* salt, std::string str);

    void fillRandom(uint8_t* data, size_t length);

 public:
    HashWord(std::string username);
    ~HashWord();

    bool open();

    Key* generateKey();

    bool saveMasterKey(Key* masterKey, std::string password);
    Key* getMasterKey(std::string password);

    bool savePassword(Key* masterKey, std::string domain, std::string domainPassword);
    bool getPassword(Key* masterKey, std::string domain);
};

#endif
