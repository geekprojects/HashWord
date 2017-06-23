#ifndef __HASHWORD_H_
#define __HASHWORD_H_

#include "database.h"
#include "data.h"
#include "cryptoutils.h"

#define CONFIG_GLOBAL_SALT "globalSalt"
#define CONFIG_ROUNDS "rounds"

#define HASHWORD_KD_HKDF 1 // SHA512 Key derivation
#define HASHWORD_KD_SCRYPT 2 // Scrypt Key Derivation

#define HASHWORD_KD HASHWORD_KD_SCRYPT

struct PasswordDetails
{
    std::string username;
    std::string info;
    std::string password;
};

class HashWord
{
 private:
    Database* m_database;
    CryptoUtils m_crypto;

    std::string m_username;
    Key* m_globalSalt;
    int m_rounds;

    bool hasConfig(std::string name);
    std::string getConfig(std::string name);
    int getConfigInt(std::string name);
    void setConfig(std::string name, std::string value);
    void setConfig(std::string name, int value);

    bool savePassword(std::string idHash, std::string saltEnc64, std::string domainUserEnc64, std::string domainPasswordEnc64, std::string updatedEnc64);

 public:
    HashWord(std::string username, std::string dbpath);
    ~HashWord();

    bool open();

    bool hasMasterKey();
    bool saveMasterKey(Key* masterKey, std::string password);
    Key* getMasterKey(std::string password);
    std::string getUsername() { return m_username; }

    bool savePassword(Key* masterKey, std::string domain, std::string domainUser, std::string domainPassword);
    bool savePassword(Key* masterKey, std::string domain, std::string domainPassword);
    bool getPassword(Key* masterKey, std::string domain, std::string domainUser, PasswordDetails& details);
    bool hasPassword(Key* masterKey, std::string domain, std::string domainUser);

    bool sync(Key* masterKey, HashWord* syncHashWord, bool newOnly = false);

    CryptoUtils* getCrypto() { return &m_crypto; }
};

#endif
