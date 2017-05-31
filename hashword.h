#ifndef __HASHWORD_H_
#define __HASHWORD_H_

#include "database.h"
#include "data.h"
#include "cryptoutils.h"

struct PasswordDetails
{
    std::string username;
    std::string password;
};

class HashWord
{
 private:
    Database* m_database;
    CryptoUtils m_crypto;

    std::string m_username;
    Key* m_globalSalt;

    std::string getConfig(std::string name);
    void setConfig(std::string name, std::string value);

 public:
    HashWord(std::string username);
    ~HashWord();

    bool open();

    bool hasMasterKey();
    bool saveMasterKey(Key* masterKey, std::string password);
    Key* getMasterKey(std::string password);

    bool savePassword(Key* masterKey, std::string domain, std::string domainUser, std::string domainPassword);
    bool savePassword(Key* masterKey, std::string domain, std::string domainPassword);
    bool getPassword(Key* masterKey, std::string domain, PasswordDetails& details);

    CryptoUtils* getCrypto() { return &m_crypto; }
};

#endif
