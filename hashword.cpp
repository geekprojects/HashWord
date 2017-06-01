
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hashword.h"
#include "base64.h"
#include "utils.h"

#define AES_ROUNDS 10000

using namespace std;

HashWord::HashWord(string username)
    : m_crypto(username)
{
    m_database = new Database("hashword.db");

    m_username = username;
}

HashWord::~HashWord()
{
    if (m_globalSalt != NULL)
    {
        free(m_globalSalt);
    }

    m_database->close();
    delete m_database;
}

bool HashWord::open()
{
    bool res = m_database->open();
    if (!res)
    {
        return false;
    }

    vector<Table> tables;

    Table config;
    config.name = "config";
    config.columns.insert(Column("name", "TEXT", true));
    config.columns.insert(Column("value"));
    tables.push_back(config);

    Table keys;
    keys.name = "user_keys";
    keys.columns.insert(Column("user_hash", "TEXT", true));
    keys.columns.insert(Column("salt"));
    keys.columns.insert(Column("master_key_enc"));
    keys.columns.insert(Column("check_hash"));
    tables.push_back(keys);

    Table passwords;
    passwords.name = "passwords";
    passwords.columns.insert(Column("id", "TEXT", true));
    passwords.columns.insert(Column("salt_enc", "TEXT", false));
    passwords.columns.insert(Column("domain_user_enc", "TEXT", false));
    passwords.columns.insert(Column("domain_password_enc", "TEXT", false));
    tables.push_back(passwords);

    m_database->checkSchema(tables);

    string globalSalt64 = getConfig("globalSalt");
    if (globalSalt64.length() == 0)
    {
        m_globalSalt = m_crypto.generateKey();
        globalSalt64 = m_globalSalt->base64();
        setConfig("globalSalt", globalSalt64);
    }
    else
    {
        m_globalSalt = m_crypto.decodeKey(globalSalt64);
    }

    return true;
}

/*
hkdf((username + password), salt) -> User Key

*/

bool HashWord::saveMasterKey(Key* masterKey, string password)
{
    if (m_globalSalt == NULL)
    {
        printf("HashWord::saveMasterKey: No global salt!\n");
        return false;
    }

    // Generate a salt
    Key* salt = m_crypto.generateKey();

    Key* userKey = m_crypto.deriveKey(salt, m_globalSalt, m_username + password);

    Data* masterKeyEnc = m_crypto.encryptMultiple(userKey, NULL, (Data*)masterKey);
    string masterKey64 = base64_encode(masterKeyEnc->data, masterKeyEnc->length);

    m_crypto.shred(masterKeyEnc);
    free(masterKeyEnc);

    string userHash = m_crypto.hash(m_globalSalt, m_username);
    string salt64 = base64_encode(salt->data, salt->length);

    string checkHash = m_crypto.hash(masterKey, salt64);

    m_crypto.shred(userKey);
    free(userKey);

    m_crypto.shred(salt);
    free(salt);

    vector<string> args;
    args.push_back(userHash);
    args.push_back(salt64);
    args.push_back(masterKey64);
    args.push_back(checkHash);

    m_database->execute(
        "INSERT OR REPLACE INTO user_keys (user_hash, salt, master_key_enc, check_hash) VALUES (?, ?, ?, ?)",
        args);

    return true;
}


bool HashWord::hasMasterKey()
{
    PreparedStatement* stmt = m_database->prepareStatement("SELECT 1 FROM user_keys WHERE user_hash=?");
    string userHash = m_crypto.hash(NULL, m_username);
    stmt->bindString(1, userHash);

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        delete stmt;
        return false;
    }

    res = stmt->step();
    delete stmt;

    if (!res)
    {
        return false;
    }

    return true;
}

Key* HashWord::getMasterKey(string password)
{
    if (m_globalSalt == NULL)
    {
        printf("HashWord::saveMasterKey: No global salt!\n");
        return NULL;
    }

    PreparedStatement* stmt = m_database->prepareStatement("SELECT salt, master_key_enc, check_hash FROM user_keys WHERE user_hash=?");
    string userHash = m_crypto.hash(m_globalSalt, m_username);
    stmt->bindString(1, userHash);

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        delete stmt;
        return NULL;
    }

    res = stmt->step();
    if (!res)
    {
        delete stmt;
        return NULL;
    }

    string salt64 = stmt->getString(0);
    string masterKey64 = stmt->getString(1);
    string checkHash = stmt->getString(2);

    delete stmt;

    Key* salt = m_crypto.decodeKey(salt64);

    Key* userKey = m_crypto.deriveKey(salt, m_globalSalt, m_username + password);

    Key* masterKey = (Key*)m_crypto.decryptMultiple(userKey, NULL, masterKey64);

    string checkHash2 = m_crypto.hash(masterKey, salt64);

    m_crypto.shred(userKey);
    free(userKey);
    m_crypto.shred(salt);
    free(salt);

    if (checkHash != checkHash2)
    {
        m_crypto.shred(masterKey);
        free(masterKey);

        return NULL;
    }

    return masterKey;
}

bool HashWord::savePassword(Key* masterKey, string domain, string domainUser, string domainPassword)
{
    Key* salt = m_crypto.generateKey();
    Key* passwordKey = m_crypto.deriveKey(salt, m_globalSalt, m_username + domain);

    string domainUserEnc = m_crypto.encryptValue(masterKey, passwordKey, domainUser);
    string domainPasswordEnc = m_crypto.encryptValue(masterKey, passwordKey, domainPassword);

    m_crypto.shred(passwordKey);
    free(passwordKey);

    string idHash = m_crypto.hash(masterKey, m_username + ":" + domain);

    Data* saltEnc = m_crypto.encryptMultiple(masterKey, NULL, salt);
    string saltEnc64 = base64_encode(saltEnc->data, saltEnc->length);

    vector<string> args;
    args.push_back(idHash);
    args.push_back(saltEnc64);
    args.push_back(domainUserEnc);
    args.push_back(domainPasswordEnc);

    m_database->execute(
        "INSERT OR REPLACE INTO passwords (id, salt_enc, domain_user_enc, domain_password_enc) VALUES (?, ?, ?, ?)",
        args);

    return true;
}

bool HashWord::savePassword(Key* masterKey, string domain, std::string domainPassword)
{
    return savePassword(masterKey, domain, "", domainPassword);
}

bool HashWord::getPassword(Key* masterKey, std::string domain, PasswordDetails& details)
{
    string idHash = m_crypto.hash(masterKey, m_username + ":" + domain);

    PreparedStatement* stmt = m_database->prepareStatement(
        "SELECT domain_user_enc, domain_password_enc, salt_enc FROM passwords WHERE id=?");
    stmt->bindString(1, idHash);

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        delete stmt;
        return false;
    }

    res = stmt->step();
    if (!res)
    {
        printf(
            "HashWord::getPassword: Failed to find a password for the domain: %s\n",
            domain.c_str());

        delete stmt;
        return false;
    }

    string domainUserEnc64 = stmt->getString(0);
    string domainPasswordEnc64 = stmt->getString(1);
    string saltEnc64 = stmt->getString(2);

    delete stmt;

    Key* salt = (Key*)m_crypto.decryptMultiple(masterKey, NULL, saltEnc64);

    Key* passwordKey = m_crypto.deriveKey(salt, m_globalSalt, m_username + domain);
    m_crypto.shred(salt);
    free(salt);

    details.username = m_crypto.decryptValue(masterKey, passwordKey, domainUserEnc64);
    details.password = m_crypto.decryptValue(masterKey, passwordKey, domainPasswordEnc64);

    m_crypto.shred(passwordKey);
    free(passwordKey);

    return true;
}

std::string HashWord::getConfig(std::string name)
{
    PreparedStatement* stmt = m_database->prepareStatement("SELECT value FROM config WHERE name=?");
    stmt->bindString(1, name);

    bool res;
    res = stmt->executeQuery();
    if (res)
    {
        res = stmt->step();
    }

    if (!res)
    {
        delete stmt;
        return "";
    }

    string value = stmt->getString(0);
    delete stmt;

    return value;
}

void HashWord::setConfig(std::string name, std::string value)
{
    vector<string> args;
    args.push_back(name);
    args.push_back(value);
    m_database->execute("INSERT INTO config (name, value) VALUES (?, ?)", args);
}


