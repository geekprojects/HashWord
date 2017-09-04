
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hashword.h"
#include "utils.h"

#define ROUNDS_DEFAULT 50

using namespace std;

HashWord::HashWord(string username, string dbpath)
    : m_crypto()
{
    m_database = new Database(dbpath);

    m_username = SecureString(username);

    m_rounds = ROUNDS_DEFAULT;
}

HashWord::~HashWord()
{
    if (m_globalSalt != NULL)
    {
        free(m_globalSalt);
    }

    if (m_database != NULL)
    {
        m_database->close();
        delete m_database;
    }
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
    passwords.columns.insert(Column("domain_info_enc", "TEXT", false));
    passwords.columns.insert(Column("domain_password_enc", "TEXT", false));
    passwords.columns.insert(Column("updated_enc", "TEXT", false));
    tables.push_back(passwords);

    m_database->checkSchema(tables);

    if (hasConfig(CONFIG_GLOBAL_SALT))
    {
        SecureString globalSalt64 = getConfig(CONFIG_GLOBAL_SALT);
        m_globalSalt = m_crypto.decodeKey(globalSalt64);
    }
    else
    {
        m_globalSalt = m_crypto.generateKey();
        string globalSalt64 = m_globalSalt->encode();
        setConfig(CONFIG_GLOBAL_SALT, globalSalt64);
    }

    if (hasConfig(CONFIG_ROUNDS))
    {
        m_rounds = getConfigInt(CONFIG_ROUNDS);
    }
    else
    {
        m_rounds = ROUNDS_DEFAULT;
        setConfig(CONFIG_ROUNDS, m_rounds);
    }

    return true;
}

/*
hkdf((username + password), salt) -> User Key

*/

bool HashWord::saveMasterKey(Key* masterKey, SecureString password)
{
    if (m_globalSalt == NULL)
    {
        printf("HashWord::saveMasterKey: No global salt!\n");
        return false;
    }

    // Generate a salt
    Key* salt = m_crypto.generateKey();

    Key* userKey = m_crypto.deriveKey(salt, m_globalSalt, SecureString(m_username) + password);

    Data* masterKeyEnc = m_crypto.encryptMultiple(userKey, NULL, (Data*)masterKey, m_rounds);
    string masterKey64 = masterKeyEnc->encode();

    m_crypto.shred(masterKeyEnc);
    free(masterKeyEnc);

    SecureString userHash = m_crypto.hash(m_globalSalt, m_username);
    string salt64 = salt->encode();

    SecureString checkHash = m_crypto.hash(masterKey, salt64);

    m_crypto.shred(userKey);
    free(userKey);

    m_crypto.shred(salt);
    free(salt);

    vector<string> args;
    args.push_back(userHash.string());
    args.push_back(salt64);
    args.push_back(masterKey64);
    args.push_back(checkHash.string());

    m_database->execute(
        "INSERT OR REPLACE INTO user_keys (user_hash, salt, master_key_enc, check_hash) VALUES (?, ?, ?, ?)",
        args);

    return true;
}

bool HashWord::hasMasterKey()
{
    PreparedStatement* stmt = m_database->prepareStatement("SELECT 1 FROM user_keys WHERE user_hash=?");
    SecureString userHash = m_crypto.hash(NULL, SecureString(m_username));
    stmt->bindString(1, userHash.string());

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

Key* HashWord::getMasterKey(SecureString password)
{
    if (m_globalSalt == NULL)
    {
        printf("HashWord::saveMasterKey: No global salt!\n");
        return NULL;
    }

    PreparedStatement* stmt = m_database->prepareStatement("SELECT salt, master_key_enc, check_hash FROM user_keys WHERE user_hash=?");
    SecureString userHash = m_crypto.hash(m_globalSalt, m_username);
    stmt->bindString(1, userHash.string());

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
    SecureString checkHash = SecureString(stmt->getString(2));

    delete stmt;

    Key* salt = m_crypto.decodeKey(salt64);

    Key* userKey = m_crypto.deriveKey(salt, m_globalSalt, m_username + password);

    Key* masterKey = (Key*)m_crypto.decryptMultiple(userKey, NULL, masterKey64, m_rounds);

    SecureString checkHash2 = m_crypto.hash(masterKey, salt64);

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

bool HashWord::savePassword(Key* masterKey, SecureString domain, SecureString domainUser, SecureString domainPassword)
{
    if (domainUser.length() == 0)
    {
        domainUser = m_username;
    }

    Key* salt = m_crypto.generateKey();
    Key* passwordKey = m_crypto.deriveKey(salt, m_globalSalt, domainUser + domain);

    SecureString domainUserEnc = m_crypto.encryptValue(masterKey, passwordKey, domainUser, m_rounds);
    SecureString domainPasswordEnc = m_crypto.encryptValue(masterKey, passwordKey, domainPassword, m_rounds);

    m_crypto.shred(passwordKey);
    free(passwordKey);

    SecureString idHash = m_crypto.hash(masterKey, m_username + ":" + domainUser + ":" + domain);

    Data* saltEnc = m_crypto.encryptMultiple(masterKey, NULL, salt, m_rounds);
    string saltEnc64 = saltEnc->encode();

    time_t now = time(NULL);
    char updatedStr[16];
    snprintf(updatedStr, 16, "%lu", now);
    SecureString updatedEnc64 = m_crypto.encryptValue(masterKey, NULL, updatedStr, m_rounds);

    savePassword(idHash.string(), saltEnc64, domainUserEnc.string(), domainPasswordEnc.string(), updatedEnc64.string());

    return true;
}

bool HashWord::savePassword(Key* masterKey, SecureString domain, SecureString domainPassword)
{
    return savePassword(masterKey, domain, "", domainPassword);
}

bool HashWord::savePassword(
    std::string idHash,
    std::string saltEnc64,
    std::string domainUserEnc,
    std::string domainPasswordEnc,
    std::string updatedEnc64)
{
    vector<string> args;
    args.push_back(idHash);
    args.push_back(saltEnc64);
    args.push_back(domainUserEnc);
    args.push_back(domainPasswordEnc);
    args.push_back(updatedEnc64);

    m_database->execute(
        "INSERT OR REPLACE INTO passwords (id, salt_enc, domain_info_enc, domain_password_enc, updated_enc) VALUES (?, ?, ?, ?, ?)",
        args);

    return true;
}


bool HashWord::getPassword(Key* masterKey, SecureString domain, SecureString user, PasswordDetails& details)
{
    if (user.length() == 0)
    {
        user = m_username;
    }

    SecureString idHash = m_crypto.hash(masterKey, m_username + ":" + user + ":" + domain);

    PreparedStatement* stmt = m_database->prepareStatement(
        "SELECT domain_info_enc, domain_password_enc, salt_enc FROM passwords WHERE id=?");
    stmt->bindString(1, idHash.string());

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

    Key* salt = (Key*)m_crypto.decryptMultiple(masterKey, NULL, saltEnc64, m_rounds);

    Key* passwordKey = m_crypto.deriveKey(salt, m_globalSalt, user + domain);
    m_crypto.shred(salt);
    free(salt);

    details.username = m_crypto.decryptValue(masterKey, passwordKey, domainUserEnc64, m_rounds);
    details.password = m_crypto.decryptValue(masterKey, passwordKey, domainPasswordEnc64, m_rounds);

    m_crypto.shred(passwordKey);
    free(passwordKey);

    return true;
}

bool HashWord::hasPassword(Key* masterKey, SecureString domain, SecureString user)
{
    if (user.length() == 0)
    {
        user = m_username;
    }

    SecureString idHash = m_crypto.hash(masterKey, m_username + ":" + user + ":" + domain);

    PreparedStatement* stmt = m_database->prepareStatement(
        "SELECT domain_info_enc, domain_password_enc, salt_enc FROM passwords WHERE id=?");
    stmt->bindString(1, idHash.string());

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        delete stmt;
        return false;
    }

    res = stmt->step();
    delete stmt;

    return res;
}

enum SyncTarget
{
    NONE,
    OWN,
    SYNC
};

bool HashWord::sync(Key* masterKey, HashWord* syncHashWord, bool newOnly)
{
    PreparedStatement* stmt = m_database->prepareStatement(
        "SELECT id, salt_enc, domain_info_enc, domain_password_enc, updated_enc FROM passwords");

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        delete stmt;
        return false;
    }

    while (stmt->step())
    {
        string id = stmt->getString(0);
        string saltEnc64 = stmt->getString(1);
        string domainUserEnc = stmt->getString(2);
        string domainPasswordEnc = stmt->getString(3);
        string updatedEnc64 = stmt->getString(4);

        SecureString updatedStr = m_crypto.decryptValue(masterKey, NULL, updatedEnc64, m_rounds);
        uint64_t updated = atoll(updatedStr.c_str());

        //printf("HashWord::sync: updated=%lld\n", updated);

        PreparedStatement* syncStmt = syncHashWord->m_database->prepareStatement(
            "SELECT salt_enc, domain_info_enc, domain_password_enc, updated_enc FROM passwords WHERE id=?");
        syncStmt->bindString(1, id);

        res = syncStmt->executeQuery();
        if (!res)
        {
            return false;
        }

        SyncTarget target = NONE;

        res = syncStmt->step();
        if (!res)
        {
            printf("HashWord::sync: Password does not exist in sync DB!\n");
            target = SYNC;
        }
        else if (!newOnly)
        {
            string syncSaltEnc64 = syncStmt->getString(0);
            string syncDomainInfoEnc64 = syncStmt->getString(1);
            string syncDomainPasswordEnc64 = syncStmt->getString(2);
            string syncUpdatedEnc = syncStmt->getString(3);
            delete syncStmt;

            SecureString syncUpdatedStr = m_crypto.decryptValue(masterKey, NULL, syncUpdatedEnc, m_rounds);
            uint64_t syncUpdated = atoll(syncUpdatedStr.c_str());

            //printf("HashWord::sync:  -> syncUpdated=%lld\n", syncUpdated);

            if (updated > syncUpdated)
            {
                printf("HashWord::sync: Synchronising password\n");
                target = SYNC;
            }
            else if (updated < syncUpdated)
            {
                printf("HashWord::sync: Synchronising password\n");

                saltEnc64 = syncSaltEnc64;
                domainUserEnc = syncDomainInfoEnc64;
                domainPasswordEnc = syncDomainPasswordEnc64;
                updatedEnc64 = syncUpdatedEnc;
                target = OWN;
            }
        }

        if (target == SYNC)
        {
            syncHashWord->savePassword(id, saltEnc64, domainUserEnc, domainPasswordEnc, updatedEnc64);
        }
        else if (target == OWN)
        {
            savePassword(id, saltEnc64, domainUserEnc, domainPasswordEnc, updatedEnc64);
        }

    }
    delete stmt;

    // Now check for things in the other DB that we don't have
    if (!newOnly)
    {
        res = syncHashWord->sync(masterKey, this, true);
        if (!res)
        {
            return false;
        }
    }

    return true;
}

bool HashWord::hasConfig(std::string name)
{
    PreparedStatement* stmt = m_database->prepareStatement("SELECT 1 FROM config WHERE name=?");
    stmt->bindString(1, name);

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        return false;
    }

    res = stmt->step();

    delete stmt;

    return res;
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

int HashWord::getConfigInt(std::string name)
{
    string valueStr = getConfig(name);

    return atoi(valueStr.c_str());
}

void HashWord::setConfig(std::string name, std::string value)
{
    vector<string> args;
    args.push_back(name);
    args.push_back(value);
    m_database->execute("INSERT INTO config (name, value) VALUES (?, ?)", args);
}

void HashWord::setConfig(std::string name, int value)
{
    char valueStr[64];
    snprintf(valueStr, 64, "%d", value);
    setConfig(name, valueStr);
}

