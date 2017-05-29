
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
{
    m_database = new Database("hashword.db");

    m_username = username;
    int i;
    for (i = 0; i < OAES_BLOCK_SIZE; i++)
    {
        m_iv[i] = m_username.at(i % m_username.length());
    }
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
        m_globalSalt = generateKey();
        globalSalt64 = m_globalSalt->base64();
        setConfig("globalSalt", globalSalt64);
    }
    else
    {
        m_globalSalt = decodeKey(globalSalt64);
    }

    return true;
}

Key* HashWord::generateKey()
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc(&m_random);

    res = oaes_key_gen_256(oaes);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        return NULL;
    }

    size_t keyLen;
    res = oaes_key_export_data(oaes, NULL, &keyLen);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        return NULL;
    }

    Key* key = Key::alloc(keyLen);
    if (key == NULL)
    {
        oaes_free(&oaes);
        return NULL;
    }

    res = oaes_key_export_data(oaes, key->data, &keyLen);
    if (res != OAES_RET_SUCCESS)
    {
        shred(key);
        free(key);
        oaes_free(&oaes);
        return NULL;
    }

    oaes_free(&oaes);

    return key;
}

Data* HashWord::encrypt(Key* key, uint8_t* in, size_t inLength)
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc(&m_random);

    res = oaes_key_import_data(oaes, key->data, key->length);

    size_t encLen;
    uint8_t pad = 0;

    // Get the length
    res = oaes_encrypt(oaes, in, inLength, NULL, &encLen, NULL, &pad);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("HashWord::encrypt: Unable to get encrypted length!\n");
        exit(1);
    }

    uint8_t iv[OAES_BLOCK_SIZE];
    memcpy(iv, m_iv, OAES_BLOCK_SIZE);

    Data* encData = Data::alloc(encLen);

    res = oaes_encrypt(oaes, in, inLength, encData->data, &(encData->length), iv, &pad);

    oaes_free(&oaes);

    if (res != OAES_RET_SUCCESS)
    {
        printf("HashWord::encrypt: Unable to encrypt!\n");
        exit(1);
    }

    return encData;
}

Data* HashWord::encrypt(Key* key, Data* data)
{
    return encrypt(key, data->data, data->length);
}

std::string HashWord::encrypt64(Key* key, uint8_t* in, size_t inLength)
{
    Data* enc = encrypt(key, in, inLength);

    if (enc == NULL)
    {
        return "";
    }

    string encrypted64 = base64_encode(enc->data, enc->length);
    shred(enc);
    free(enc);

    return encrypted64;
}

std::string HashWord::encrypt64(Key* key, Data* data)
{
    return encrypt64(key, data->data, data->length);
}

Data* HashWord::encryptMultiple(Key* key1, Key* key2, Data* value)
{
    Data* encrypted = value;
    int i;
    for (i = 0; i < AES_ROUNDS; i++)
    {
        Key* key;
        if (key2 == NULL || (i % 2) == 0)
        {
            key = key1;
        }
        else
        {
            key = key2;
        }
        Data* encryptedNew = encrypt(key, encrypted);
        if (encrypted != value)
        {
            shred(encrypted);
            free(encrypted);
        }
        encrypted = encryptedNew;
    }
    return encrypted;
}

string HashWord::encryptValue(Key* masterKey, Key* valueKey, string value)
{
    size_t valueDataLen = sizeof(Data) + value.length();
    if (valueDataLen < 256)
    {
        valueDataLen = 256;
    }

    Data* valueData = Data::alloc(valueDataLen);
    valueData->length = valueDataLen;

    // The value we encrypt embeds its size
    Data* valueContainer = (Data*)(valueData->data);
    fillRandom((uint8_t*)valueContainer, valueDataLen);
    valueContainer->length = value.length();
    memcpy(valueContainer->data, value.c_str(), value.length());

    Data* encValue = encryptMultiple(masterKey, valueKey, valueData);

    string valueEnc = base64_encode(encValue->data, encValue->length);

    shred(encValue);
    free(encValue);

    shred(valueData);
    free(valueData);

    return valueEnc;
}

Data* HashWord::decrypt(Key* key, Data* encData)
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc(&m_random);

    res = oaes_key_import_data(oaes, key->data, key->length);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("HashWord::decrypt: Failed to import key: res=%d\n", res);
        return NULL;
    }

    uint8_t iv[OAES_BLOCK_SIZE];
    memcpy(iv, m_iv, OAES_BLOCK_SIZE);

    size_t decLen;
    uint8_t pad = 0;
    res = oaes_decrypt(oaes, encData->data, encData->length, NULL, &decLen, NULL, pad);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("HashWord::decrypt: Failed to get decrypt length: res=%d\n", res);
        return NULL;
    }

    Data* dec = Data::alloc(decLen);
    dec->length = decLen;
    res = oaes_decrypt(oaes, encData->data, encData->length, dec->data, &(dec->length), iv, pad);

    oaes_free(&oaes);

    if (res != OAES_RET_SUCCESS)
    {
        free(dec);
        printf("HashWord::decrypt: Failed to decrypt data: res=%d\n", res);
        return NULL;
    }

    return dec;
}

Data* HashWord::decrypt(Key* key, std::string enc64)
{
    OAES_RET res;
    string enc = base64_decode(enc64);

    OAES_CTX* oaes = oaes_alloc(&m_random);

    res = oaes_key_import_data(oaes, key->data, key->length);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("HashWord::decrypt: Failed to import key: res=%d\n", res);
        return NULL;
    }

    uint8_t iv[OAES_BLOCK_SIZE];
    memcpy(iv, m_iv, OAES_BLOCK_SIZE);

    size_t decLen;
    uint8_t pad = 0;
    res = oaes_decrypt(oaes, (uint8_t*)enc.c_str(), enc.length(), NULL, &decLen, NULL, pad);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("HashWord::decrypt: Failed to get decrypt length: res=%d\n", res);
        return NULL;
    }

    Data* dec = Data::alloc(decLen);
    res = oaes_decrypt(oaes, (uint8_t*)enc.c_str(), enc.length(), dec->data, &(dec->length), iv, pad);

    oaes_free(&oaes);

    if (res != OAES_RET_SUCCESS)
    {
        free(dec);
        printf("HashWord::decrypt: Failed to decrypt data: res=%d\n", res);
        return NULL;
    }

    return dec;
}

Data* HashWord::decryptMultiple(Key* key1, Key* key2, Data* enc)
{
    Data* decrypted = enc;
    int i;
    for (i = AES_ROUNDS - 1; i >= 0; i--)
    {
        Key* key;
        if (key2 == NULL || (i % 2) == 0)
        {
            key = key1;
        }
        else
        {
            key = key2;
        }
        Data* decryptedNew = decrypt(key, decrypted);
        if (decrypted != enc)
        {
            shred(decrypted);
            free(decrypted);
        }
        decrypted = decryptedNew;
    }
    return decrypted;
}

Data* HashWord::decryptMultiple(Key* key1, Key* key2, std::string enc64)
{
    string encStr = base64_decode(enc64);
    Data* encData = Data::alloc(encStr.length());
    encData->length = encStr.length();
    memcpy(encData->data, encStr.c_str(), encStr.length());

    Data* decData = decryptMultiple(key1, key2, encData);

    shred(encData);
    free(encData);

    return decData;
}

string HashWord::decryptValue(Key* masterKey, Key* valueKey, std::string enc64)
{
    Data* decData = decryptMultiple(masterKey, valueKey, enc64);

    Data* valueData = (Data*)decData->data;
    string value = string((char*)valueData->data, valueData->length);

    shred(decData);
    free(decData);

    return value;
}

std::string HashWord::hash(Key* salt, std::string str)
{
    USHAContext ctx;
    USHAReset(&ctx, SHA512);
    if (salt != NULL)
    {
        USHAInput(&ctx, salt->data, salt->length);
    }
    USHAInput(&ctx, (uint8_t*)str.c_str(), str.length());

    uint8_t digest[USHAMaxHashSize];
    USHAResult(&ctx, digest);
    string hash = base64_encode(digest, SHA512HashSize);
    return hash;
}

Key* HashWord::deriveKey(Key* salt, std::string password)
{
    string ikm = m_username + password;

    int buflen = 32;
    Key* newKey = Key::alloc(buflen);

    int res = hkdf(
        SHA512,
        salt->data, salt->length,
        (uint8_t*)ikm.c_str(), ikm.length(),
        m_globalSalt->data, m_globalSalt->length,
        newKey->data, newKey->length);
    if (res != shaSuccess)
    {
        shred(newKey);
        free(newKey);
        return NULL;
    }

    //printf("HashWord::deriveKey: hkdf res=%d\n", res);
    //printf("HashWord::deriveKey: key:\n");
    //hexdump((char*)newKey->data, newKey->length);

    return newKey;
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
    Key* salt = generateKey();

    Key* userKey = deriveKey(salt, password);

    Data* masterKeyEnc = encryptMultiple(userKey, NULL, (Data*)masterKey);
    string masterKey64 = base64_encode(masterKeyEnc->data, masterKeyEnc->length);

    shred(masterKeyEnc);
    free(masterKeyEnc);

    string userHash = hash(m_globalSalt, m_username);
    string salt64 = base64_encode(salt->data, salt->length);

    string checkHash = hash(masterKey, salt64);

    shred(userKey);
    free(userKey);

    shred(salt);
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

Key* HashWord::decodeKey(std::string key64)
{
    string keyStr = base64_decode(key64);
    Key* key = Key::alloc(keyStr.length());
    memcpy(key->data, keyStr.c_str(), keyStr.length());
    return key;
}

bool HashWord::hasMasterKey()
{
    PreparedStatement* stmt = m_database->prepareStatement("SELECT 1 FROM user_keys WHERE user_hash=?");
    string userHash = hash(NULL, m_username);
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
    string userHash = hash(m_globalSalt, m_username);
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

    Key* salt = decodeKey(salt64);

    Key* userKey = deriveKey(salt, password);

    Key* masterKey = (Key*)decryptMultiple(userKey, NULL, masterKey64);

    string checkHash2 = hash(masterKey, salt64);

    shred(userKey);
    free(userKey);
    shred(salt);
    free(salt);

    if (checkHash != checkHash2)
    {
        shred(masterKey);
        free(masterKey);

        return NULL;
    }

    return masterKey;
}

bool HashWord::savePassword(Key* masterKey, string domain, string domainUser, string domainPassword)
{
    Key* salt = generateKey();
    Key* passwordKey = deriveKey(salt, domain);

    string domainUserEnc = encryptValue(masterKey, passwordKey, domainUser);
    string domainPasswordEnc = encryptValue(masterKey, passwordKey, domainPassword);

    shred(passwordKey);
    free(passwordKey);

    string idHash = hash(masterKey, m_username + ":" + domain);

    Data* saltEnc = encryptMultiple(masterKey, NULL, salt);
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
    string idHash = hash(masterKey, m_username + ":" + domain);

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

    Key* salt = (Key*)decryptMultiple(masterKey, NULL, saltEnc64);

    Key* passwordKey = deriveKey(salt, domain);
    shred(salt);
    free(salt);

    details.username = decryptValue(masterKey, passwordKey, domainUserEnc64);
    details.password = decryptValue(masterKey, passwordKey, domainPasswordEnc64);

    shred(passwordKey);
    free(passwordKey);

    return true;
}

// This assumes that srandomdev has already been called!
void HashWord::fillRandom(uint8_t* data, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++)
    {
        data[i] = random() % 256;
    }
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

string g_lower = "abcdefghijklmnopqrstuvwxyz";
string g_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
string g_numbers = "0123456789";
string g_other = "!@#$%^&*()/";

string HashWord::generatePassword(int length)
{
    string password = "";

    string possibleChars = g_lower + g_upper + g_numbers + g_other;

    int i;
    for (i = 0; i < length; i++)
    {
        int c = m_random.rand32() % possibleChars.length();

        password += possibleChars[c];
    }
    return password;
}

void HashWord::shred(Data* data)
{
    size_t i;
    for (i = 0; i < data->length; i++)
    {
        data->data[i] = m_random.rand32() % 255;
    }
    for (i = 0; i < data->length; i++)
    {
        data->data[i] = 0;
    }
    for (i = 0; i < data->length; i++)
    {
        data->data[i] = m_random.rand32() % 255;
    }
    for (i = 0; i < data->length; i++)
    {
        data->data[i] = 255;
    }
    for (i = 0; i < data->length; i++)
    {
        data->data[i] = 0;
    }
}

