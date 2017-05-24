
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libscrypt.h>

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

    hexdump((char*)m_iv, OAES_BLOCK_SIZE);
}

HashWord::~HashWord()
{
    m_database->close();
    delete m_database;
}

bool HashWord::open()
{
    bool res = m_database->open();
    vector<Table> tables;

    Table keys;
    keys.name = "user_keys";
    keys.columns.insert(Column("user", "TEXT", true));
    keys.columns.insert(Column("salt"));
    keys.columns.insert(Column("master_key_enc"));
    tables.push_back(keys);

Table passwords;
passwords.name = "passwords";
passwords.columns.insert(Column("user", "TEXT", true));
passwords.columns.insert(Column("domain_hash", "TEXT", true));
passwords.columns.insert(Column("salt", "TEXT", false));
passwords.columns.insert(Column("domain_password_enc", "TEXT", false));
tables.push_back(passwords);

    m_database->checkSchema(tables);
    return true;
}

Key* HashWord::generateKey()
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc();

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

    Key* key = (Key*)malloc(sizeof(Key) + keyLen);
    if (key == NULL)
    {
        oaes_free(&oaes);
        return NULL;
    }
    key->length = keyLen;

    res = oaes_key_export_data(oaes, key->key, &keyLen);
    if (res != OAES_RET_SUCCESS)
    {
        free(key);
        oaes_free(&oaes);
        return NULL;
    }

    oaes_free(&oaes);

    printf("HashWord::generateKey: Generated key:\n");
    hexdump((char*)key->key, keyLen);

    return key;
}

Data* HashWord::encrypt(Key* key, uint8_t* in, size_t inLength)
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc();

    res = oaes_key_import_data(oaes, key->key, key->length);

    size_t encLen;
    uint8_t pad = 0;

    // Get the length
    res = oaes_encrypt(oaes, in, inLength, NULL, &encLen, NULL, &pad);
    if (res != OAES_RET_SUCCESS)
    {
        printf("HashWord::encrypt: Unable to get encrypted length!\n");
        exit(1);
    }

    uint8_t iv[OAES_BLOCK_SIZE];
    memcpy(iv, m_iv, OAES_BLOCK_SIZE);

    Data* encData = (Data*)malloc(sizeof(Data) + encLen);
    encData->length = encLen;

    uint8_t encrypted[encLen];
    res = oaes_encrypt(oaes, in, inLength, encData->data, &(encData->length), iv, &pad);
    if (res != OAES_RET_SUCCESS)
    {
        printf("HashWord::encrypt: Unable to encrypt!\n");
        exit(1);
    }

    oaes_free(&oaes);

/*
    printf("HashWord::encrypt: encrypted bytes (%lu -> %lu):\n", inLength, encData->length);
    hexdump((char*)encData->data, encData->length);
*/

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
    free(enc);

    //printf("HashWord::encrypt64: encrypted: %s\n", encrypted64.c_str());
    return encrypted64;
}

std::string HashWord::encrypt64(Key* key, Data* data)
{
    return encrypt64(key, data->data, data->length);
}

Data* HashWord::decrypt(Key* key, Data* encData)
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc();

    res = oaes_key_import_data(oaes, key->key, key->length);
if (res != OAES_RET_SUCCESS)
{
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
printf("HashWord::decrypt: Failed to get decrypt length: res=%d\n", res);
return NULL;
}

    Data* dec = (Data*)malloc(sizeof(Data) + decLen);
    dec->length = decLen;
    res = oaes_decrypt(oaes, encData->data, encData->length, dec->data, &(dec->length), iv, pad);
if (res != OAES_RET_SUCCESS)
{
free(dec);
printf("HashWord::decrypt: Failed to decrypt data: res=%d\n", res);
return NULL;
}

    oaes_free(&oaes);

    return dec;
}

Data* HashWord::decrypt(Key* key, std::string enc64)
{
    OAES_RET res;
    string enc = base64_decode(enc64);

    printf("HashWord::decrypt: encrypted bytes :\n");
    hexdump((char*)enc.c_str(), enc.length());

    OAES_CTX* oaes = oaes_alloc();

    res = oaes_key_import_data(oaes, key->key, key->length);
if (res != OAES_RET_SUCCESS)
{
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
printf("HashWord::decrypt: Failed to get decrypt length: res=%d\n", res);
return NULL;
}

    Data* dec = (Data*)malloc(sizeof(Data) + decLen);
    dec->length = decLen;
    res = oaes_decrypt(oaes, (uint8_t*)enc.c_str(), enc.length(), dec->data, &(dec->length), iv, pad);
if (res != OAES_RET_SUCCESS)
{
free(dec);
printf("HashWord::decrypt: Failed to decrypt data: res=%d\n", res);
return NULL;
}

    oaes_free(&oaes);

    return dec;
}

std::string HashWord::hash(Key* salt, std::string str)
{
    USHAContext ctx;
    USHAReset(&ctx, SHA512);
    if (salt != NULL)
    {
        USHAInput(&ctx, salt->key, salt->length);
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
    string info = "HashWord";

    int buflen = 32;
    Key* newKey = (Key*)malloc(sizeof(Key) + buflen);
    newKey->length = buflen;

    int res = hkdf(
        SHA512,
        salt->key, salt->length,
        (uint8_t*)ikm.c_str(), ikm.length(),
        (uint8_t*)info.c_str(), info.length(),
        newKey->key, newKey->length);

    //printf("HashWord::deriveKey: hkdf res=%d\n", res);
    //printf("HashWord::deriveKey: key:\n");
    //hexdump((char*)newKey->key, newKey->length);

    return newKey;
}

/*
hkdf((username + password), salt) -> User Key

*/

bool HashWord::saveMasterKey(Key* masterKey, string password)
{
    // Generate a salt
    Key* salt = generateKey();

    Key* userKey = deriveKey(salt, password);

    printf("Hashword::getMasterKey: user key:\n");
    hexdump((char*)userKey->key, userKey->length);

    Data* masterKeyEnc = encrypt(userKey, masterKey->key, masterKey->length);
    int i;
    for (i = 0; i < AES_ROUNDS; i++)
    {
        Data* newMasterKeyEnc = encrypt(userKey, masterKeyEnc->data, masterKeyEnc->length);
        free(masterKeyEnc);
        masterKeyEnc = newMasterKeyEnc;
    }
    string masterKey64 = base64_encode(masterKeyEnc->data, masterKeyEnc->length);
    free(masterKeyEnc);
    printf("HashWord::createKey: masterKey64: %s\n", masterKey64.c_str());

    string salt64 = base64_encode(salt->key, salt->length);
    printf("HashWord::createKey: salt: %s\n", salt64.c_str());

    vector<string> args;
    args.push_back(m_username);
    args.push_back(salt64);
    args.push_back(masterKey64);

    m_database->execute(
        "INSERT OR REPLACE INTO user_keys (user, salt, master_key_enc) VALUES (?, ?, ?)",
        args);

    return true;
}

Key* decodeKey(std::string key64)
{
    string keyStr = base64_decode(key64);
    Key* key = (Key*)malloc(sizeof(Key) + keyStr.length());
    key->length = keyStr.length();
    memcpy(key->key, keyStr.c_str(), keyStr.length());
    return key;
}

Key* HashWord::getMasterKey(string password)
{
    PreparedStatement* stmt = m_database->prepareStatement("SELECT salt, master_key_enc FROM user_keys WHERE user=?");
stmt->bindString(1, m_username);

bool res;
res = stmt->executeQuery();
    if (!res)
    {
        return NULL;
    }

res = stmt->step();
if (!res)
{
return NULL;
}

    string salt64 = stmt->getString(0);
    string masterKey64 = stmt->getString(1);

    printf("Hashword::getMasterKey: salt64=%s\n", salt64.c_str());
    printf("Hashword::getMasterKey: masterKey64=%s\n", masterKey64.c_str());

    Key* salt = decodeKey(salt64);
    //hexdump((char*)salt->key, salt->length);

    Key* userKey = deriveKey(salt, password);

    printf("Hashword::getMasterKey: user key:\n");
    hexdump((char*)userKey->key, userKey->length);

    Data* masterKeyBytes = decrypt(userKey, masterKey64);
    if (masterKeyBytes == NULL)
    {
        return NULL;
    }
    int i;
    for (i = 0; i < AES_ROUNDS; i++)
    {
        Data* newMasterKeyBytes = decrypt(userKey, masterKeyBytes);
        free(masterKeyBytes);
        if (newMasterKeyBytes == NULL)
        {
            return NULL;
        }
        masterKeyBytes = newMasterKeyBytes;
    }

    printf("Hashword::getMasterKey: masterKey:\n");
    hexdump((char*)masterKeyBytes->data, masterKeyBytes->length);

    return (Key*)masterKeyBytes;
}

bool HashWord::savePassword(Key* masterKey, std::string domain, std::string domainPassword)
{
    Key* salt = generateKey();
    Key* passwordKey = deriveKey(salt, domain);

    size_t domainPasswordDataLen = sizeof(Data) + domainPassword.length();
    if (domainPasswordDataLen < 256)
    {
        domainPasswordDataLen = 256;
    }
    Data* domainPasswordData = (Data*)malloc(domainPasswordDataLen);
    fillRandom((uint8_t*)domainPasswordData, domainPasswordDataLen);
    domainPasswordData->length = domainPassword.length();
    memcpy(domainPasswordData->data, domainPassword.c_str(), domainPassword.length());

    Data* domainPasswordEnc1 = encrypt(passwordKey, (uint8_t*)domainPasswordData, domainPasswordDataLen);

int i;
for (i = 0; i < AES_ROUNDS; i++)
{
    Data* domainPasswordEnc1New = encrypt(passwordKey, domainPasswordEnc1);
free(domainPasswordEnc1);
domainPasswordEnc1 = domainPasswordEnc1New;
}

    string domainPasswordEnc2 = encrypt64(masterKey, domainPasswordEnc1);
    printf("HashWord::savePassword: domainPasswordEnc2=%s\n", domainPasswordEnc2.c_str());

/*
    string domainEnc = encrypt64(masterKey, (uint8_t*)domain.c_str(), domain.length());
    printf("HashWord::savePassword: domain=%s, domainHash=%s\n", domain.c_str(), domainEnc.c_str());
*/
    string domainHash = hash(masterKey, domain);
    printf("HashWord::savePassword: domain=%s, domainHash=%s\n", domain.c_str(), domainHash.c_str());

    string salt64 = base64_encode(salt->key, salt->length);

    vector<string> args;
    args.push_back(m_username);
    args.push_back(salt64);
    args.push_back(domainHash);
    args.push_back(domainPasswordEnc2);

    m_database->execute(
        "INSERT OR REPLACE INTO passwords (user, salt, domain_hash, domain_password_enc) VALUES (?, ?, ?, ?)",
        args);

    return true;
}

bool HashWord::getPassword(Key* masterKey, std::string domain)
{
    string domainHash = hash(masterKey, domain);
    printf("HashWord::getPassword: , domainHash=%s\n", domainHash.c_str());

    PreparedStatement* stmt = m_database->prepareStatement(
        "SELECT domain_password_enc, salt FROM passwords WHERE domain_hash=?");
    stmt->bindString(1, domainHash);

    bool res;
    res = stmt->executeQuery();
    if (!res)
    {
        return false;
    }
    res = stmt->step();
    if (!res)
    {
        printf(
            "HashWord::getPassword: Failed to find a password for the domain: %s\n",
            domain.c_str());
        return false;
    }

    string domainPasswordEnc64 = stmt->getString(0);
    string salt64 = stmt->getString(1);
    printf("HashWord::getPassword: domainPasswordEnc64=%s\n", domainPasswordEnc64.c_str());
    printf("HashWord::getPassword: salt64=%s\n", salt64.c_str());

    Key* salt = decodeKey(salt64);
    Key* passwordKey = deriveKey(salt, domain);
    printf("HashWord::getPassword: passwordKey:\n");
    hexdump((char*)passwordKey->key, passwordKey->length);

    Data* decData1 = decrypt(masterKey, domainPasswordEnc64);
    Data* decData2 = decrypt(passwordKey, decData1);

    int i;
    for (i = 0; i < AES_ROUNDS; i++)
    {
        Data* decData2New = decrypt(passwordKey, decData2);
        free(decData2);
        decData2 = decData2New;
    }

    Data* passwordData = (Data*)decData2->data;
    printf("HashWord::getPassword: decData2:\n");
    hexdump((char*)decData2->data, decData2->length);

    string password = string((char*)passwordData->data, passwordData->length);
    printf("HashWord::getPassword: %s\n", password.c_str());

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

