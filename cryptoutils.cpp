
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hashword.h"
#include "base64.h"
#include "utils.h"
#include "cryptoutils.h"

#define AES_ROUNDS 10000

using namespace std;

CryptoUtils::CryptoUtils(string ivstr)
{
    int i;
    for (i = 0; i < OAES_BLOCK_SIZE; i++)
    {
        m_iv[i] = ivstr.at(i % ivstr.length());
    }
}

CryptoUtils::~CryptoUtils()
{
}

Key* CryptoUtils::generateKey()
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

Data* CryptoUtils::encrypt(Key* key, uint8_t* in, size_t inLength)
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
        printf("CryptoUtils::encrypt: Unable to get encrypted length!\n");
        exit(1);
    }

    uint8_t iv[OAES_BLOCK_SIZE];
    memcpy(iv, m_iv, OAES_BLOCK_SIZE);

    Data* encData = Data::alloc(encLen);

    res = oaes_encrypt(oaes, in, inLength, encData->data, &(encData->length), iv, &pad);

    oaes_free(&oaes);

    if (res != OAES_RET_SUCCESS)
    {
        printf("CryptoUtils::encrypt: Unable to encrypt!\n");
        exit(1);
    }

    return encData;
}

Data* CryptoUtils::encrypt(Key* key, Data* data)
{
    return encrypt(key, data->data, data->length);
}

std::string CryptoUtils::encrypt64(Key* key, uint8_t* in, size_t inLength)
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

std::string CryptoUtils::encrypt64(Key* key, Data* data)
{
    return encrypt64(key, data->data, data->length);
}

Data* CryptoUtils::encryptMultiple(Key* key1, Key* key2, Data* value)
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

string CryptoUtils::encryptValue(Key* masterKey, Key* valueKey, string value)
{
    size_t valueDataLen = sizeof(Container) + value.length();
    if (valueDataLen < 256)
    {
        valueDataLen = 256;
    }

    Data* valueData = Data::alloc(valueDataLen);
    valueData->length = valueDataLen;

    // The value we encrypt embeds its size
    Container* valueContainer = (Container*)(valueData->data);
    fillRandom((uint8_t*)valueContainer, valueDataLen);
    valueContainer->length = value.length();
    valueContainer->timestamp = time(NULL);
    memcpy(valueContainer->data, value.c_str(), value.length());

    Data* encValue = encryptMultiple(masterKey, valueKey, valueData);

    string valueEnc = base64_encode(encValue->data, encValue->length);

    shred(encValue);
    free(encValue);

    shred(valueData);
    free(valueData);

    return valueEnc;
}

Data* CryptoUtils::decrypt(Key* key, Data* encData)
{
    OAES_RET res;

    OAES_CTX* oaes = oaes_alloc(&m_random);

    res = oaes_key_import_data(oaes, key->data, key->length);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("CryptoUtils::decrypt: Failed to import key: res=%d\n", res);
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
        printf("CryptoUtils::decrypt: Failed to get decrypt length: res=%d\n", res);
        return NULL;
    }

    Data* dec = Data::alloc(decLen);
    dec->length = decLen;
    res = oaes_decrypt(oaes, encData->data, encData->length, dec->data, &(dec->length), iv, pad);

    oaes_free(&oaes);

    if (res != OAES_RET_SUCCESS)
    {
        free(dec);
        printf("CryptoUtils::decrypt: Failed to decrypt data: res=%d\n", res);
        return NULL;
    }

    return dec;
}

Data* CryptoUtils::decrypt(Key* key, std::string enc64)
{
    OAES_RET res;
    string enc = base64_decode(enc64);

    OAES_CTX* oaes = oaes_alloc(&m_random);

    res = oaes_key_import_data(oaes, key->data, key->length);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("CryptoUtils::decrypt: Failed to import key: res=%d\n", res);
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
        printf("CryptoUtils::decrypt: Failed to get decrypt length: res=%d\n", res);
        return NULL;
    }

    Data* dec = Data::alloc(decLen);
    res = oaes_decrypt(oaes, (uint8_t*)enc.c_str(), enc.length(), dec->data, &(dec->length), iv, pad);

    oaes_free(&oaes);

    if (res != OAES_RET_SUCCESS)
    {
        free(dec);
        printf("CryptoUtils::decrypt: Failed to decrypt data: res=%d\n", res);
        return NULL;
    }

    return dec;
}

Data* CryptoUtils::decryptMultiple(Key* key1, Key* key2, Data* enc)
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

Data* CryptoUtils::decryptMultiple(Key* key1, Key* key2, std::string enc64)
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

string CryptoUtils::decryptValue(Key* masterKey, Key* valueKey, std::string enc64)
{
    Data* decData = decryptMultiple(masterKey, valueKey, enc64);

    Container* valueData = (Container*)decData->data;
    string value = string((char*)valueData->data, valueData->length);

    shred(decData);
    free(decData);

    return value;
}

std::string CryptoUtils::hash(Key* salt, std::string str)
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

Key* CryptoUtils::deriveKey(Key* salt, Key* salt2, std::string ikm)
{
    int buflen = 32;
    Key* newKey = Key::alloc(buflen);

    int res = hkdf(
        SHA512,
        salt->data, salt->length,
        (uint8_t*)ikm.c_str(), ikm.length(),
        salt2->data, salt2->length,
        newKey->data, newKey->length);
    if (res != shaSuccess)
    {
        shred(newKey);
        free(newKey);
        return NULL;
    }

    //printf("CryptoUtils::deriveKey: hkdf res=%d\n", res);
    //printf("CryptoUtils::deriveKey: key:\n");
    //hexdump((char*)newKey->data, newKey->length);

    return newKey;
}

/*
hkdf((username + password), salt) -> User Key

*/

Key* CryptoUtils::decodeKey(std::string key64)
{
    string keyStr = base64_decode(key64);
    Key* key = Key::alloc(keyStr.length());
    memcpy(key->data, keyStr.c_str(), keyStr.length());
    return key;
}

// This assumes that srandomdev has already been called!
void CryptoUtils::fillRandom(uint8_t* data, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++)
    {
        data[i] = random() % 256;
    }
}

void CryptoUtils::shred(Data* data)
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

string g_lower = "abcdefghijklmnopqrstuvwxyz";
string g_upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
string g_numbers = "0123456789";
string g_other = "!@#$%^&*()/";

string CryptoUtils::generatePassword(int length)
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

