
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "hashword.h"
#include "utils.h"
#include "cryptoutils.h"

#include "scrypt/libscrypt.h"

using namespace std;

CryptoUtils::CryptoUtils()
{
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

    Data* encData = Data::alloc(encLen + 16);

    int i;
    for (i = 0; i < 16; i += 4)
    {
        uint32_t r = m_random.rand32();
        encData->data[i + 0] = (r >> 24) & 0xff;
        encData->data[i + 1] = (r >> 16) & 0xff;
        encData->data[i + 2] = (r >> 8) & 0xff;
        encData->data[i + 3] = (r >> 0) & 0xff;
    }

    uint8_t iv[16];
    memcpy(iv, encData->data, 16);

    res = oaes_encrypt(oaes, in, inLength, &(encData->data[16]), &(encData->length), iv, &pad);
    encData->length += 16;

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

    string encrypted64 = enc->encode();
    shred(enc);
    free(enc);

    return encrypted64;
}

std::string CryptoUtils::encrypt64(Key* key, Data* data)
{
    return encrypt64(key, data->data, data->length);
}

Data* CryptoUtils::encryptMultiple(Key* key1, Key* key2, Data* value, int rounds)
{
    Data* encrypted = value;
    int i;
    for (i = 0; i < rounds; i++)
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

string CryptoUtils::encryptValue(Key* masterKey, Key* valueKey, string value, int rounds)
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

    Data* encValue = encryptMultiple(masterKey, valueKey, valueData, rounds);

    string valueEnc = encValue->encode();

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

    size_t decLen;
    uint8_t pad = 0;
    res = oaes_decrypt(oaes, &(encData->data[16]), encData->length - 16, NULL, &decLen, NULL, pad);
    if (res != OAES_RET_SUCCESS)
    {
        oaes_free(&oaes);
        printf("CryptoUtils::decrypt: Failed to get decrypt length: res=%d\n", res);
        return NULL;
    }

    uint8_t iv[16];
    memcpy(iv, encData->data, 16);

    Data* dec = Data::alloc(decLen);
    dec->length = decLen;
    res = oaes_decrypt(oaes, &(encData->data[16]), encData->length - 16, dec->data, &(dec->length), iv, pad);

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
    Data* enc = Data::decode(enc64);

    if (enc == NULL)
    {
        return NULL;
    }
    return decrypt(key, enc);
}

Data* CryptoUtils::decryptMultiple(Key* key1, Key* key2, Data* enc, int rounds)
{
    Data* decrypted = enc;
    int i;
    for (i = rounds - 1; i >= 0; i--)
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

Data* CryptoUtils::decryptMultiple(Key* key1, Key* key2, std::string enc64, int rounds)
{
    Data* encData = Data::decode(enc64);

    Data* decData = decryptMultiple(key1, key2, encData, rounds);

    shred(encData);
    free(encData);

    return decData;
}

string CryptoUtils::decryptValue(Key* masterKey, Key* valueKey, std::string enc64, int rounds)
{
    Data* decData = decryptMultiple(masterKey, valueKey, enc64, rounds);

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
    string hash = Data::encode(digest, SHA512HashSize);
    return hash;
}

Key* CryptoUtils::deriveKey(Key* salt, Key* salt2, std::string ikm)
{
#if HASHWORD_KD == HASHWORD_KD_HKDF
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

#elif HASHWORD_KD == HASHWORD_KD_SCRYPT

    int buflen = 32;
    Key* newKey = Key::alloc(buflen);

    int res;
    res = libscrypt_scrypt(
        (uint8_t*)ikm.c_str(),
        ikm.length(),
        salt->data,
        salt->length,
        16384, // SCRYPT_N
        8, // SCRYPT_r
        16, // SCRYPT_p
        newKey->data,
        newKey->length);

    if (res != 0)
    {
        free(newKey);
        return NULL;
    }

#endif

    return newKey;
}

Key* CryptoUtils::decodeKey(std::string key64)
{
    return (Key*)Data::decode(key64);
}

// This assumes that srandomdev has already been called!
void CryptoUtils::fillRandom(uint8_t* data, size_t length)
{
    size_t i;
    for (i = 0; i < length; i++)
    {
        data[i] = m_random.rand32() % 256;
    }
}

void CryptoUtils::shred(Data* data)
{
    volatile uint8_t* dest = data->data;

    size_t i;
    for (i = 0; i < data->length; i++)
    {
        dest[i] = m_random.rand32() % 255;
    }
    for (i = 0; i < data->length; i++)
    {
        dest[i] = 0;
    }
    for (i = 0; i < data->length; i++)
    {
        dest[i] = m_random.rand32() % 255;
    }
    for (i = 0; i < data->length; i++)
    {
        dest[i] = 255;
    }
    for (i = 0; i < data->length; i++)
    {
        dest[i] = 0;
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

