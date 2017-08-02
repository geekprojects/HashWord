#ifndef __HASHWORD_DATA_H_
#define __HASHWORD_DATA_H_

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include <string>

#include "securestring.h"

struct Data
{
    size_t length;
    uint8_t data[0];

    static Data* alloc(size_t size);

    std::string encode();
    static std::string encode(uint8_t* data, unsigned int len);
    static Data* decode(SecureString enc);
    static Data* decode(std::string enc);
    static Data* decode(const char* enc, size_t length);
};

struct Key : public Data
{
    static Key* alloc(size_t size);
};

struct Container
{
    size_t length;
    time_t timestamp;
    uint8_t data[0];
};

#endif
