#ifndef __HASHWORD_DATA_H_
#define __HASHWORD_DATA_H_

#include <stdint.h>
#include <sys/types.h>

#include <string>

struct Data
{
    size_t length;
    uint8_t data[0];

    std::string base64();

    static Data* alloc(size_t size);
};

struct Key : public Data
{
    static Key* alloc(size_t size);
};

#endif
