#ifndef __HASHWORD_DATA_H_
#define __HASHWORD_DATA_H_

#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include <string>

struct Data
{
    size_t length;
    uint8_t data[0];

    static Data* alloc(size_t size);

    std::string encode();
    static std::string encode(uint8_t* data, unsigned int len);
    static Data* decode(std::string enc);
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
