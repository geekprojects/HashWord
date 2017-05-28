
#include "data.h"
#include "base64.h"

#include <stdlib.h>

using namespace std;

Data* Data::alloc(size_t length)
{
    Data* data = (Data*)malloc(sizeof(Data) + length);
    data->length = length;
    return data;
}

Key* Key::alloc(size_t length)
{
    Key* key = (Key*)malloc(sizeof(Key) + length);
    key->length = length;
    return key;
}


void Data::shred()
{
    size_t i;
    for (i = 0; i < length; i++)
    {
        data[i] = random() % 255;
    }
    for (i = 0; i < length; i++)
    {
        data[i] = 0;
    }
    for (i = 0; i < length; i++)
    {
        data[i] = random() % 255;
    }
    for (i = 0; i < length; i++)
    {
        data[i] = 255;
    }
    for (i = 0; i < length; i++)
    {
        data[i] = 0;
    }
}

string Data::base64()
{
    return base64_encode(data, length);
}

