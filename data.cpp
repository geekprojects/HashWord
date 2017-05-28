
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

string Data::base64()
{
    return base64_encode(data, length);
}

