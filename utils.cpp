
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include <cinttypes>

#include "utils.h"
#include "zxcvbn/zxcvbn.h"

using namespace std;

void hexdump(const char* pos, int len)
{
    int i;
    for (i = 0; i < len; i += 16)
    {
        int j;
        printf("%08" PRIx64 ": ", (uint64_t)(pos + i));
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            printf("%02x ", (uint8_t)pos[i + j]);
        }
        for (j = 0; j < 16 && (i + j) < len; j++)
        {
            char c = pos[i + j];
            if (!isprint(c))
            {
                c = '.';
            }
            printf("%c", c);
        }
        printf("\n");
    }
}

double getPasswordEntropy(string password)
{
    ZxcMatch_t *Info;

    const char *UsrDict[] =
    {
        NULL
    };

    return ZxcvbnMatch(password.c_str(), UsrDict, &Info);
}

