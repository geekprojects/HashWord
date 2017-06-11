/*
 * Implementation of the ISAAC Cryptographic Pseudo Number Generator
 * Based on Public Domain implementation by Bob Jenkins
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/random.h>
#endif

#include "random.h"

Random::Random()
{
    init();
}

bool Random::init()
{
    uint32_t seed[256];

#ifdef __APPLE__

    int i;
    for (i = 0; i < 256; i += 64)
    {
        int res = getentropy(&(seed[i]), sizeof(uint32_t) * 64);
        if (res != 0)
        {
            return false;
        }
    }

#else
    FILE* fd;

    fd = fopen("/dev/urandom", "r");
    if (!fd)
    {
        return false;
    }

    int i;
    for (i = 0; i < 256; i++)
    {
        uint32_t word;
        int res;
        res = fread(&word, 4, 1, fd);
        if (res != 1)
        {
            break;
        }
        seed[i] = word;
    }
    fclose(fd);
#endif

    return init(seed);
}

void Random::mix(uint32_t* s)
{
    s[0] ^= s[1] << 11; s[3] += s[0]; s[1] += s[2];
    s[1] ^= s[2] >> 2;  s[4] += s[1]; s[2] += s[3];
    s[2] ^= s[3] << 8;  s[5] += s[2]; s[3] += s[4];
    s[3] ^= s[4] >> 16; s[6] += s[3]; s[4] += s[5];
    s[4] ^= s[5] << 10; s[7] += s[4]; s[5] += s[6];
    s[5] ^= s[6] >> 4;  s[0] += s[5]; s[6] += s[7];
    s[6] ^= s[7] << 8;  s[1] += s[6]; s[7] += s[0];
    s[7] ^= s[0] >> 9;  s[2] += s[7]; s[0] += s[1];
}

bool Random::init(uint32_t* seed)
{
    m_aa = 0;
    m_bb = 0;
    m_cc = 0;

    uint32_t initState[8];

    int i;
    for (i = 0; i < 8; i++)
    {
        initState[i] = 0x9e3779b9; // Golden Ratio
    }

    for (i = 0; i < 4; i++)
    {
        mix(initState);
    }

    for (i = 0; i < 256; i += 8)
    {
        int j;
        for (j = 0; j < 8; j++)
        {
            initState[j] += seed[i + j];
        }

        mix(initState);

        for (j = 0; j < 8; j++)
        {
            m_mm[i + j] = initState[j];
        }
    }

    for (i = 0; i < 256; i += 8)
    {
        int j;
        for (j = 0; j < 8; j++)
        {
            initState[j] += m_mm[i + j];
        }

        mix(initState);

        for (j = 0; j < 8; j++)
        {
            m_mm[i + j] = initState[j];
        }
    }

    // Force us to generate more results
    m_resultsUsed = 256;

    return true;
}

void Random::generateMore()
{
    m_cc++;
    m_bb += m_cc;

    int i;
    for (i = 0; i < 256; i++)
    {
        uint32_t x = m_mm[i];

        switch (i % 4)
        {
            case 0:
                m_aa = m_aa ^ (m_aa << 13);
                break;

            case 1:
                m_aa = m_aa ^ (m_aa >> 6);
                break;

            case 2:
                m_aa = m_aa ^ (m_aa << 2);
                break;

            case 3:
                m_aa = m_aa ^ (m_aa >> 16);
                break;
        }

         m_aa = m_mm[(i + 128) % 256] + m_aa;

         uint32_t y  = m_mm[(x >> 2) % 256] + m_aa + m_bb;
         m_mm[i] = y;
         m_bb = m_mm[(y >> 10) % 256] + x;
         m_results[i] = m_bb;
    }

    m_resultsUsed = 0;
}

uint32_t Random::rand32()
{
    if (m_resultsUsed >= 256)
    {
        generateMore();
    }

    return m_results[m_resultsUsed++];
}

int Random::range(int min, int max)
{
    float r = (max - min) + 1;
    float v1 = ((float)rand32() / (float)(maxrand()));
    float v2 = v1 * r;
    return min + (int)v2;
}

double Random::ranged(double min, double max)
{
    double rnd = (double)rand32() * (double)rand32();
    double r = (max - min) + 1;
    double v = (rnd / ((double)maxrand() * (double)maxrand() + 1)) * r;
    return min + v;
}

