#ifndef __BEYOND_RANDOM_H_
#define __BEYOND_RANDOM_H_

#include <stdint.h>

class Random
{
 private:
    uint32_t m_results[256];
    uint32_t m_resultsUsed;

    uint32_t m_mm[256];
    uint32_t m_aa;
    uint32_t m_bb;
    uint32_t m_cc;

    static void mix(uint32_t* s);

    bool init();
    bool init(uint32_t* buffer);
    void generateMore();

 public:
    Random();

    uint32_t rand32();

    uint32_t maxrand() { return 4294967295UL; } // unsigned 32 bits
    int range(int min, int max);
    double ranged(double min, double max);
};

#endif
