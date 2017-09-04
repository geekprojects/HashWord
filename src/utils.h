#ifndef __HASHWORD_UTILS_H_
#define __HASHWORD_UTILS_H_

#include <string>

#include "securestring.h"

void hexdump(const char* pos, int len);

double getPasswordEntropy(SecureString password);

void scrubData(uint8_t* data, size_t length);

#endif
