#ifndef __HASHWORD_UTILS_H_
#define __HASHWORD_UTILS_H_

#include <string>

void hexdump(const char* pos, int len);

double getPasswordEntropy(std::string password);

#endif
