#ifndef __HASHWORD_UI_H_
#define __HASHWORD_UI_H_

#include <string>

#include "securestring.h"

SecureString getPassword(std::string prompt);
void showPassword(SecureString username, SecureString password, bool showEntropy = true);

SecureString getScriptPassword();

bool confirm(std::string prompt);

#endif
