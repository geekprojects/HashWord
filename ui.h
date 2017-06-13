#ifndef __HASHWORD_UI_H_
#define __HASHWORD_UI_H_

#include <string>

std::string getPassword(std::string prompt);
void showPassword(std::string username, std::string password);
double getPasswordEntropy(std::string password);

std::string getScriptPassword();

bool confirm(std::string prompt);

#endif
