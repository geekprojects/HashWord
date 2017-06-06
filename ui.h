#ifndef __HASHWORD_UI_H_
#define __HASHWORD_UI_H_

#include <string>

std::string getPassword(std::string prompt);
void showPassword(std::string username, std::string password);
bool checkPassword(std::string password);

std::string getScriptPassword();

#endif
