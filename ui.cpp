
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "ui.h"

using namespace std;

#ifdef __APPLE__
#define TCGETA TIOCGETA
#define TCSETA TIOCSETA
#endif

void setPasswordMode(struct termios* tsave)
{
    struct termios chgit;

    // Save the current state
    if (ioctl(0, TCGETA, tsave) == -1)
    {
        printf("Failed to store terminal settings!\n");
        exit(1);
    }
    chgit = *tsave;

    // Turn off canonial mode and echoing
    chgit.c_lflag &= ~(ICANON|ECHO);
    chgit.c_cc[VMIN] = 1;
    chgit.c_cc[VTIME] = 0;
    if (ioctl(0, TCSETA, &chgit) == -1)
    {
        printf("Failed to modify terminal settings!\n");
        exit(1);
    }
}

void resetMode(struct termios* tsave)
{
    if (ioctl(0, TCSETA, tsave) == -1)
    {
        printf("Failed to restore terminal settings!\n");
        exit(1);
    }
}

string getPassword(string prompt)
{
    string password = "";
    struct termios tsave;

    printf("%s: ", prompt.c_str());
    fflush(stdout);

    setPasswordMode(&tsave);

    while (1)
    {
        int c = getchar();
        /* CR is ascii value 13, interrupt is -1, control-c is 3 */
        if (c == '\r' || c == '\n' || c == '\b' || c == -1 || c == 3)
        {
            break;
        }

        if (isprint(c))
        {
            password += c;
        }
    }

    printf("\n");

    resetMode(&tsave);

    return password;
}

void showPassword(string username, string password)
{
    struct termios tsave;

    printf("Username: %s\n", username.c_str());
    printf("Password: %s\n", password.c_str());
    printf("Press a key to hide the password");
    fflush(stdout);

    setPasswordMode(&tsave);
    getchar();

    resetMode(&tsave);

    printf("%c[2A", 0x1B);
    printf("%c[1K", 0x1B);
    printf("%c[1B", 0x1B);
    printf("%c[1K", 0x1B);
    printf("%c[1B", 0x1B);
    printf("%c[1K", 0x1B);
    printf("\n");
    printf("\n");
}

bool checkPassword(string password)
{
    bool lower = false;
    bool upper = false;
    bool numbers = false;
    bool other = false;

    int i;
    for (i = 0; i < password.length(); i++)
    {
        char c = password[i];
        if (islower(c))
        {
            lower = true;
        }
        else if (isupper(c))
        {
            upper = true;
        }
        else if (isdigit(c))
        {
            numbers = true;
        }
        else
        {
            other = true;
        }
    }

    int possibleChars = 0;
    if (lower)
    {
        possibleChars += 26;
    }
    if (upper)
    {
        possibleChars += 26;
    }
    if (numbers)
    {
        possibleChars += 10;
    }
    if (other)
    {
        possibleChars += 26;
    }

    unsigned long perms = 1;
    for (i = 0; i < password.length(); i++)
    {
        perms *= possibleChars;
    }
    printf("checkPassword: Permutations=%lu\n", perms);

    return true;
}

