
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
#include "utils.h"

using namespace std;

void setPasswordMode(struct termios* tsave)
{
    struct termios chgit;
    int res;

    // Save the current state
    res = tcgetattr(0, tsave);
    if (res == -1)
    {
        printf("Failed to store terminal settings!\n");
        exit(1);
    }

    chgit = *tsave;

    // Turn off canonial mode and echoing
    chgit.c_lflag &= ~(ICANON|ECHO);
    chgit.c_cc[VMIN] = 1;
    chgit.c_cc[VTIME] = 0;

    res = tcsetattr(0, TCSANOW, &chgit);
    if (res == -1)
    {
        printf("Failed to modify terminal settings!\n");
        exit(1);
    }
}

void resetMode(struct termios* tsave)
{
    int res;

    res = tcsetattr(0, TCSANOW, tsave);
    if (res == -1)
    {
        printf("Failed to restore terminal settings!\n");
        exit(1);
    }
}

SecureString getPassword(string prompt)
{
    SecureString password;
    struct termios tsave;

    setPasswordMode(&tsave);

    while (true)
    {
        printf("%s: ", prompt.c_str());
        fflush(stdout);

        password.clear();
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
        if (password.length() > 0)
        {
            break;
        }
    }

    resetMode(&tsave);

    return password;
}

void hideLines(int number)
{
    int i;
    printf("%c[%dA", 0x1B, number);

    for (i = 0; i < number; i++)
    {
        printf("%c[2K", 0x1B);
        printf("%c[1B", 0x1B);
    }

    printf("%c[2K\n", 0x1B);
}

void showPassword(SecureString username, SecureString password, bool showEntropy)
{
    struct termios tsave;

    printf("Username: %s\n", username.c_str());
    if (showEntropy)
    {
        printf("Password: %s (%0.2f entropy bits)\n", password.c_str(), getPasswordEntropy(password));
    }
    else
    {
        printf("Password: %s\n", password.c_str());
    }

    printf("Press a key to hide the password");
    fflush(stdout);

    setPasswordMode(&tsave);
    getchar();

    resetMode(&tsave);

    hideLines(2);
}

SecureString getScriptPassword()
{
    char buffer[1024];
    char* res;

    res = fgets(buffer, 1024, stdin);
    if (res == NULL)
    {
        return "";
    }
    int len = strlen(buffer);
    if (buffer[len - 1] == '\n')
    {
        buffer[len - 1] = 0;
    }
    return string(buffer);
}

bool confirm(string prompt)
{
    struct termios tsave;
    char c;
    while (true)
    {
        printf("%s [Yn]: ", prompt.c_str());
        fflush(stdout);

        setPasswordMode(&tsave);
        c = getchar();
        resetMode(&tsave);
        printf("%c\n", c);

        if (c == 'Y' || c == 'n' || c == 'N')
        {
            break;
        }
    }
    return (c == 'Y');
}


