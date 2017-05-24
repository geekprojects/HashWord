
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "hashword.h"

using namespace std;

string getPassword(string prompt)
{
    string password = "";
    struct termios tsave, chgit;

    printf("%s: ", prompt.c_str());
    fflush(stdout);

    // Save the current state
    if (ioctl(0, TIOCGETA, &tsave) == -1)
    {
        printf("Failed to store terminal settings!\n");
        exit(1);
    }
    chgit = tsave;

    // Turn off canonial mode and echoing
    chgit.c_lflag &= ~(ICANON|ECHO);
    chgit.c_cc[VMIN] = 1;
    chgit.c_cc[VTIME] = 0;
    if (ioctl(0, TIOCSETA, &chgit) == -1)
    {
        printf("Failed to modify terminal settings!\n");
        exit(1);
    }

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

    if (ioctl(0, TIOCSETA, &tsave) == -1)
    {
        printf("Failed to restore terminal settings!\n");
        exit(1);
    }
    return password;
}

int main(int argc, char** argv)
{
    HashWord hashWord("ian");
    hashWord.open();

    if (argc < 2)
    {
        return 1;
    }

    char* command = argv[1];

    if (!strncmp("init", command, 4))
    {
        string password1 = getPassword("Password");
        string password2 = getPassword("Retype password");
        if (password1 != password2)
        {
            printf("Passwords do not match\n");
            return 1;
        }
printf("HashWord: Generating new master key:\n");
        Key* masterKey = hashWord.generateKey();
printf("HashWord: Saving...\n");
        hashWord.saveMasterKey(masterKey, password1);
    }
    else if (!strncmp("showkey", command, 7))
    {
        string password1 = getPassword("Password");
        hashWord.getMasterKey(password1);
    }
else if (!strncmp("savepassword", command, 12))
{
if (argc < 3)
{
return 1;
}
char* domain = argv[2];
        string masterPassword = getPassword("Master Password");
        string domainPassword = getPassword("Domain Password");
        Key* masterKey = hashWord.getMasterKey(masterPassword);
        hashWord.savePassword(masterKey, string(domain), domainPassword);
    }
else if (!strncmp("getpassword", command, 11))
{
if (argc < 3)
{
return 1;
}
char* domain = argv[2];
        string masterPassword = getPassword("Master Password");
        Key* masterKey = hashWord.getMasterKey(masterPassword);
        hashWord.getPassword(masterKey, string(domain));
    }


    return 0;
}

