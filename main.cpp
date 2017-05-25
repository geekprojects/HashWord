
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <termios.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "hashword.h"

using namespace std;

#ifdef __APPLE__
#define TCGETA TIOCGETA
#define TCSETA TIOCSETA
#endif

string getPassword(string prompt)
{
    string password = "";
    struct termios tsave, chgit;

    printf("%s: ", prompt.c_str());
    fflush(stdout);

    // Save the current state
    if (ioctl(0, TCGETA, &tsave) == -1)
    {
        printf("Failed to store terminal settings!\n");
        exit(1);
    }
    chgit = tsave;

    // Turn off canonial mode and echoing
    chgit.c_lflag &= ~(ICANON|ECHO);
    chgit.c_cc[VMIN] = 1;
    chgit.c_cc[VTIME] = 0;
    if (ioctl(0, TCSETA, &chgit) == -1)
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

    if (ioctl(0, TCSETA, &tsave) == -1)
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
        string password1 = getPassword("New Master password");
        string password2 = getPassword("Retype new Master password");
        if (password1 != password2)
        {
            printf("Passwords do not match\n");
            return 1;
        }
        Key* masterKey = hashWord.generateKey();
        hashWord.saveMasterKey(masterKey, password1);

        masterKey->shred();
        free(masterKey);
    }
    else if (!strncmp("savepassword", command, 12))
    {
        if (argc < 3)
        {
            return 1;
        }
        const char* user = "";
        const char* domain = "";
        if (argc == 3)
        {
            domain = argv[2];
        }
        else if (argc == 4)
        {
            domain = argv[2];
            user = argv[3];
        }
        string masterPassword = getPassword("Master Password");
        string domainPassword = getPassword("Domain Password");
        Key* masterKey = hashWord.getMasterKey(masterPassword);
        if (masterKey == NULL)
        {
            printf("HashWord: Unable to unlock Master Key\n");
            return 1;
        }
        hashWord.savePassword(masterKey, string(domain), string(user), domainPassword);

        masterKey->shred();
        free(masterKey);
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
        if (masterKey == NULL)
        {
            printf("HashWord: Unable to unlock Master Key\n");
            return 1;
        }

        hashWord.getPassword(masterKey, string(domain));
        masterKey->shred();
        free(masterKey);
    }


    return 0;
}

