
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <getopt.h>

#include "hashword.h"
#include "ui.h"

using namespace std;

static const struct option g_options[] =
{
    { "user",    required_argument, NULL, 'u' },
    { NULL,      0,                 NULL, 0 }
};

int main(int argc, char** argv)
{
    const char* user = getenv("LOGNAME");

    while (true)
    {
        int c = getopt_long(
            argc,
            argv,
            "u:",
            g_options,
            NULL);

        if (c == -1)
        {
            break;
        }
        switch (c)
        {
            case 'u':
                user = optarg;
                break;
        }
    }

    if (user == NULL)
    {
        printf("HashWord: No user specified\n");
        return 1;
    }

    int remaining_argc = argc - optind;

    HashWord hashWord(user);

    bool res;
    res = hashWord.open();
    if (!res)
    {
        printf("HashWord: Failed to open database\n");
        return 1;
    }

    if (remaining_argc < 1)
    {
        return 1;
    }

    char* command = argv[optind];

    if (!strncmp("init", command, 4))
    {
        if (hashWord.hasMasterKey())
        {
            printf("Master key is already present\n");
            return 1;
        }

        string password1 = getPassword("New Master password");
        string password2 = getPassword("Retype new Master password");
        if (password1 != password2)
        {
            printf("Passwords do not match\n");
            return 1;
        }
        Key* masterKey = hashWord.getCrypto()->generateKey();
        hashWord.saveMasterKey(masterKey, password1);

        hashWord.getCrypto()->shred(masterKey);
        free(masterKey);
    }
    else if (!strncmp("changepassword", command, 14))
    {
        string oldMasterPassword = getPassword("Old Master Password");
        string newMasterPassword = getPassword("New Master Password");
        string newMasterPassword2 = getPassword("Retype new Master password");

        if (newMasterPassword != newMasterPassword2)
        {
            printf("Passwords do not match\n");
            return 1;
        }

        Key* masterKey = hashWord.getMasterKey(oldMasterPassword);
        if (masterKey == NULL)
        {
            printf("HashWord: Unable to unlock Master Key\n");
            return 1;
        }

        hashWord.saveMasterKey(masterKey, newMasterPassword);
        hashWord.getCrypto()->shred(masterKey);
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

        checkPassword(domainPassword);

        Key* masterKey = hashWord.getMasterKey(masterPassword);
        if (masterKey == NULL)
        {
            printf("HashWord: Unable to unlock Master Key\n");
            return 1;
        }
        hashWord.savePassword(masterKey, string(domain), string(user), domainPassword);

        hashWord.getCrypto()->shred(masterKey);
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

        PasswordDetails details;
        hashWord.getPassword(masterKey, string(domain), details);
        hashWord.getCrypto()->shred(masterKey);
        free(masterKey);

        showPassword(details.username, details.password);
    }
    else if (!strncmp("generatepassword", command, 16))
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
        Key* masterKey = hashWord.getMasterKey(masterPassword);
        if (masterKey == NULL)
        {
            printf("HashWord: Unable to unlock Master Key\n");
            return 1;
        }

        string password = hashWord.getCrypto()->generatePassword(16);
        checkPassword(password);

        hashWord.savePassword(masterKey, string(domain), string(user), password);

        showPassword(string(user), password);

        hashWord.getCrypto()->shred(masterKey);
        free(masterKey);
    }

    return 0;
}

