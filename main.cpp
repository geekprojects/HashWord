
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

typedef bool(*commandFunc_t)(HashWord*, int, char**);

static bool initCommand(HashWord* hashWord, int argc, char** argv)
{
    if (hashWord->hasMasterKey())
    {
        printf("Master key is already present\n");
        return 1;
    }

    string password1 = getPassword("New Master password");
    string password2 = getPassword("Retype new Master password");
    if (password1 != password2)
    {
        printf("Passwords do not match\n");
        return false;
    }

    Key* masterKey = hashWord->getCrypto()->generateKey();
    hashWord->saveMasterKey(masterKey, password1);

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

bool changePasswordCommand(HashWord* hashWord, int argc, char** argv)
{
    string oldMasterPassword = getPassword("Old Master Password");
    string newMasterPassword = getPassword("New Master Password");
    string newMasterPassword2 = getPassword("Retype new Master password");

    if (newMasterPassword != newMasterPassword2)
    {
        printf("Passwords do not match\n");
        return false;
    }

    Key* masterKey = hashWord->getMasterKey(oldMasterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }

    hashWord->saveMasterKey(masterKey, newMasterPassword);
    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);
 
    return true;
}

bool savePasswordCommand(HashWord* hashWord, int argc, char** argv)
{
    if (argc < 1)
    {
        return false;
    }

    const char* user = "";
    const char* domain = "";
    if (argc == 1)
    {
        domain = argv[2];
    }
    else if (argc == 2)
    {
        domain = argv[0];
        user = argv[1];
    }
    string masterPassword = getPassword("Master Password");
    string domainPassword = getPassword("Domain Password");

    checkPassword(domainPassword);

    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }
    hashWord->savePassword(masterKey, string(domain), string(user), domainPassword);

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

bool getPasswordCommand(HashWord* hashWord, int argc, char** argv)
{
    if (argc < 1)
    {
        return false;
    }

    char* domain = argv[0];
    string masterPassword = getPassword("Master Password");
    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }

    PasswordDetails details;
    hashWord->getPassword(masterKey, string(domain), details);
    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    showPassword(details.username, details.password);
 
    return true;
}

bool generatePasswordCommand(HashWord* hashWord, int argc, char** argv)
{
    if (argc < 1)
    {
        return false;
    }

    const char* user = "";
    const char* domain = "";
    if (argc == 1)
    {
        domain = argv[0];
    }
    else if (argc == 2)
    {
        domain = argv[0];
        user = argv[1];
    }

    string masterPassword = getPassword("Master Password");
    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return 1;
    }

    string password = hashWord->getCrypto()->generatePassword(16);
    checkPassword(password);

    hashWord->savePassword(masterKey, string(domain), string(user), password);

    showPassword(string(user), password);

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

typedef struct command
{
    const char* name;
    commandFunc_t func;
} command_t;

static const command g_commands[] =
{
    { "init", initCommand },
    { "changepassword", changePasswordCommand },
    { "savepassword", savePasswordCommand },
    { "getpassword", getPasswordCommand },
    { "generatepassword", generatePasswordCommand }
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

    HashWord hashWord(user);

    bool res;
    res = hashWord.open();
    if (!res)
    {
        printf("HashWord: Failed to open database\n");
        return 1;
    }

    int remaining_argc = argc - optind;
    if (remaining_argc < 1)
    {
        return 1;
    }
    int commandArgc = remaining_argc - 1;

    int i;
    for (i = 0; i < sizeof(g_commands) / sizeof(command); i++)
    {
        const command* cmd = &(g_commands[i]);
        if (!strcmp(cmd->name, argv[optind]))
        {
            cmd->func(&hashWord, commandArgc, argv + optind + 1);
            break;
        }
    }

    return 0;
}

