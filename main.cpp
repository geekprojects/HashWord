
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>

#include <getopt.h>

#include "hashword.h"
#include "ui.h"
#include "utils.h"

using namespace std;

struct Options
{
    bool script;
};

typedef bool(*commandFunc_t)(HashWord*, Options options, int, char**);

static bool initCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    if (hashWord->hasMasterKey())
    {
        printf("Master key is already present\n");
        return 1;
    }

    string password1;
    if (!options.script)
    {
        password1 = getPassword("New Master password");

        string password2 = getPassword("Retype new Master password");
        if (password1 != password2)
        {
            printf("Passwords do not match\n");
            return false;
        }
    }
    else
    {
        password1 = getScriptPassword();
    }

    Key* masterKey = hashWord->getCrypto()->generateKey();
    hashWord->saveMasterKey(masterKey, password1);

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

bool changePasswordCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    string oldMasterPassword;
    string newMasterPassword;
    if (!options.script)
    {
        oldMasterPassword = getPassword("Old Master Password");
        newMasterPassword = getPassword("New Master Password");
        string newMasterPassword2 = getPassword("Retype new Master password");

        if (newMasterPassword != newMasterPassword2)
        {
            printf("Passwords do not match\n");
            return false;
        }
    }
    else
    {
        oldMasterPassword = getScriptPassword();
        newMasterPassword = getScriptPassword();
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

bool savePasswordCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    if (argc < 1)
    {
        return false;
    }

    const char* user = "";
    const char* domain = "";
    if (argc == 2)
    {
        domain = argv[1];
    }
    else if (argc == 3)
    {
        domain = argv[1];
        user = argv[2];
    }

    string masterPassword;
    if (!options.script)
    {
        masterPassword = getPassword("Master Password");
    }
    else
    {
        masterPassword = getScriptPassword();
    }

    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }

    if (!options.script)
    {
        bool res = hashWord->hasPassword(masterKey, string(domain), string(user));
        if (res)
        {
            res = confirm("An entry for this domain already exists, overwrite?");
            if (!res)
            {
                return true;
            }
        }
    }

    string domainPassword;
    if (!options.script)
    {
        domainPassword = getPassword("Domain Password");
    }
    else
    {
        domainPassword = getScriptPassword();
    }

    hashWord->savePassword(masterKey, string(domain), string(user), domainPassword);

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

bool getPasswordCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    if (argc < 1)
    {
        return false;
    }

    const char* domain = argv[1];
    const char* user = "";
    if (argc > 2)
    {
        user = argv[2];
    }

    string masterPassword;
    if (!options.script)
    {
        masterPassword = getPassword("Master Password");
    }
    else
    {
        masterPassword = getScriptPassword();
    }

    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }

    PasswordDetails details;
    hashWord->getPassword(masterKey, string(domain), string(user), details);
    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    if (!options.script)
    {
        showPassword(details.username, details.password);
    }
    else
    {
        printf("%s\n", details.username.c_str());
        printf("%s\n", details.password.c_str());
    }
 
    return true;
}

static const struct option g_generatePasswordOptions[] =
{
    { "length",   required_argument, NULL, 'l' },
    { "no-symbols",  no_argument, NULL, 's' },
    { "help",     no_argument, NULL, 'h' },
    { NULL,       0,                 NULL, 0 }
};

bool generatePasswordCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    int length = 16;

#ifdef _OPTRESET
    optreset = 1;
#endif

    optind = 0;
    opterr = 0;

    bool useSymbols = true;

    while (true)
    {
        int c = getopt_long(
            argc,
            argv,
            "+l:",
            g_generatePasswordOptions,
            NULL);

        if (c == -1)
        {
            break;
        }
        switch (c)
        {
            case 'l':
                length = atoi(optarg);
                break;

            case 's':
                useSymbols = false;
                break;

            case 'h':
                printf("Usage: hashword gen [options]\n");
                printf("Options:\n");
                printf("\t-l\t--length=length\tSpecify the length of the password\n");
                printf("\t-s\t--no-symbols\tDon't include symbols in password\n");
                return true;
                break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0)
    {
        string password = hashWord->getCrypto()->generatePassword(length, useSymbols);

        if (!options.script)
        {
            showPassword("", password);
        }
        else
        {
            printf("%s\n", password.c_str());
        }

        return true;
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

    string masterPassword;
    if (!options.script)
    {
        masterPassword = getPassword("Master Password");
    }
    else
    {
        masterPassword = getScriptPassword();
    }

    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return 1;
    }

    if (!options.script)
    {
        bool res = hashWord->hasPassword(masterKey, string(domain), string(user));
        if (res)
        {
            res = confirm("An entry for this domain already exists, overwrite?");
            if (!res)
            {
                return true;
            }
        }
    }

    string password = hashWord->getCrypto()->generatePassword(length, useSymbols);

    hashWord->savePassword(masterKey, string(domain), string(user), password);

    if (!options.script)
    {
        showPassword(string(user), password);
    }
    else
    {
        printf("%s\n", password.c_str());
    }

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

bool syncCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    if (argc < 2)
    {
        return false;
    }

    string masterPassword;
    if (!options.script)
    {
        masterPassword = getPassword("Master Password");
    }
    else
    {
        masterPassword = getScriptPassword();
    }

    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return 1;
    }

    const char* targetDB = argv[1];

    char* targetFile = strdup("sync.XXXXXX.db");
    mkstemps(targetFile, 3);

    string command = string("/usr/bin/scp ") + string(targetDB) + " " + targetFile;
    printf("syncCommand: Retrieving target: %s\n", command.c_str());

    int sysres;
    sysres = system(command.c_str());
    if (sysres != 0)
    {
        printf("syncCommand: Failed to get target database\n");
        return false;
    }

    bool res;
    HashWord syncHashWord(hashWord->getUsername(), string(targetFile));

    res = syncHashWord.open();
    if (!res)
    {
        printf("syncCommand: Failed to open sync database\n");
        return false;
    }

    res = hashWord->sync(masterKey, &syncHashWord);

    if (res)
    {
        string command = string("/usr/bin/scp ") + targetFile + " " + string(targetDB);
        printf("syncCommand: Updating target: %s\n", command.c_str());
        sysres = system(command.c_str());
        if (sysres != 0)
        {
            printf("syncCommand: Failed to update target database\n");
            return false;
        }

        unlink(targetFile);
    }

    return true;
}

typedef struct command
{
    const char* name;
    const char* descr;
    commandFunc_t func;
} command_t;

static const command g_commands[] =
{
    { "init", "Create a new database or add a new user", initCommand },
    { "change", "Change master password", changePasswordCommand },
    { "save", "Save or update an entry", savePasswordCommand },
    { "get", "Retrieve an entry", getPasswordCommand },
    { "gen", "Generate a new password and create or update an entry", generatePasswordCommand },
    { "sync", "Synchronise passwords with a remote database", syncCommand }
};

static const struct option g_options[] =
{
    { "user",     required_argument, NULL, 'u' },
    { "database", required_argument, NULL, 'd' },
    { "script",   no_argument, NULL, 's' },
    { "help",   no_argument, NULL, 'h' },
    { NULL,       0,                 NULL, 0 }
};

void help(const char* argv0, int status)
{
    printf("Usage: %s [options] [command] [command options]\n", argv0);
    printf("Options:\n");
    printf("\t-d\t--database=db\tPath to database. Defaults to ~/.hashword/hashword.db\n");
    printf("\t-u\t--user=user\tMaster user\n");
    printf("\t-s\t--script\tWrite output more suitable for scripts\n");
    printf("\t-h\t--help\tThis help text\n");
    printf("\nCommands:\n");

    int i;
    for (i = 0; i < sizeof(g_commands) / sizeof(command); i++)
    {
        const command* cmd = &(g_commands[i]);
        printf("\t%s\t%s\n", cmd->name, cmd->descr);
    }

    exit(status);
}

int main(int argc, char** argv)
{
    const char* user = getenv("LOGNAME");

    const char* dbpath = NULL;
    const char* home = getenv("HOME");
    if (home != NULL)
    {
        dbpath = (string(home) + "/.hashword/hashword.db").c_str();
    }

    Options options;
    options.script = false;

    while (true)
    {
        int c = getopt_long(
            argc,
            argv,
            "+u:d:s",
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
            case 'd':
                dbpath = optarg;
                break;
            case 's':
                options.script = true;
                break;
            case 'h':
                help(argv[0], 0);
                break;
        }
    }

    if (user == NULL)
    {
        printf("HashWord: No user specified\n");
        return 1;
    }

    if (dbpath == NULL)
    {
        printf("HashWord: No database path specified\n");
        return 1;
    }

    // Only read and writable by the current user, no one else
    umask(077);

    HashWord hashWord(user, dbpath);

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
    int commandArgc = remaining_argc;

    char* commandArg = argv[optind];

    int i;
    bool found = false;
    for (i = 0; i < sizeof(g_commands) / sizeof(command); i++)
    {
        const command* cmd = &(g_commands[i]);
        if (!strcmp(cmd->name, commandArg))
        {
            cmd->func(&hashWord, options, commandArgc, argv + optind);
            found = true;
            break;
        }
    }

    if (!found)
    {
        printf("%s: Unknown command: %s\n", argv[0], commandArg);
        help(argv[0], 1);
    }

    return 0;
}

