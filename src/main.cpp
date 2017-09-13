
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>

#include <getopt.h>

#include "config.h"
#include "hashword.h"
#include "ui.h"
#include "utils.h"

using namespace std;

bool dumpmem();

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

    SecureString password1;
    if (!options.script)
    {
        password1 = getPassword("New Master password");

        SecureString password2 = getPassword("Retype new Master password");
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
    SecureString oldMasterPassword;
    SecureString newMasterPassword;
    if (!options.script)
    {
        oldMasterPassword = getPassword("Old Master Password");
        newMasterPassword = getPassword("New Master Password");
        SecureString newMasterPassword2 = getPassword("Retype new Master password");

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

    SecureString masterPassword;
    if (!options.script)
    {
        masterPassword = getPassword("Master Password");
    }
    else
    {
        masterPassword = getScriptPassword();
    }

    const char* user = "";
    SecureString domain;
    if (argc == 1)
    {
        if (!options.script)
        {
            domain = getPassword("Domain");
        }
        else
        {
            domain = getScriptPassword();
        }
    }
    else if (argc == 2)
    {
        domain = SecureString(argv[1]);
    }
    else if (argc == 3)
    {
        domain = argv[1];
        user = argv[2];
    }

    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }

    if (!options.script)
    {
        bool res = hashWord->hasPassword(masterKey, domain, SecureString(user));
        if (res)
        {
            res = confirm("An entry for this domain already exists, overwrite?");
            if (!res)
            {
                return true;
            }
        }
    }

    SecureString domainPassword;
    if (!options.script)
    {
        domainPassword = getPassword("Domain Password");

        SecureString password2 = getPassword("Retype password");
        if (domainPassword != password2)
        {
            printf("Passwords do not match\n");
            return false;
        }
    }
    else
    {
        domainPassword = getScriptPassword();
    }

    hashWord->savePassword(masterKey, domain, SecureString(user), domainPassword);

    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    return true;
}

static const struct option g_getPasswordOptions[] =
{
    { "chars",    required_argument, NULL, 'c' },
    { "help",     no_argument, NULL, 'h' },
    { NULL,       0,                 NULL, 0 }
};

bool getPasswordCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
#ifdef _OPTRESET
    optreset = 1;
#endif

    optind = 0;
    opterr = 0;

    vector<int> chars;

    while (true)
    {
        int c = getopt_long(
            argc,
            argv,
            "+c:h",
            g_getPasswordOptions,
            NULL);

        if (c == -1)
        {
            break;
        }
        switch (c)
        {
            case 'c':
            {
                char* charStr = strdup(optarg);
                char* sepPos = charStr;
                printf("getPasswordCommand: charStr=%s\n", charStr);
                char* token;
                while ((token = strsep(&sepPos, ",")) != NULL)
                {
                    int ch = atoi(token);
                    chars.push_back(ch);
                }
            } break;

            case 'h':
                printf("Usage: hashword get [options] domain [domain user]\n");
                printf("Options:\n");
                printf("\t-c\t--chars=chars\tComma separated list of password chars to print\n");
                printf("\t-h\t--help\tPrint this help\n");
                break;
        }
    }

    argc -= optind;
    argv += optind;

    SecureString masterPassword;
    if (!options.script)
    {
        masterPassword = getPassword("Master Password");
    }
    else
    {
        masterPassword = getScriptPassword();
    }

    SecureString domain;
    if (argc > 0)
    {
        domain = SecureString(argv[0]);
    }
    else
    {
        if (!options.script)
        {
            domain = getPassword("Domain");
        }
        else
        {
            domain = getScriptPassword();
        }
    }

    const char* user = "";
    if (argc > 1)
    {
        user = argv[1];
    }
    Key* masterKey = hashWord->getMasterKey(masterPassword);
    if (masterKey == NULL)
    {
        printf("HashWord: Unable to unlock Master Key\n");
        return false;
    }

    PasswordDetails details;
    hashWord->getPassword(masterKey, domain, SecureString(user), details);
    hashWord->getCrypto()->shred(masterKey);
    free(masterKey);

    bool showEntropy = true;
    if (!chars.empty())
    {
        SecureString charsStr = "";
        vector<int>::iterator it;
        bool comma = false;
        for (it = chars.begin(); it != chars.end(); it++)
        {
            int charnum = *it;
            if (comma)
            {
                charsStr += ", ";
            }
            comma = true;

            char charnumstr[10];
            sprintf(charnumstr, "%d", charnum);

            char c = details.password.at(charnum - 1);
            if (c != 0)
            {
                SecureString charOutput = SecureString(charnumstr) + "='" + c + "'";
                charsStr += charOutput;
            }
        }
        details.password = charsStr;
        showEntropy = false;
    }

    if (!options.script)
    {
        showPassword(details.username, details.password, showEntropy);
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
        SecureString password = hashWord->getCrypto()->generatePassword(length, useSymbols);

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

    SecureString masterPassword;
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
        bool res = hashWord->hasPassword(masterKey, SecureString(domain), SecureString(user));
        if (res)
        {
            res = confirm("An entry for this domain already exists, overwrite?");
            if (!res)
            {
                return true;
            }
        }
    }

    SecureString password = hashWord->getCrypto()->generatePassword(length, useSymbols);

    hashWord->savePassword(masterKey, SecureString(domain), SecureString(user), password);

    if (!options.script)
    {
        showPassword(SecureString(user), password);
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
    int res;

    if (argc < 2)
    {
        return false;
    }

    SecureString masterPassword;
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

    const char* targetDB = argv[1];

    char* targetFile = strdup("sync.XXXXXX.db");
    res = mkstemps(targetFile, 3);
    if (res == -1)
    {
        printf("syncCommand: Failed to create temp file\n");
        return false;
    }

    string command = string("/usr/bin/scp ") + string(targetDB) + " " + targetFile;
    printf("syncCommand: Retrieving target: %s\n", command.c_str());

    res = system(command.c_str());
    if (res != 0)
    {
        printf("syncCommand: Failed to get target database\n");
        return false;
    }

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
        res = system(command.c_str());
        if (res != 0)
        {
            printf("syncCommand: Failed to update target database\n");
            return false;
        }

        unlink(targetFile);
    }

    return true;
}

bool entropyCommand(HashWord* hashWord, Options options, int argc, char** argv)
{
    SecureString password;
    if (!options.script)
    {
        password = getPassword("Password");
    }
    else
    {
        password = getScriptPassword();
    }

    double entropy = getPasswordEntropy(password);

    printf("%0.2f bits of entropy\n", entropy);

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
    { "sync", "Synchronise passwords with a remote database", syncCommand },
    { "entropy", "Calculate the amount of entropy for a given password", entropyCommand }
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

    unsigned int i;
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

    HashWord hashWord((string(user)), (string(dbpath)));

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

    unsigned int i;
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

#ifdef ENABLE_MEMDUMP
    dumpmem();
#endif

    return 0;
}

