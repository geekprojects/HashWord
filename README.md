HashWord
===

[![Build Status](https://travis-ci.org/geekprojects/HashWord.svg)](https://travis-ci.org/geekprojects/HashWord)

HashWord is a simple, secure command line password manager based on standard secure techniques.

* ISAAC CSPRNG
* Scrypt or SHA512 HKDF key derivation
* Multiple rounds of AES 256 encryption
* SHA512 hashes
* zxcvbn password entropy info

Features:
* Domain Names are not stored, only hashed
    * HashWord does not know what the passwords are for, and nor will any adversary. You must specify the username and domain you want when retrieving the passwords.
* Passwords are encrypted using keys derived from the domain name and individual salts, as well as the master key.
    * Even if you have the master password, you must guess what domains the user has passwords for.
* Simple secure password generator
* Synchronise and backup multiple copies of a database via SCP
    * Make sure the latest passwords are copied between databases


Requirements
---
* POSIX OS
    * Tested with OS X, Debian, Ubuntu and Cygwin
* libsqlite3


Building
---

### Linux ###

Dependencies:
* m4
* autoconf
* automake
* libtool
* libsqlite3-dev

Building:
```shell
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

### Mac OS X ###

Dependencies (Using Homebrew):
* m4
* autoconf
* automake
* libtool
* sqlite

```shell
$ ./autogen.sh
$ ./configure
$ make
$ make install
```


Usage
---

    Usage: hashword [options] [command] [command options]
    Options:
        -d    --database=db Path to database. Defaults to ~/.hashword/hashword.db
        -u    --user=user   Master user
        -s    --script      Write output more suitable for scripts
        -h    --help        This help text

    Commands:
        init    Create a new database or add a new user
        change  Change master password
        save    Save or update an entry
        get     Retrieve an entry
        gen     Generate a new password and create or update an entry
        sync    Synchronise database with a remote database
        entropy Show the number of bits of entropy for a password

    Use 'hashword <command> --help' for specific help.


Hints
---

* Use a good, secure master password!!
    * Using this tool is pointless if you use a weak password. Remember that anyone trying to get access to your passwords will likely have a copy of the database and can spend as much time as they like trying to brute force it.
    * Do not use a master password that you use for anything else
    * Change the master password occasionally, but not so frequently that you end up using an insecure one
* Keep backups of the database!
* If you're paranoid, make sure you build HashWord from source


Copyrights
---

HashWord itself is Copyright (c) 2017 GeekProjects.com. All rights reserved.
See LICENCE for more details

HashWord includes code by third parties.
* ISAAC RNG is based on public domain code by Bob Jenkins.
* OpenAES is Copyright (c) 2012, Nabil S. Al Ramli. Modified slightly to use my own Random class. (See openaes/LICENSE)
* SHA code is Copyright (c) 2011 IETF Trust and the persons identified as authors of the SHA code. (See sha/sha.h)
* libscrypt is Copyright (c) 2013, Joshua Small. Modified to use our copy of the IETF SHA code (See scrypt/LICENSE)
* zxcvbn is Copyright (c) 2015-2017 Tony Evans (see zxcvbn/LICENSE.txt)

