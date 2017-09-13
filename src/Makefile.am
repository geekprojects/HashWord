
SUBDIRS=openaes sha scrypt zxcvbn

bin_PROGRAMS=hashword

hashword_SOURCES=main.cpp hashword.cpp cryptoutils.cpp database.cpp utils.cpp data.cpp random.cpp ui.cpp securestring.cpp

if BUILD_MEMDUMP
if LINUX
hashword_SOURCES+=memdump_linux.cpp
endif
if DARWIN
hashword_SOURCES+=memdump_darwin.cpp
endif
endif

hashword_LDFLAGS=openaes/libopenaes.la scrypt/libscrypt.la sha/libsha.la zxcvbn/libzxcvbn.la

test:
	./test.sh

