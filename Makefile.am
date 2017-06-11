
SUBDIRS=openaes sha scrypt

bin_PROGRAMS=hashword

hashword_SOURCES=main.cpp hashword.cpp cryptoutils.cpp database.cpp utils.cpp data.cpp random.cpp ui.cpp
hashword_LDFLAGS=openaes/libopenaes.la sha/libsha.la scrypt/libscrypt.la

test:
	./test.sh

