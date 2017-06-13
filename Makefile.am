
SUBDIRS=openaes sha scrypt zxcvbn

bin_PROGRAMS=hashword

hashword_SOURCES=main.cpp hashword.cpp cryptoutils.cpp database.cpp utils.cpp data.cpp random.cpp ui.cpp
hashword_LDFLAGS=openaes/libopenaes.la scrypt/libscrypt.la sha/libsha.la zxcvbn/libzxcvbn.la

test:
	./test.sh

