TOP=.
TGT=hashword

SUBDIRS=openaes sha scrypt
SRCS=main.cpp hashword.cpp cryptoutils.cpp database.cpp utils.cpp data.cpp random.cpp ui.cpp

all: TARGET=all
all: $(TGT)

include $(TOP)/common.mk

$(TGT): $(OBJS) subdirs
	gcc -o $(TGT) $(ALL_OBJS) -lstdc++ -lsqlite3

