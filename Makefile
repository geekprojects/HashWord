TOP=.
TGT=hashword

SUBDIRS=openaes sha
SRCS=main.cpp hashword.cpp database.cpp base64.cpp utils.cpp data.cpp

all: TARGET=all
all: $(TGT)

include $(TOP)/common.mk

$(TGT): $(OBJS) subdirs
	gcc -o $(TGT) $(ALL_OBJS) -lstdc++ -lsqlite3

