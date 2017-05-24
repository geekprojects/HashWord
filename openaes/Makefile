
SRCS=oaes_base64.c oaes_lib.c rand.c
OBJS=$(SRCS:.c=.o)

all: libopenaes.o
	ld -r -o libopenaes.o $(OBJS)

libopenaes.o: $(OBJS)
	

