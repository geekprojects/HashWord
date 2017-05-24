
SRCS=hmac.c sha224-256.c sha384-512.c usha.c hkdf.c
OBJS=$(SRCS:.c=.o)

all: libsha.o

libsha.o: $(OBJS)
	ld -r -o libsha.o $(OBJS)

