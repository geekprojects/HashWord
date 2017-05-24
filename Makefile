
SRCS=main.cpp hashword.cpp database.cpp base64.cpp utils.cpp
OBJS=$(SRCS:.cpp=.o)

all: hashword

hashword: $(OBJS)
	cd openaes; $(MAKE) $(TARGET)
	cd sha; $(MAKE) $(TARGET)
	gcc -o hashword $(OBJS) openaes/libopenaes.o sha/libsha.o -lstdc++ -lsqlite3 -L/usr/local/lib -lscrypt

.cpp.o:
	gcc -c $< -I/usr/local/include

