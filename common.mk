
SUBDIR_TGT=subdir.o

OBJS=$(SRCS:.cpp=.o) $(SRCS_C:.c=.o)
SUBDIROBJS=$(foreach dir,$(SUBDIRS), $(dir)/$(SUBDIR_TGT))
ALL_OBJS=$(OBJS) $(SUBDIROBJS)

#CFLAGS=-O3 -ggdb
#CFLAGS+=-Wall -Werror

CFLAGS+=-I/usr/local/include

subdirs:
	for dir in $(SUBDIRS) $(EXTRA_SUBDIRS) ; do \
	    $(MAKE) -C $$dir $(TARGET); res=$$?; \
	    if test $$res != 0 ; then exit $$res; fi; \
	done;

subdir.o: $(OBJS)
	ld -r $(OBJS) -o subdir.o

clean: TARGET=clean
clean: subdirs
	rm -rf $(OBJS) $(TGT) $(SUBDIR_TGT)

.c.o:
	gcc -c -I. -I$(TOP) $(CFLAGS) $<

.cpp.o:
	gcc -c -I. -I$(TOP) $(CFLAGS) -std=c++11 $<


