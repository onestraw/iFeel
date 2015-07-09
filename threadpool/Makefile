CFLAGS = -D_REENTRANT -Wall -pedantic -Isrc
LDLIBS = -lpthread

ifdef DEBUG
CFLAGS += -g
LDFLAGS += -g
endif

TARGETS = libthreadpool.so 

all: $(TARGETS)

threadpool.o: threadpool.h threadpool.c

# Short-hand aliases
shared: libthreadpool.so

libthreadpool.so: threadpool.c threadpool.h
	$(CC) -shared -fPIC ${CFLAGS} -o $@ $< ${LDLIBS}

libthreadpool.o: threadpool.c threadpool.h
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<

clean:
	rm -f $(TARGETS) *~ */*~ */*.o
