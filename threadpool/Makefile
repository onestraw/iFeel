CFLAGS = -D_REENTRANT -Wall -pedantic -Isrc
LDLIBS = -lpthread

ifdef DEBUG
CFLAGS += -g
LDFLAGS += -g
endif

TARGETS = libthreadpool.so libthreadpool.a

all: $(TARGETS)

threadpool.o: threadpool.h threadpool.c

# Short-hand aliases
shared: libthreadpool.so
static: libthreadpool.a

libthreadpool.so: threadpool.c threadpool.h
	$(CC) -shared -fPIC ${CFLAGS} -o $@ $< ${LDLIBS}

libthreadpool.o: threadpool.c threadpool.h
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<

libthreadpool.a: libthreadpool.o
	ar rcs $@ $^

clean:
	rm -f $(TARGETS) *~ */*~ */*.o
