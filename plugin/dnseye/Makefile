CFLAGS = -I../../sniffer -D_REENTRANT -Wall -pedantic -Isrc
LDLIBS = -lpcap

#ifdef DEBUG
CFLAGS += -g
LDFLAGS += -g
#endif

TARGETS = libdnseye.so libdnseye.a

all: $(TARGETS)

dnseye.o: dnseye.h dnseye.c

# Short-hand aliases
shared: libdnseye.so
static: libdnseye.a

libdnseye.so: dnseye.c dnseye.h
	$(CC) -shared -fPIC ${CFLAGS} -o $@ $< ${LDLIBS}

libdnseye.o: dnseye.c dnseye.h
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<

libdnseye.a: libdnseye.o
	ar rcs $@ $^

clean:
	rm -f $(TARGETS) *~ */*~ */*.o
