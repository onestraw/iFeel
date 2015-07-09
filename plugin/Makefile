CFLAGS = -I../sniffer -D_REENTRANT -Wall -pedantic -Isrc
LDLIBS = -lpcap

ifdef DEBUG
CFLAGS += -g
LDFLAGS += -g
endif

TARGETS = lib/libdnseye.so 

all: $(TARGETS)

dnseye.o: dnseye/dnseye.h dnseye/dnseye.c

# Short-hand aliases
shared: lib/libdnseye.so

lib/libdnseye.so: dnseye/dnseye.c dnseye/dnseye.h
	$(CC) -shared -fPIC ${CFLAGS} -o $@ $< ${LDLIBS}

libdnseye.o: dnseye/dnseye.c dnseye/dnseye.h
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<

clean:
	rm -f $(TARGETS) *~ */*~ */*.o
