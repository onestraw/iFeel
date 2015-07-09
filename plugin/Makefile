CFLAGS = -I../sniffer -D_REENTRANT -Wall -pedantic -Isrc
LDLIBS = -lpcap

ifdef DEBUG
CFLAGS += -g
LDFLAGS += -g
endif

TARGETS = lib/libdnseye.so 
TARGETS += lib/libportscan.so 

all: $(TARGETS)

portscan.o: dnseye/dnseye.h dnseye/dnseye.c
portscan.o: portscan/portscan.h portscan/portscan.c

# Short-hand aliases
shared: lib/libportscan.so

lib/libdnseye.so: dnseye/dnseye.c dnseye/dnseye.h
	$(CC) -shared -fPIC ${CFLAGS} -o $@ $< ${LDLIBS}

lib/libportscan.so: portscan/portscan.c portscan/portscan.h
	$(CC) -shared -fPIC ${CFLAGS} -o $@ $< ${LDLIBS}

libdnseye.o: dnseye/dnseye.c dnseye/dnseye.h
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<

libportscan.o: portscan/portscan.c portscan/portscan.h
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<

clean:
	rm -f $(TARGETS) *~ */*~ */*.o
