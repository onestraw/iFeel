CFLAGS = -I../sniffer -D_REENTRANT -Wall -pedantic -Isrc
LDLIBS = -lpcap

DEBUG = 1
ifdef DEBUG
CFLAGS += -g
LDFLAGS += -g
endif

TARGETS = lib/libdnseye.so 
TARGETS += lib/libportscan.so 
TARGETS += lib/libsearchword.so 
TARGETS += lib/libsearchword_c.so 

all: $(TARGETS)

lib/libdnseye.so: lib/dnseye.o
	$(CC) -shared -o $@ $< ${LDLIBS}
lib/libportscan.so: lib/portscan.o
	$(CC) -shared -o $@ $< ${LDLIBS}
lib/libsearchword.so: lib/searchword.o lib/decode.o
	$(CXX) -shared -o $@ $^ ${LDLIBS}
lib/libsearchword_c.so: lib/searchword_c.o
	$(CXX) -shared -o $@ $< -L./lib -lsearchword

lib/dnseye.o: dnseye/dnseye.c 
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<
lib/portscan.o: portscan/portscan.c
	$(CC) -c -fPIC ${CFLAGS} -o $@ $<
sw = searchword
lib/searchword.o: $(sw)/searchword.cc 
	$(CXX) -c -fPIC -o $@ $<
lib/decode.o: $(sw)/decode.cc 
	$(CXX) -c -fPIC -o $@ $<
lib/searchword_c.o: $(sw)/c_api.cc
	$(CXX) -c -fPIC -o $@ $<

#g++ -shared -fPIC -o lib/libsearchword.so searchword/searchword.*  searchword/decode.* 
#g++ -shared -fPIC -o lib/libsearchword_c.so  searchword/c_api.cc

clean:
	rm -f $(TARGETS) *~ */*~ *.o */*.o
