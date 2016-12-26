all: client server
# all: rsock.client rsock.server


ip: cleaner client server


LDFLAGS += -lrt
ifneq ($(GDB),)
	CFLAGS += -g
endif


socket_common.o: socket_common.c socket_common.h
	gcc -c $(CFLAGS) -o $@ $< $(DEFS) $(LDFLAGS)

%: %.c socket_common.o socket_common.h
	gcc $(CFLAGS) -o $@ $< socket_common.o $(DEFS) $(LDFLAGS)

### %: %.cpp socket_common.o socket_common.h
### 	g++ -o $@ $< $(DEFS)


# e.g. 'make unix.client'
unix.%:
	$(MAKE) $*	DEFS="-DUNIX_SOCKETS"

rsock.%:
	$(MAKE) $*	DEFS="-DRDMA_SOCKETS"  LDFLAGS="-lrdmacm"


tosn.%: clean
	rsync -Pva --del --sparse /opt/campaign/jti/new/erasureUtils/sockets/ root@stb-dsu-sn$(*):/usr/local/marfs_sockets

clean:
	rm -f *~
	rm -f *.o

cleaner: clean
	rm -f client
	rm -f server
