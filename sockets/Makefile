# all: client server
all: rsock.client rsock.server


ip: cleaner client server


ifneq ($(GDB),)
	CFLAGS += -g
endif

%: %.c socket_common.h
	gcc $(CFLAGS) -o $@ $< $(DEFS) $(LDFLAGS)

%: %.cpp socket_common.h
	g++ -o $@ $< $(DEFS)


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
