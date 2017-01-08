all: rsock


ip:    cleaner client       server

rsock: cleaner
	$(MAKE) rsock.client
	$(MAKE) rsock.server


LDFLAGS += -lrt
LDFLAGS += -lpthread

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
	$(MAKE) $*	DEFS="-DRDMA_SOCKETS"  LDFLAGS="-lrdmacm $(LDFLAGS)" CFLAGS="$(CFLAGS)"





tosn.%: clean
	ssh root@stb-dsu-sn$(*) mkdir -p /usr/local/marfs_sockets
	rsync -Pva --del --sparse /opt/campaign/jti/new/erasureUtils/sockets/ root@stb-dsu-sn$(*):/usr/local/marfs_sockets

clean:
	rm -f *~
	rm -f *.o

cleaner: clean
	rm -f client
	rm -f server
