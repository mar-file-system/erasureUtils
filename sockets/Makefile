all: cleaner client socket_fserver


# 'make ... PROT={RDMA,UNIX,IP}'   default=IP


# The Makefile parser is inconsistent about whether the bodies of
# conditions should be tab-indented or not.  Here, tab-indents fail.
ifeq ($(PROT),UNIX)
  DEFS += -DUNIX_SOCKETS
else
ifeq ($(PROT),RDMA)
  LDFLAGS += -lrdmacm
  DEFS    += -DRDMA_SOCKETS
endif
endif

LDFLAGS += -lrt
LDFLAGS += -lpthread

# Here, tab-indents succeed
ifeq ($(GDB),)
	CFLAGS += -O3
else
	CFLAGS += -g
endif


# This allows client to do a fixed number of iterations, passing raw
# buffers to the server instead of doing reads.  The value is the
# number of 1MB buffers to be transferred to the server.
ifneq ($(SKIP_CLIENT_READS),)
	DEFS+="-DSKIP_CLIENT_READS=$(SKIP_CLIENT_READS)"
endif

# This allows avoiding the cost of actually writing to file on the
# server-side.  The value of the variable is not important, other than
# defined/undefined.
ifneq ($(SKIP_SERVER_WRITES),)
	DEFS+="-DSKIP_SERVER_WRITES"
endif



common.o: common.c common.h
	gcc -c $(CFLAGS) -o $@ $< $(DEFS) $(LDFLAGS)

%: %.c common.o common.h
	gcc $(CFLAGS) -o $@ $< common.o $(DEFS) $(LDFLAGS)

### %: %.cpp common.o common.h
### 	g++ -o $@ $< $(DEFS)






# '%' is e.g. '001'
tosn.%: clean
	ssh root@stb-dsu-sn$(*) mkdir -p /usr/local/marfs_sockets
	rsync -Pva --del --sparse /opt/campaign/jti/new/erasureUtils/sockets/ root@stb-dsu-sn$(*):/usr/local/marfs_sockets

clean:
	rm -f *~
	rm -f *.o

cleaner: clean
	rm -f client
	rm -f socket_fserver
