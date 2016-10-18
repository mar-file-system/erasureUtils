CC = gcc
CFLAGS = -g -Wall

# add this, even if cflags was overridden
CFLAGS += -I. -lisal

libne.a : erasure.o
	ar rcs $@ $^

test : libTest.c erasure.o
	$(CC) $(CFLAGS) libTest.c erasure.o -o libTest

cleanLib : 
	rm -f erasure.o
	rm -f libne.a

cleanTest :
	rm -f libTest

clean : cleanLib cleanTest

