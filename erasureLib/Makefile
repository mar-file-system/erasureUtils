CC = gcc
CFLAGS = -Wall -I. -l isal

all : lib test

lib : erasure.c erasure.h
	$(CC) $(CFLAGS) -c erasure.c

test : libTest.c
	$(CC) $(CFLAGS) libTest.c erasure.o -o libTest

cleanLib : 
	rm erasure.o 

cleanTest :
	rm libTest

clean :
	rm erasure.o libTest

