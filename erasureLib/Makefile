CC = gcc
CFLAGS = -g -Wall -I. -l isal

lib : erasure.c erasure.h
	$(CC) $(CFLAGS) -c erasure.c

all : lib test

test : libTest.c
	$(CC) $(CFLAGS) libTest.c erasure.o -o libTest

cleanLib : 
	rm erasure.o 

cleanTest :
	rm libTest

clean :
	rm erasure.o libTest

