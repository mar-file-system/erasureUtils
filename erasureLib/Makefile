CC = gcc
CFLAGS = -Wall -I. -l isal

all : lib test

lib : erasure.c erasure.h
	$(CC) $(CFLAGS) -c erasure.c

test : libTest.c
	$(CC) $(CFLAGS) libTest.c erasure.o -o erasureTest

clean : 
	rm erasure.o erasureTest testfile.*

