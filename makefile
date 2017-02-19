CC=gcc
CFLAGS=-O2 -Wall -Wextra -std=c11 -pedantic

.PHONY: all clean

all: test

clean:
	rm -f *.o *.gch test

test: test.o monocypher.o sha512.o
	$(CC) $(CFLAGS) -o $@ $^

test.o: test.c
	$(CC) $(CFLAGS) -c $^

sha512.o: sha512.c sha512.h
	$(CC) $(CFLAGS) -c $^

monocypher.o: monocypher.c monocypher.h
	$(CC) $(CFLAGS) -c $^ -DED25519_SHA512
