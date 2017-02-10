CC=gcc
CFLAGS=-O2 -Wall -Wextra -std=c11 -pedantic

.PHONY: all clean

all: test

clean:
	rm -f *.o test

test: test.o monocypher.o sha512.o
	$(CC) $(CFLAGS) -o $@ $^

test.o: test.c
	$(CC) $(CFLAGS) -c $^

sha512.o: sha512.c
	$(CC) $(CFLAGS) -c $^

monocypher.o: monocypher.c
	$(CC) $(CFLAGS) -c $^ -DED25519_SHA512
