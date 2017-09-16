# compile with any of the following
CC=gcc -std=gnu99 # speed tests don't work with -std=cxx, they need the POSIX extensions
#CC=gcc -std=c99
#CC=gcc -std=c11
#CC=g++ -std=c++98
#CC=g++ -std=c++11
#CC=g++ -std=c++14
#CC=g++ -std=c++17
#CC=clang -std=c99
#CC=clang -std=c11
#CC=clang++ -std=c++98
#CC=clang++ -std=c++11
#CC=clang++ -std=c++14

# These may be used for tests (except speed)
#CC = clang -std=c99 -fsanitize=address
#CC = clang -std=c99 -fsanitize=memory
#CC = clang -std=c99 -fsanitize=undefined
#CC = clang -std=c99 -fprofile-instr-generate -fcoverage-mapping

#TODO maybe just use the environment variable?
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native -g

.PHONY: all clean install test

all: lib/libmonocypher.a lib/libmonocypher.so

test: test.out
	./test.out

clean:
	rm -rf lib/
	rm -f  test.out

# Monocypher libraries
lib/libmonocypher.a: lib/monocypher.o
	ar cr $@ $^
lib/libmonocypher.so: lib/monocypher.o
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -shared -o $@ $^
lib/%.o: src/%.c src/%.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -fPIC -c -o $@ $<

# Test libraries
lib/utils.o: tests/utils.c tests/utils.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -fPIC -c -o $@ $<
lib/test.o: tests/test.c tests/utils.h    \
                         tests/vectors.h  \
                         src/monocypher.h \
                         src/sha512.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -I src -fPIC -c -o $@ $<

# test executable
test.out: lib/test.o lib/monocypher.o lib/sha512.o lib/utils.o
	$(CC) $(CFLAGS) -I src -o $@ $^
