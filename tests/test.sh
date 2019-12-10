#! /bin/sh

set -e

make clean;  make test; make test-legacy
make clean;  make test CFLAGS="-DBLAKE2_NO_UNROLLING -O3"
make clean;  make test CC="clang -std=c99" CFLAGS="-g -fsanitize=address"
make clean;  make test CC="clang -std=c99" CFLAGS="-g -fsanitize=memory"
make clean;  make test CC="clang -std=c99" CFLAGS="-g -fsanitize=undefined"
make clean;  make test.out;  valgrind ./test.out

echo
echo "All sanitisers passed!"
echo
