#! /bin/sh

set -e

make clean
make test CC="clang -std=c99" CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
llvm-profdata merge default.profraw -o all.profdata
llvm-cov show -instr-profile=all.profdata "./test.out"
