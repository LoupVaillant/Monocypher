#! /bin/sh

set -e

make clean
make test CC="clang -std=c99" CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
llvm-profdata-3.8 merge default.profraw -o all.profdata
llvm-cov-3.8 show -instr-profile=all.profdata "./test.out"
