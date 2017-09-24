#! /bin/sh

llvm-profdata-3.8 merge default.profraw -o all.profdata
llvm-cov show "./test.out" -instr-profile=all.profdata
