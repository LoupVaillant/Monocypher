#! /bin/sh

llvm-profdata-3.8 merge default.profraw -o all.profdata
llvm-cov-3.8 show -instr-profile=all.profdata "./test.out"
