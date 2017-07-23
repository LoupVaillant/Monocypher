#! /bin/sh
echo
echo "Run & record coverage"
echo "====================="
"./$1"

echo
echo "Generate report"
echo "==============="
llvm-profdata-3.8 merge default.profraw -o all.profdata


echo
echo "Show report"
echo "==========="
llvm-cov show "./$1" -instr-profile=all.profdata
