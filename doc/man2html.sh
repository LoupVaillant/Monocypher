#! /bin/sh

mkdir -p html

for name in $(ls -1 "man/man3/" | sed 's/.3monocypher//' | grep -v "style.css")
do
    mandoc                         \
        -Oman=%N.%S.html           \
        -Ostyle=style.css \
        -Thtml man/man3/$name.3monocypher > html/$name.html
done

