#! /bin/sh

DIR=$(dirname "$0")

for name in $(ls -1 "$DIR/man/man3/" | sed 's/.3monocypher//')
do
    mandoc                            \
        -Oman=%N.html,style=style.css \
        -Thtml "$DIR/man/man3/$name.3monocypher" > "$DIR/html/$name.html"
done
