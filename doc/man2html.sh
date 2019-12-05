#! /bin/sh

DIR=$(dirname "$0")

# clean before build
rm -rf "$DIR/html/*.html"

convert() {
    MANS=$1
    for name in $(ls -1 "$MANS/" | sed 's/.3monocypher//')
    do
        test -f "$MANS/$name.3monocypher" || continue
        mandoc                            \
        -Oman=%N.html,style=style.css \
        -Thtml "$MANS/$name.3monocypher" \
        > "$DIR/html/$name.html"
    done
}

convert "$DIR/man/man3"
convert "$DIR/man/man3/optional"

