#! /bin/env sh

set -e

DIR=$(dirname "$0")

POLY=$DIR/poly1305.gen.py

echo "Check limb overflow: $POLY"
$DIR/filter.sh Poly1305 <$DIR/../../src/monocypher.c >$POLY
python3 $DIR/poly1305.gen.py

echo "No limb overflow detected"
