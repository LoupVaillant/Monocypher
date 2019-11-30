#! /bin/sh

mkdir -p tests/formal-analysis
cp src/monocypher.c       \
   src/monocypher.h       \
   src/optional/ed25519.h \
   src/optional/ed25519.c \
   tests/utils.h          \
   tests/utils.c          \
   tests/test.c           \
   tests/vectors.h        \
   tests/formal-analysis
