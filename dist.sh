#! /bin/sh

cp README.md     dist/
cp AUTHORS.md    dist/
cp LICENCE.md    dist/

(cd tests/gen/; make)

mkdir -p dist/tests/vectors
gcc tests/vector_to_header.c -o dist/tests/vectors/vector_to_header.out

cat tests/gen/chacha20.vec tests/vectors/chacha20 > dist/tests/vectors/chacha20.vec
cat tests/gen/poly1305.vec tests/vectors/poly1305 > dist/tests/vectors/poly1305.vec
cat tests/gen/x25519.vec   tests/vectors/x25519   > dist/tests/vectors/x25519.vec
cp  tests/gen/xchacha20.vec                         dist/tests/vectors/xchacha20.vec
cp  tests/gen/blake2b.vec                           dist/tests/vectors/blake2b.vec
cp  tests/gen/sha512.vec                            dist/tests/vectors/sha512.vec
cp  tests/gen/argon2i.vec                           dist/tests/vectors/argon2i.vec
cp  tests/gen/edDSA.vec                             dist/tests/vectors/edDSA.vec
cp  tests/vectors/key_exchange                      dist/tests/vectors/key_exchange.vec

(cd dist/tests/vectors
 ./vector_to_header.out chacha20     < chacha20.vec     > chacha20.h
 ./vector_to_header.out xchacha20    < xchacha20.vec    > xchacha20.h
 ./vector_to_header.out poly1305     < poly1305.vec     > poly1305.h
 ./vector_to_header.out blake2b      < blake2b.vec      > blake2b.h
 ./vector_to_header.out sha512       < sha512.vec       > sha512.h
 ./vector_to_header.out argon2i      < argon2i.vec      > argon2i.h
 ./vector_to_header.out x25519       < x25519.vec       > x25519.h
 ./vector_to_header.out edDSA        < edDSA.vec        > edDSA.h
 ./vector_to_header.out key_exchange < key_exchange.vec > key_exchange.h
)

cat dist/tests/vectors/*.h > dist/tests/vectors.h
rm -rf dist/tests/vectors/
