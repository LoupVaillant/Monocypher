#! /bin/sh

cat << END
#include <stdio.h>
#include <stdlib.h>
#include "../src/monocypher.h"
#include "../src/optional/monocypher-ed25519.h"

typedef struct SHA2_CTX { } SHA2_CTX;
void SHA512Init(SHA2_CTX*);
void SHA512Update(SHA2_CTX*, const void*, size_t);
void SHA512Final(uint8_t*, SHA2_CTX*);
void arc4random_buf(void*, size_t);

int main() {
END

for f in man/man3/*.3monocypher man/man3/optional/*.3monocypher; do
	if ! [ -L "$f" ]; then
		echo "// $f"
		sed -n "/^\.Bd/,/^\.Ed/p" < $f | sed "s/\.Bd.*/{/" | sed "s/\.Ed/}/"
	fi
done

echo "}"
