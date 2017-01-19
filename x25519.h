#ifndef X25519_H
#define X25519_H

#include <inttypes.h>
#include <stddef.h>

// Computes a shared secret from your private key and their public key.
// WARNING: DO NOT USE THE SHARED SECRET DIRECTLY.
// The shared secret is not pseudo-random.  You need to hash it to derive
// an acceptable secret key.  Any cryptographic hash can work, as well as
// HChacha20.
//
// Implementation details: this is an elliptic curve.  The public key is
// a point on this curve, and your private key is a scalar.  The shared
// secret is another point on this curve, obtained by scalar multiplication.
// Basically:
//     shared_secret == your_sk * their_pk == your_sk * (their_sk * base_point)
//                   == their_sk * your_pk == their_sk * (your_sk * base_point)
void crypto_x25519(uint8_t       shared_secret   [32],
                   const uint8_t your_secret_key [32],
                   const uint8_t their_public_key[32]);

// Generates a public key from the specified secret key.
// Make sure the secret key is randomly selected.
//
// Implementation detail: your secret key is a scalar, and we multiply
// the base point (a constant) by it to obtain a public key.  That is:
//     public_key == secret_key * base_point
// Reversing the operation is conjectured to be infeasible
// without quantum computers (128 bits of security).
void crypto_x25519_base(uint8_t public_key[32], const uint8_t secret_key[32]);


#endif // X25519_H
