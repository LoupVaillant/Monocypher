Monocypher Manual
=================

Authenticated encryption (XChacha20 + Poly1305)
-----------------------------------------------

Encryption makes your messages unreadable to eavesdroppers.
Authentication ascertain the origin and integrity of the messages you
read.

Both are important.  Without encryption, you give away all your
secrets, and without authentication, you can fall prey to forgeries
(messages that look legitimate, but actually come from the attacker).
A clever attacker may even leverage forgeries to steal your secrets.

Always authenticate your messages.


### crypto\_lock()

    void crypto_lock(uint8_t        mac[16],
                     uint8_t       *ciphertext,
                     const uint8_t  key[32],
                     const uint8_t  nonce[24],
                     const uint8_t *plaintext, size_t text_size);

The inputs are:

- `key`: a 32-byte session key, shared between you and the recipient.
  It must be secret (unknown to the attacker) and random
  (unpredictable to the attacker).  Of course, one does not simply
  transmit this key over the network.  There are less suicidal ways to
  share session keys, such as meeting physically, or performing a
  Diffie Hellman key exchange (described below).

- `nonce`: a 24-byte a number, used only once with any given session
  key.  It doesn't have to be secret or random.  But you must _never_
  reuse that number with the same key.  If you do, the attacker will
  have access to the XOR of 2 different messages, *and* the ability to
  forge messages in your stead.

  The easiest (and recommended) way to generate this nonce is to use
  your OS's random number generator (`/dev/urandom` on UNIX systems).
  Don't worry about accidental collisions, the nonce is big enough to
  make them virtually impossible.

  Don't use user space random number generators, they're error prone.
  You could accidentally reuse the generator's internal state,
  duplicate the random stream, and trigger a nonce reuse.  Oops.

- `plaintext`: the secret you want to send.  Of course, it must be
  unknown to the attacker.  Keep in mind however that the _length_ of
  the plaintext, unlike its content, is not secret.  Make sure your
  protocol doesn't leak secret information with the length of
  messages.  (It has happened before with variable-length voice
  encoding software.)  Solutions to mitigate this include
  constant-length encodings and padding.

The outputs are:

- `mac`: a 16-byte _message authentication code_ (MAC), that only you
  could have produced.  (Of course, this guarantee goes out the window
  the nanosecond the attacker somehow learns your session key, or sees
  2 messages with the same nonce.  Seriously, don't reuse that nonce.)

  Transmit this MAC over the network so the recipient can authenticate
  your message.

- `ciphertext`: the encrypted message (same length as the plaintext
  message).  Transmit it over the network so the recipient can decrypt
  and read it.

  Note: `ciphertext` is allowed to have the same value as `plaintext`.
  I so, encryption will happen in place.


### crypto\_unlock()

    int crypto_unlock(uint8_t       *plaintext,
                      const uint8_t  key[32],
                      const uint8_t  nonce[24],
                      const uint8_t  mac[16],
                      const uint8_t *ciphertext, size_t text_size);

The flip side of the coin.  The inputs are:

- `key`: the session key.  It's the same as the one used for
  authenticated encryption.

- `nonce`: the nonce that was used to encrypt this particular
  message.  No decryption is possible without it.

- `mac`: the message authentication code produced by the sender.
  Integrity cannot be ensured without it.

- `ciphertext`: the encrypted text produced by the sender.

There are 2 outputs:

- `plaintext`: The decrypted message (same length as the ciphertext).

  Note: `plaintext` is allowed to be the same as `ciphertext`.  If so,
  decryption will happen in place.

- A return code: 0 if all went well, -1 if the message was corrupted
  (either accidentally or intentionally).

  Tip: always check your return code.

Unlocking proceeds in two steps: first, we authenticate the additional
data and the ciphertext with the provided MAC.  If any of those three
has been corrupted, `crypto_aead_unlock()` returns -1 immediately,
without decrypting the message.  If the message is genuine,
`crypto_aead_unlock()` decrypts the ciphertext, then returns 0.

_(Again, if someone gave away the session key or reused a nonce,
detecting forgeries becomes impossible.  Don't reuse the nonce.)_


### AEAD (Authenticated Encryption with Additional Data)

    void crypto_aead_lock(uint8_t        mac[16],
                          uint8_t       *ciphertext,
                          const uint8_t  key[32],
                          const uint8_t  nonce[24],
                          const uint8_t *ad       , size_t ad_size,
                          const uint8_t *plaintext, size_t text_size);

    int crypto_aead_unlock(uint8_t       *plaintext,
                           const uint8_t  key[32],
                           const uint8_t  nonce[24],
                           const uint8_t  mac[16],
                           const uint8_t *ad        , size_t ad_size,
                           const uint8_t *ciphertext, size_t text_size);

Those functions have two additional parameters: `ad` and `ad_size`.
They represent _additional data_, that is authenticated, but _not_
encrypted.  Note: `ad` is optional, and may be null if `ad_size` is
zero.  This can be useful if your protocol somehow requires you to
send unencrypted data.

_Note: using those functions is discouraged: if the data you're
transmitting is worth authenticating, it's probably worth encrypting
as well.  Do so if you can, using `crypto_lock()` and
`crypto_unlock()`._

If you must send unencrypted data, remember that you cannot trust
unauthenticated data.  _Including the length of the additional data_.
If you transmit that length over the wire, you must authenticate it.
(The easiest way to do so is to append that length to the additional
data before you call `crypto_aead_*()`).  If you don't, the attacker
could provide a false length, effectively moving the boundary between
the additional data and the ciphertext.

If however the length of the additional data is implicit (fixed size)
or self-contained (length appending, null termination…), you don't
need to authenticate it explicitly.

_(The `crypto_aead_*()` functions don't authenticate the length
themselves for simplicity, compatibility, and efficiency reasons: most
of the time, the length of the additional data is either fixed or self
contained, and thus outside of attacker control.  It also makes them
compatible with `crypto_lock()` and `crypto_unlock()` when the size of
the additional data is zero, and simplifies the implementation.)_


Diffie-Hellman key exchange (X25519 + HChacha20)
------------------------------------------------

Key exchange works thus: Alice and Bob each have a key pair (a secret
key and a public key).  They know each other's public key, but they
keep their own secret key… secret.  Key exchange works like this:

    shared_secret = get_shared_secret(Alice_public_key, Bob_secret_key)
                  = get_shared_secret(Bob_public_key, Alice_secret_key)

If Eve learns Alice's secret key, she could compute the shared secret
between Alice and anyone else (including Bob), allowing her to read
and forge correspondence.  Protect your secret key.

Furthermore, Alice and Bob must know each other's public keys
_beforehand_.  If they don't, and try to communicate those keys over
an insecure channel, Eve might [intercept their communications][MITM]
and provide false public keys.  There are various ways to learn of
each other's public keys (crypto parties, certificate authorities, web
of trust…), each with its advantages and drawbacks.

[MITM]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
        (Man-in-the-middle attack)

### crypto\_lock\_key()

    int crypto_key_exchange(uint8_t       shared_key      [32],
                            const uint8_t your_secret_key [32],
                            const uint8_t their_public_key[32]);

Computes a shared key with your secret key and their public key,
suitable for the `crypto_*lock()` functions above.  It performs a
X25519 key exchange, then hashes the shared secret (with HChacha20) to
get a suitably random-looking shared key.

Keep in mind that if either of your long term secret keys leaks, it
may compromise _all past messages_!  If you want
[forward secrecy][FS], you'll need to exchange temporary public keys,
then compute your shared secret with _them_.  (How that should
be done, and the exact security guarantees are not clear to me at the
moment.)

[FS]: https://en.wikipedia.org/wiki/Forward_secrecy (Wikipedia)

The return code serves as a security check: there are a couple evil
public keys out there, that force the shared key to a known constant
(the HCHacha20 of zero).  This never happens with legitimate public
keys, but if the ones you process aren't exactly trustworthy, watch
out.

So, `crypto_key_exchange()` returns -1 whenever it detects such an evil
public key.  If all goes well, it returns zero.


### crypto\_x25519\_public\_key()

    void crypto_x25519_public_key(uint8_t       public_key[32],
                                  const uint8_t secret_key[32]);

Deterministically computes the public key from the specified secret
key.  Make sure the secret key is random.  Again, use your OS's random
number generator.


### crypto\_x25519()

    int  crypto_x25519(uint8_t       shared_secret   [32],
                       const uint8_t your_secret_key [32],
                       const uint8_t their_public_key[32]);

Tip: this is a low level function.  Unless you _really_ know what
you're doing, you should use `crypto_key_exchange()` instead.

Computes a shared secret with your secret key and the other party's
public key.  __Warning: the shared secret is not cryptographically
random.__ Don't use it directly as a session key.  You need to hash it
first.  Any cryptographically secure hash will do.
`crypto_key_exchange()` uses HChacha20 (it's not a general purpose
hash, but here it works just fine).

Just like `crypto_key_exchange()`, the return code asserts
contributory behaviour: if zero, all went well.  If -1, the shared
secret has been forced to a string of zeros.

Implementation detail: note that the most significant bit of the
public key is systematically ignored.  It is not needed, because every
public key should be smaller than 2^255-19, which fits in 255 bits.
If another implementation of x25519 gives you a key that's not fully
reduced and has its high bit set, the computation will fail.  On the
other hand, it also means you may use this bit for other purposes
(parity flipping for ed25519 compatibility or whatever unfathomable
goal you have in mind).


Public key signatures (edDSA with curve25519 & Blake2b)
-------------------------------------------------------

Authenticated encryption with key exchange is not always enough.
Sometimes, you want to _broadcast_ a signature, in such a way that
_everybody_ can verify.

When you sign a message with your private key, anybody who knows your
public key can verify that you signed the message.  Obviously, any
attacker that gets a hold of your private key can sign messages in
your stead.  Protect your private key.

Monocypher provides public key signatures with a variant of ed25519,
which uses Blake2b as the hash instead of SHA-512.  SHA-512 is
provided as an option for compatibility with other systems.

Blake2b is the default because it is faster, more flexible, harder to
misuse than SHA-512, and already required by Argon2i.  Monocypher
needs only one hash, and that shall be Blake2b.

The reason why there's a SHA-512 option at all is official test
vectors.  Can't test signatures reliably without them.

Note that using Blake2b instead of SHA-512 does *not* block your
upgrade path to faster implementations: Floodyberry's [Donna][]
library provides blazing fast implementations that can work with
custom hashes.

[Donna]: https://github.com/floodyberry/ed25519-donna

### crypto\_sign\_public\_key()

    void crypto_sign_public_key(uint8_t        public_key[32],
                                const uint8_t  secret_key[32]);

Deterministically computes a public key from the specified secret key.
Make sure the secret key is randomly selected. OS good. User space
bad.

By the way, these are _not_ the same as key exchange key pairs.
Maintain separate sets of keys for key exchange and signing.  There
are clever ways to unify those keys, but those aren't covered by
Monocypher.


### void crypto\_sign()

    void crypto_sign(uint8_t        signature[64],
                     const uint8_t  secret_key[32],
                     const uint8_t  public_key[32], // optional, may be null
                     const uint8_t *message, size_t message_size);

Signs a message with your secret key.  The public key is optional, and
will be recomputed if you don't provide it.  It's twice as slow,
though.


### crypto\_check()

    int crypto_check(const uint8_t  signature[64],
                     const uint8_t  public_key[32],
                     const uint8_t *message, size_t message_size);

Checks that a given signature is genuine.  Returns 0 for legitimate
messages, -1 for forgeries.  Of course, if the attacker got a hold of
the matching private key, all bets are off.

A word of warning: this function does *not* run in constant time.  It
doesn't have to in most threat models, because nothing is secret:
everyone knows the public key, and the signature and message are
rarely secret.

If you want to ascertain the origin of a secret message, you may want
to use x25519 key exchange instead.


Cryptographic Hash (Blake2b)
----------------------------

Blake2b is a fast cryptographically secure hash, based on the ideas of
Chacha20.  It is faster than md5, yet just as secure as SHA-3.

### direct interface

The direct interface sports 2 functions:

    void crypto_blake2b_general(uint8_t       *digest, size_t digest_size,
                                const uint8_t *key   , size_t key_size,
                                const uint8_t *in    , size_t in_size);

    void crypto_blake2b(uint8_t digest[64], const uint8_t *in, size_t in_size);

The second one is a convenience function, which uses a 64 bytes hash
and no key (this is a good default).

If you use the first function, you can specify the size of the digest
(I'd advise against anything below 32-bytes), and use a secret key to
make the hash unpredictable —useful for message authentication codes.

(Note: Blake2b is immune to [length extension attacks][LEA], and as
such does not require any [specific precaution][HMAC].  It can
authenticate messages with a naive approach.  _However_, older hashes
are _not_ immune to such attacks, and _do_ require those precautions.)

[LEA]:  https://en.wikipedia.org/wiki/Length_extension_attack (Wikipedia)
[HMAC]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code (HMAC)

- `digest     `: The output digest.  Must have at least `digest_size` free bytes.
- `digest_size`: the length of the hash.  Must be between 1 and 64.
- `key_size   `: length of the key.       Must be between 0 and 64.
- `key        `: some secret key.         May be null if key_size is 0.

Any deviation from these invariants results in __undefined
behaviour.__ Make sure your inputs are correct.

### Incremental interface.

Incremental interfaces are useful to handle streams of data or large
files without using too much memory.  This interface uses 3 steps:

- initialisation, where we set up a context with the various hashing
  parameters;
- update, where we hash the message chunk by chunk, and keep the
  intermediary result in the context;
- and finalisation, where we produce the final digest.

There are 2 init functions, one update function, and one final function:

    void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t digest_size,
                                     const uint8_t      *key, size_t key_size);

    void crypto_blake2b_init(crypto_blake2b_ctx *ctx);

    void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                               const uint8_t      *in, size_t in_size);

    void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *digest);


The invariants of the parameters are the same as for
`crypto_blake2b_general()`: `digest_size` must be between 1 and 64,
`key_size` must be between 0 and 64.  Any bigger and you get undefined
behaviour.

`crypto_blake2b_init()` is a convenience init function, that specifies
a 64 bytes hash and no key.  This is a good default.

`crypto_blake2b_update()` computes your hash piece by piece.

`crypto_blake2b_final()` outputs the digest.

Here's how you can hash the concatenation of 3 chunks with the
incremental interface:

    uint8_t digest[64];
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init  (&ctx);
    crypto_blake2b_update(&ctx, chunk1, chunk1_size);
    crypto_blake2b_update(&ctx, chunk2, chunk2_size);
    crypto_blake2b_update(&ctx, chunk3, chunk3_size);
    crypto_blake2b_final (&ctx, digest);


Password key derivation (Argon2i)
---------------------------------

Storing passwords in plaintext is suicide.  Storing hashed and salted
passwords is better, but still very dangerous: passwords simply don't
have enough entropy to prevent a dedicated attacker from guessing them
by sheer brute force.

One way to prevent such attacks is to make sure hashing a password
takes too much resources for a brute force search to be effective.
Moreover, we'd like the attacker to spend as much resources for each
attempt as we do, even if they have access to dedicated silicon.

Argon2i is a resource intensive password key derivation scheme
optimised for the typical x86-like processor.  It runs in constant
time with respect to the contents of the password.

Typical applications are password checking (for online services), and
key derivation (so you can encrypt stuff).  You can use this for
instance to protect your private keys.

The version currently provided by Monocypher has no threading support,
so the degree of parallelism is currently limited to 1.  It's good
enough for most purposes anyway.

### crypto\_argon2i()

    void crypto_argon2i(uint8_t       *tag,       uint32_t tag_size,
                        void          *work_area, uint32_t nb_blocks,
                        uint32_t       nb_iterations,
                        const uint8_t *password,  uint32_t password_size,
                        const uint8_t *salt,      uint32_t salt_size,
                        const uint8_t *key,       uint32_t key_size,
                        const uint8_t *ad,        uint32_t ad_size);

- The minimum tag size is 4 bytes
- The minimum number of blocks is 8. (blocks are 1024 bytes big.)
- the work area must be big enough to hold the requested number of
  blocks, and suitably aligned for 64-bit integers.  Tip: just use
  `malloc()`.
- The minimum number of iterations is 1.
- The minimum salt size is 8 bytes.
- The key and additional data are optional.  They can be null if their
  respective size is zero.

Any deviation from these invariants may result in __undefined
behaviour.__

Recommended choice of parameters:

- If you need a key, use a 32 byte one.
- Do what you will with the additional data `ad`.
- Use a 32 byte tag to derive a 256-bit key.
- Put 128 bits of entropy in the salt.  16 random bytes work well.
- Use at least 3 iterations.  Argon2i is less safe with only one or
  two.  Otherwise, more memory is better than more iterations.

Use `crypto_memcmp()` to compare Argon2i outputs.  Argon2i is designed
to withstand offline attacks, but if you reveal your database through
timing leaks, the weakest passwords will be vulnerable.

The hardness of the computation can be chosen thus:

- Decide how long the computation should take.  Typically somewhere
  between half a second (convenient) and several seconds (paranoid).

- Try to hash a password with 3 iterations and 100.000 blocks (a
  hundred megabytes).  If it takes too long, reduce that number.  If
  it doesn't take long enough, increase that number.

- If the computation is too short even with all the memory you can
  spare, increase the number of iterations.


Constant time comparison
------------------------

Packaging an easy to use, state of the art, timing immune crypto
library took me over 2 months, full time.  It will all be for naught
if you start leaking information by using standard comparison
functions.

In crypto, we often need to compare secrets together.  A message
authentication code for instance: while the MAC sent over the network
along with a message is public, the true MAC is _secret_.  If the
attacker attempts a forgery, you don't want to tell him "your MAC is
wrong, _and it took me 384 microseconds to figure it out_".  If in the
next attempt it takes you 462 microseconds instead, it gives away the
fact that the attacker just got a few bytes right.  Next thing you
know, you've destroyed integrity.

You need special comparison functions, whose timing do not depend on
the content of the buffers.  They generally work with bit-wise or and
xor.

Monocypher provides 2 functions: `crypto_memcmp()` and
`crypto_zerocmp()`.

    int crypto_memcmp (const uint8_t *p1, const uint8_t *p2, size_t n);
    int crypto_zerocmp(const uint8_t *p , size_t n);

`crypto_memcmp()` returns 0 if it the two memory chunks are the same,
-1 otherwise. `crypto_zerocmp()` returns 0 if all bytes of the memory
chunk are zero, -1 otherwise.  They both run in constant time.  (More
precisely, their timing depends solely on the _length_ of their
inputs.)


Encryption (Chacha20)
---------------------

__Warning: encryption alone is not sufficient for security.__ Using
Chacha20 directly is therefore discouraged.  Use authenticated
encryption instead.

Monocypher provides an incremental interface for Chacha20, with an
initialisation, and as many encryption steps as you want.


### crypto\_chacha20\_H()

A not-so-cryptographic hash.  May be used for some specific purposes,
such as X25519 key derivation, or XChacha20 initialisation.  If in
doubt, do not use directly.  Use Blake2b.

The output `out` is a cryptographically secure random number _if_
there's enough entropy in in the input `key`.  X25519 shared secrets
have enough entropy.  The input `in` fills the space reserved for the
nonce and counter.  It doesn't have to be random.

    void crypto_chacha20_H(uint8_t       out[32],
                           const uint8_t key[32],
                           const uint8_t in [16]);

### crypto\_chacha20\_init()

    void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                              const uint8_t      key[32],
                              const uint8_t      nonce[8]);

Initialises a chacha context.  Again, don't use the same nonce and key
twice. You'd expose the XOR of subsequent encrypted messages, and
destroy confidentiality.

__Warning: don't select the nonce at random__ Unlike the authenticated
encryption we've seen at the top, this nonce is only 64 bits.  This is
too small for random nonces: you might reuse one by sheer dumb
misfortune.  Use a counter instead.

If there are multiple parties sending out messages, you can give them
all an initial nonce of 0, 1 .. n-1 respectively, and have them
increment their nonce by n.  (Also make sure the counters never wrap
around.)

### void crypto\_chacha20\_x_init()

    void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                                const uint8_t      key[32],
                                const uint8_t      nonce[24]);

Initialises a chacha context with a big nonce (192 bits).  This nonce
is big enough to be selected at random (use the OS; avoid user space
generators).  This is the init function Monocypher uses for
authenticated encryption.

The bigger nonce is allowed by a clever use of HChacha20.  The
security guarantees are the same as regular initialisation.  It is
just a tiny bit slower —it doesn't matter in practice.

### crypto\_chacha20\_encrypt()

    void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                                 uint8_t           *cipher_text,
                                 const uint8_t     *plain_text,
                                 size_t             message_size);

Encrypts the plain_text by XORing it with a pseudo-random stream of
numbers, seeded by the provided chacha20 context.  Decryption is the
same as encryption.  Once the context is initialised, encryption can
safely be chained thus:

    crypto_encrypt_chacha20(ctx, plain_0, cipher_0, length_0);
    crypto_encrypt_chacha20(ctx, plain_1, cipher_1, length_1);
    crypto_encrypt_chacha20(ctx, plain_2, cipher_2, length_2);

The input `plain_text` and the output `cipher_text` may point to the
same location, for in-place encryption.

The input `plain_text` is allowed to be null (0), in which case it
will be interpreted as an all zero input.  The cipher_text will then
contain the raw chacha20 stream.

I must insist, __encryption alone is not secure__.  Use authenticated
encryption.

### crypto\_chacha20\_stream()

    void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                                uint8_t           *cipher_text,
                                size_t             message_size);

Convenience function.  Same as `chacha20_encrypt()` with a null
`plain_text`.  Useful as a user space random number generator.  __Did
I tell you that user space random number generators are error prone?__
By the way, it's even worse in multithreaded programs.  Really, use
your OS random number generator.

Still, this function can be used outside of a security context:
deterministic procedural generation comes to mind.

### crypto\_chacha20\_set\_ctr()

    void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);

Resets the internal counter of the Chacha context to the value
specified in `ctr`. Resuming the encryption will use the stream at the
block `ctr` (or the byte `ctr×64`).

For instance, the following code has the same effect:

    // Discard part of the stream the hard way
    crypto_chacha20_init  (ctx, key, nonce);
    uint8_t tmp[512];
    crypto_chacha20_stream(ctx, tmp, 512);
    crypto_chacha20_stream(ctx, out, size);

    // Note: 512 bytes mean 8 blocks (64 bytes per block)

    // Skip part of the stream entirely
    crypto_chacha20_init   (ctx, key, nonce);
    crypto_chacha20_set_ctr(ctx, 8);
    crypto_chacha20_stream (ctx, out, size);

This can be used to encrypt (or decrypt) part of a long message, or to
implement some AEAD constructions such as the one described in rfc7539
(not implemented in Monocypher because of its complexity and
limitations).


One-time authentication (Poly1305)
----------------------------------

__Warning: Poly1305 is easy to mess up.__ Using it directly is just
asking for trouble.  Please don't.  Use authenticated encryption
instead.

Monocypher provides both a direct interface and an incremental
interface for Poly1305.

### direct interface

    void crypto_poly1305_auth(uint8_t        mac[16],
                              const uint8_t *m,
                              size_t         msg_size,
                              const uint8_t  key[32]);

Produces a message authentication code for the given message and
authentication key.  Be careful.  The requirements for this key are
_stringent_:

- It must be secret: the attacker cannot be allowed to guess that key.
- It must be shared: the recipient must know this key.  Without it,
  the integrity of the message cannot be verified.
- It must __never__ be reused. That would utterly destroy security,
  and allow the attacker to recover the key then forge messages.

You cannot use the session key for this: it is secret and shared, but
it is _reused_.  If you use it, the attacker will recover it as soon
as the second message is sent, and will break _everything_.

You cannot use a random number: if you don't send it over the network,
it won't be shared, and the recipient wont be able to check anything.
If you do, it won't be secret, and the attacker will be able to forge
messages.

The only practical source for the authentication key is a chunk of the
encryption stream used to encrypt the message.  However, you must
ensure you do not reuse that part of the stream to encrypt the message
itself: the attacker could guess the stream by guessing the message,
and forge away like a false-smith.

To get this right, you need a session key, a _unique_ nonce, and a
stream cipher.  Generate a stream with the session key and nonce.
Take the first 32 bits of that stream as your authentication key, then
use the _rest_ of the stream to encrypt your message.  Check out the
source code of `crypto_aead_lock()` to see how it's done.

### incremental interface


    void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);

    void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                                const uint8_t *m, size_t bytes);

    void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]);

This is pretty straightforward. The init function initialises a
context, and the update function authenticates the message chunk by
chunk.  Once the message is entirely processed, the final function
gives you the message authentication code.  For instance:

    uint8_t mac[16];
    crypto_poly1305_cxt ctx;
    crypto_poly1305_init  (&ctx, authentication_key);
    crypto_poly1305_update(&ctx, chunk1, chunk1_size);
    crypto_poly1305_update(&ctx, chunk2, chunk2_size);
    crypto_poly1305_update(&ctx, chunk3, chunk3_size);
    crypto_poly1305_final (&ctx, mac);
