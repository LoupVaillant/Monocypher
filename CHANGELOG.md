2.0.6
-----
2019/10/21

- Added the `BLAKE2_NO_UNROLLING` preprocessor definition. Activating it
  makes the binary about 5KB smaller, and speeds up processing times on
  many embedded processors.
- Reduced the stack usage of signature verification by about
  40%. Signature verification now fits in smaller machines.
- Fixed many implicit casts warnings.
- Fixed the manual here and there.
- Lots of small nitpicks.


2.0.5
-----
2018/08/23

- Faster EdDSA signatures and verification.  Like, 4 times as fast.


2.0.4
-----
2018/06/24

- Corrected a critical vulnerability in EdDSA, where crypto_check() was
  accepting invalid signatures.  (Found by Mike Pechkin.)  The current
  fix removes a buggy optimisation, effectively halving the performance
  of EdDSA.
- The test suite no longer tries to allocate zero bytes (some platforms
  fail such an allocation).

2.0.3
-----
2018/06/16

- Corrected undefined behaviour in Blake2b
- Improved the test suite (faster, better coverage)

2.0.2
-----
2018/04/23

- Corrected a couple failures to wipe secret buffers.
- Corrected a bug that prevented compilation in Ed25519 mode.
- Adjusted the number of test vectors in the test suite.
- Improved tests for incremental interfaces.
- Replaced the GNU all permissive licence by a public domain dedication
  (Creative Commons CC-0).  The BSD licence remains as a fallback.

2.0.1
-----
2018/03/07

- Followed a systematic pattern for the loading code of symmetric
  crypto.  It is now easier to review.
- Tweaked Poly1305 code to make it easier to prove correct.

2.0.0
-----
2018/02/14

- Changed the authenticated encryption format.  It now conforms to
  RFC 7539, with one exception: it uses XChacha20 initialisation instead
  of the IETF version of Chacha20.  This new format conforms to
  Libsodium's `crypto_aead_xchacha20poly1305_ietf_encrypt`.
- Removed `crypto_lock_encrypt()` and `crypto_lock_auth()`.
- Renamed `crypto_lock_aead_auth()` to `crypto_lock_auth_ad()`.
- Renamed `crypto_unlock_aead_auth()` to `crypto_unlock_auth_ad()`.
- Added  `crypto_lock_auth_message()` and `crypto_unlock_auth_message()`
- Renamed `crypto_aead_lock` to `crypto_lock_aead`;
- Renamed `crypto_aead_unlock` to `crypto_unlock_aead`;

The format change facilitates optimisation by aligning data to block
boundaries.  The API changes increase consistency.

1.1.0
-----
2018/02/06

- Rewrote the manual into proper man pages.
- Added incremental interfaces for authenticated encryption and
  signatures.
- A couple breaking API changes, easily fixed by renaming the affected
  functions.

1.0.1
-----
2017/07/23

- Optimised the loading and unloading code of the symmetric crypto
  (Blake2b, sha512, Chacha20, and Poly1305).
- Fused self contained tests together for easier analysis with Frama-C
  and the TIS interpreter.

1.0
---
2017/07/18

- Renamed `crypto_chacha20_Xinit` to `crypto_chacha20_x_init`, for
  consistency reasons (snake case everywhere).
- Fixed signed integer overflow detected by UBSan.
- Doubled the speed of EdDSA by performing the scalar product in
  Montgomery space.

0.8
---
2017/07/06

- Added about a hundred lines of code to improve performance of public
  key cryptography.  Diffie-Hellman is now 20% faster than before.
  (The effects are less pronounces for EdDSA).
- Added random self-consistency tests.
- Added a speed benchmark against libsodium.

0.7
---
2017/06/07

- Slightly changed the authenticated encryption API.  Functions are
  now all in "detached" mode.  The reason is better support for
  authenticated encryption _without_ additional data.
- Rewrote Blake2b from spec, so it can use the same licence as
  everything else.
- Added random tests that compare Monocypher with libsodium and
  ed25519-donna.
- Added explicit support for Frama-C analysis (this doesn't affect the
  source code)

0.6
---
2017/03/17

- Fixed incorrect poly1305 output on empty messages.  (Found by Mike
  Pechkin.)

0.5
---
2017/03/10

- Fixed many undefined behaviours in curve25519, that occur whenever
  we perform a left shift on a signed negative integer.  It doesn't
  affect the generated code, but you never know.  (Found with Frama-C
  by André Maroneze.)

Fun fact: TweetNaCl and ref10 have the same bug.  Libsodium have
corrected the issue, though.

For those who don't comprehend the magnitude of this madness, the
expression `-1 << 3` is undefined in C.  This is explained in
section 6.5.7(§4) of the C11 standard.

0.4
---
2017/03/09

- Fixed critical bug causing Argon2i to fail whenever it uses more
  than 512 blocks.  It was reading uninitialised memory, and the
  results were incorrect.  (Found by Mike Pechkin.)
- Fixed an undefined behaviour in curve25519 (`fe_tobytes()`).  It was
  accessing uninitialised memory, before throwing it away.  It didn't
  affect the compiled code nor the results, but you never know.
  (Found with [Frama-C](http://frama-c.com) by André Maroneze.)

0.3
---
2017/02/27

- Got the invariants of poly1305 right, put them in the comments.
  There was no bug, but that was lucky (turned out the IETF test
  vectors were designed to trigger the bugs I was afraid of).
- Simplified poly1305 finalisation (replaced conditional subtraction
  by a carry propagation).
- Made a few cosmetic changes here and there.

0.2
---
????/??/??

- Public interface significantly reworked. Removed redundant, hard to
  mess up constructions.
- Added AEAD.
- Sped up curve25519 by a factor of more than 6 (switched to ref10
  arithmetic)
- Added various test vectors, completed the consistency tests.

0.1
---
2016/??/??
