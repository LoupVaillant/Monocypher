Speed benchmarks
================

    $ cd tests/speed
    $ make speed

This will give you an idea how fast Monocypher is on your machine.  Make
sure you run it on the target platform if performance is a concern.  If
Monocypher is too slow, try libsodium.  If you're not sure, you can
always switch later.

Note: the speed benchmark currently requires the POSIX
`clock_gettime()` function.

There are similar benchmarks for libsodium, TweetNaCl, LibHydrogen,
c25519, and ed25519-donna (the portable, 32-bit version):

    $ make speed-sodium
    $ make speed-tweetnacl
    $ make speed-hydrogen
    $ make speed-c25519
    $ make speed-donna

(The `speed-hydrogen` target assumes it has pkg-config installed. Try
`make pkg-config-libhydrogen` as root if it is not.)

You can also adjust the optimisation options for Monocypher, TweetNaCl,
and c25519 (the default is `-O3 march=native`):

    $ make speed           CFLAGS="-O2"
    $ make speed-tweetnacl CFLAGS="-O2"
