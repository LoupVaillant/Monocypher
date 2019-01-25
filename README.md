Monocypher
----------

Monocypher is an easy to use, easy to deploy, auditable crypto library
written in portable C.  It approaches the size of [TweetNaCl][] and the
speed of [Libsodium][].

[Official site.](https://monocypher.org/)  
[Official releases.](https://monocypher.org/download/)

[Libsodium]: https://libsodium.org
[TweetNaCl]: https://tweetnacl.cr.yp.to/

Manual
------

The manual can be found at https://monocypher.org/manual/, and in the
`doc/` folder.

The `doc/man/` folder contains the man pages.  You can install them in
your system by running `make install-doc`.

Unless you cloned the git repository, there is a html version in
`doc/html/`, that you can regenerate by executing the `doc/man2html.sh`
script.  This requires mandoc.


Installation
------------

The easiest way to use Monocypher is to include `src/monocypher.h` and
`src/monocypher.c` directly into your project.  They compile as C99,
C11, C++98, C++11, C++14, and C++17.

Alternatively, you can run `make`, then grab `lib/libmonocypher.a` or
`lib/libmonocypher.so`.  If you're running a UNIX system, you can even
install Monocypher (you need to be root):

    $ make install

This will install Monocypher in `/usr/local/` by default. Libraries
will go to `/usr/local/lib/`, the header in `/usr/local/include/`, and
the man pages in `/usr/local/share/man/man3`.  You can change those
defaults with the `PREFIX` and `DESTDIR` variables thus:

    $ make install PREFIX="/opt"

Once installed, you can use `pkg-config` to compile and link your
program.  For instance, if you have a one file C project that uses
Monocypher, you can compile it thus:

    $ gcc -o myProgram myProgram.c        \
        $(pkg-config monocypher --cflags) \
        $(pkg-config monocypher --libs)

The `cflags` line gives the include path for monocypher.h, and the
`libs` line provides the link path and option required to find
`libmonocypher.a` (or `libmonocypher.so`).


Test suite
----------

    $ make test

It should display a nice printout of all the tests, all starting with
"OK".  If you see "FAILURE" anywhere, something has gone very wrong
somewhere.

*Do not* use Monocypher without running those tests at least once.

The same test suite can be run under clang sanitisers and valgrind, and
be checked for code coverage:

    $ tests/test.sh
    $ tests/coverage.sh


### Serious auditing

The code may be analysed more formally with [Frama-c][] and the
[TIS interpreter][TIS].  To analyse the code with Frama-c, run:

    $ tests/formal-analysis.sh
    $ tests/frama-c.sh

This will have Frama-c parse, and analyse the code, then launch a GUI.
You must have Frama-c installed.  See `frama-c.sh` for the recommended
settings.  To run the code under the TIS interpreter, run

    $ tests/formal-analysis.sh
    $ tis-interpreter.sh tests/formal-analysis/*.c

(Note: `tis-interpreter.sh` is part of TIS.  If it is not in your
path, adjust the command accordingly.)

[Frama-c]:http://frama-c.com/
[TIS]: http://trust-in-soft.com/tis-interpreter/


Speed benchmark
---------------

    $ make speed

This will give you an idea how fast Monocypher is on your machine.
Make sure you run it on the target platform if performance is a
concern.  If Monocypher is too slow, try Libsodium or NaCl.  If you're
not sure, you can always switch later.

Note: the speed benchmark currently requires the POSIX
`clock_gettime()` function.

There are similar benchmarks for Libsodium and TweetNaCl:

    $ make speed-sodium
    $ make speed-tweetnacl

You can also adjust the optimisation options for Monocypher and
TweetNaCl (the default is `-O3 march=native`):

    $ make speed           CFLAGS="-O2"
    $ make speed-tweetnacl CFLAGS="-O2"


Customisation
-------------

Monocypher has two preprocessor flags: `ED25519_SHA512` and
`BLAKE2_NO_UNROLLING`, which are activated by compiling monocypher.c
with the options `-DED25519_SHA512` and `-DBLAKE2_NO_UNROLLING`
respectively.

The `-DED25519_SHA512` option is a compatibility feature for public key
signatures.  The default is EdDSA with Curve25519 and Blake2b.
Activating the option replaces it by Ed25519 (EdDSA with Curve25519 and
SHA-512).  When this option is activated, you will need to link the
final program with a suitable SHA-512 implementation.  You can use the
`sha512.c` and `sha512.h` files provided in `src/optional`.  The
makefile does this linking automatically whenever the `$CFLAGS` variable
contains the `-DED25519_SHA512` option. For instance:

    $ make CFLAGS="-O2 -DED25519_SHA512"

The `-DBLAKE2_NO_UNROLLING` option is a performance tweak.  By default,
Monocypher unrolls the Blake2b inner loop, because it is over 25% faster
on modern processors.  On some embedded processors however, unrolling
the loop makes it _slower_ (the unrolled loop is 5KB bigger, and may
strain the instruction cache).  If you're using an embedded platform,
try this option.  The binary will be smaller, perhaps even faster.


Contributor notes
-----------------

If you just cloned the GitHub repository, you will miss a couple files
that ship with the tarball releases:

- The `test/vectors.h` header.  Generating it requires Libsodium. Go
  to `test/gen/`, then run `make`.
- The html version of the manual, generated by the `doc/man2html.sh`
  script.  You will need mandoc.

To generate a tarball, simply type `make tarball`. It will make a
tarball with a name that matches the current version (as written in
VERSION.md), in the current directory.
