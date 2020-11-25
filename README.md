[![TrustInSoft CI](https://ci.trust-in-soft.com/projects/LoupVaillant/Monocypher.svg?branch=master)](https://ci.trust-in-soft.com/projects/LoupVaillant/Monocypher)


Monocypher (Developer Edition)
------------------------------

_(This is the bleeding edge, not yet released version.  If you just want
to use Monocypher, grab the [latest version][latest], or download the
[source][] and [header][] files directly. If you want to contribute, see
the notes at the end.)_

[source]: https://monocypher.org/download/monocypher.c
[header]: https://monocypher.org/download/monocypher.h
[latest]: https://monocypher.org/download/monocypher-latest.tar.gz

---

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
your system by running `make install-doc`. Official releases also have a
`doc/html/` folder with an html version.


Installation
------------

### Option 1: grab the sources

The easiest way to use Monocypher is to include `src/monocypher.h` and
`src/monocypher.c` directly into your project.  They compile as C (since
C99) and C++ (since C++98).


### Option 2: grab the library

Run `make`, then grab the `src/monocypher.h` header and either the
`lib/libmonocypher.a` or `lib/libmonocypher.so` library.  The default
compiler is `gcc -std=gnu99`, and the default flags are `-pedantic -Wall
-Wextra -O3 -march=native`.  If they don't work on your platform, you
can change them like this:

    $ make CC="clang -std=c99" CFLAGS="-O2"

### Option 3: install it on your system

The following should work on most UNIX systems:

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

The same test suite can be run under Clang sanitisers and Valgrind, and
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
    $ tis-interpreter.sh --cc -Dvolatile= tests/formal-analysis/*.c

Notes:

- `tis-interpreter.sh` is part of TIS.  If it is not in your path,
  adjust the command accordingly.

- The TIS interpreter sometimes fails to evaluate correct programs when
  they use the `volatile` keyword (which is only used as an attempt to
  prevent dead store elimination for memory wipes).  The `-cc
  -Dvolatile=` option works around that bug by ignoring `volatile`
  altogether.

[Frama-c]:https://frama-c.com/
[TIS]: https://trust-in-soft.com/tis-interpreter/


Speed benchmark
---------------

    $ make speed

This will give you an idea how fast Monocypher is on your machine.  Make
sure you run it on the target platform if performance is a concern.  If
Monocypher is too slow, try Libsodium.  If you're not sure, you can
always switch later.


Note: the speed benchmark currently requires the POSIX
`clock_gettime()` function.

There are similar benchmarks for Libsodium, TweetNaCl, LibHydrogen,
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


Customisation
-------------

Monocypher has optional compatibility with Ed25519. To have that, add
`monocypher-ed25519.h` and `monocypher-ed25519.c` provided in
`src/optional` to your project.  If you're using the makefile, define
the `USE_ED25519` variable to link it to monocypher.a and monocypher.so:

    $ make USE_ED25519=true

If you install Monocypher with the makefile, you also need that option
to copy `monocypher-ed25519.h` automatically:

    $ make install USE_ED25519=true

Monocypher also has the `BLAKE2_NO_UNROLLING` preprocessor flag, which
is activated by compiling monocypher.c with the `-DBLAKE2_NO_UNROLLING`
option.

The `-DBLAKE2_NO_UNROLLING` option is a performance tweak.  By default,
Monocypher unrolls the Blake2b inner loop, because doing so is over 25%
faster on modern processors.  Some embedded processors however, run the
unrolled loop _slower_ (possibly because of the cost of fetching 5KB of
additional code).  If you're using an embedded platform, try this
option.  The binary will be about 5KB smaller, and in some cases faster.


Contributor notes
-----------------

If you are reading this, you cloned the GitHub repository.  You miss a
couple files that ship with the tarball releases:

- The `tests/vectors.h` header.  Generating it requires Libsodium. Go
  to `tests/gen/`, then run `make`.
- The html version of the manual, generated by the `doc/man2html.sh`
  script.  You will need mandoc.

To generate a tarball, simply type `make dist`. It will make a tarball
with a name that matches the current version (using `git describe`), in
the current directory.
