Monocypher
----------

Monocypher is an easy to use, easy to deploy, auditable crypto library
inspired by [libsodium][] and [TweetNaCl][], written in portable C.

It means to eat Libsodium's lunch.

[Official site.](http://loup-vaillant.fr/projects/monocypher/)

[libsodium]: http://libsodium.org
[TweetNaCl]: http://tweetnacl.cr.yp.to/

Manual
------

The `doc/man/` folder contains the man pages.  You can install them in
your system by running `make install-doc`.

There is a html version in `doc/html/`, that you can regenerate by
executing the `doc/man2html.sh` script (this requires mandoc).


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
libmonocypher.a (or libmonocypher.so).


### Known language bindings

* [Crystal](https://github.com/konovod/monocypher.cr)
* [Lua](https://github.com/philanc/luanacha)
* [Zig](https://bitbucket.org/mihailp/zig-monocypher/src/default)
  (http://ziglang.org/).


### Known alternate distributions

* [AUR package](https://aur.archlinux.org/packages/monocypher/) for
  Arch Linux.
* If you are using [Buck Build](https://buckbuild.com) and
  [Buckaroo](https://buckaroo.pm), then there is a Buck port
  maintained at [njlr/Monocypher](https://github.com/njlr/Monocypher).


Test suite
----------

    $ make test

It should display a nice printout of all the tests, all starting with
"OK".  If you see "FAILURE" anywhere, something has gone very wrong
somewhere.

*Do not* use Monocypher without running those tests at least once.


### More serious testing

You can run the test suite under clang sanitizers or valgrind:

    $ make clean
    $ make test CC="clang -std=c99" CFLAGS="-fsanitize=address"

    $ make clean
    $ make test CC="clang -std=c99" CFLAGS="-fsanitize=memory"

    $ make clean
    $ make test CC="clang -std=c99" CFLAGS="-fsanitize=undefined"

    $ make clean
    $ make test.out
    $ valgrind ./test.out

You can also check code coverage:

    $ make clean
    $ make test CC="clang -std=c99" CFLAGS="-fprofile-instr-generate -fcoverage-mapping"
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
    $ cd tests/formal-analysis
    $ tis-interpreter.sh *.c

(Note: `tis-interpreter.sh` is part of TIS.  If it is not in your
path, adjust the command accordingly.)

[Frama-c]:http://frama-c.com/
[TIS]: http://trust-in-soft.com/tis-interpreter/


Speed benchmark
---------------

    $ make speed

This will give you an idea how fast Monocypher is on your machine.
Make sure you run it on the target platform if performance is a
concern.  If Monocypher is too slow, try libsodium or NaCl.  If you're
not sure, you can always switch later.

Note: the speed benchmark currently requires the POSIX
`clock_gettime()` function.


Customisation
-------------

For simplicity, compactness, and performance reasons, Monocypher
signatures default to EdDSA with curve25519 and Blake2b.  This is
different from the more mainstream Ed25519, which uses SHA-512
instead.

If you need Ed25519 compatibility, you need to do the following:

- Compile Monocypher.c with option -DED25519_SHA512.
- Link the final program with a suitable SHA-512 implementation.  You
  can use the `sha512.c` and `sha512.h` files provided in `src/`.

Note that even though the default hash (Blake2b) is not "standard",
you can still upgrade to faster implementations if you really need to.
The Donna implementations of ed25519 for instance can use a custom
hash —one test does just that.


Contributor notes
-----------------

If you just cloned the GitHub repository, you will miss a couple files
that ship with the tarball releases:

- The `test/vectors.h` header.  Generating it requires libsodium. Go
  to `test/gen/`, then run `make`.

- The html version of the manual, generated by the `doc/man2html.sh`
  script.  You will need mandoc.

To generate a tarball, simply type `make tarball`.  By default, it
will generate `../monocypher-master.tar.gz` (yes, in the parent
directory).  You can override those defaults thus:

    make tarball TARBALL_VERSION=x.y.z TARBALL_DIR=../my_tarballs

This will create a `../my_tarballs/monocypher-x.y.z.tar.gz`, archive
that contains a single `monocypher-x.y.z` folder with everything in
it.
