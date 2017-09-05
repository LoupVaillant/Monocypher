Monocypher
----------

Monocypher is an easy to use, easy to deploy, auditable crypto library
inspired by [libsodium][] and [TweetNaCl][], written in portable C.

It means to eat libsodium's lunch.

[Official site.](http://loup-vaillant.fr/projects/monocypher/)

[libsodium]: http://libsodium.org
[TweetNaCl]: http://tweetnacl.cr.yp.to/

Installation
------------

just copy `src/monocypher.h` and `src/monocypher.c` into your project.

They compile as C99, C11, C++98, C++11, C++14, and C++17. (Tested with
gcc 5.4.0 and clang 2.8.0 on GNU/Linux.)

If you are using [Buck Build](https://buckbuild.com) and [Buckaroo](https://buckaroo.pm), then there is a Buck port maintained at [njlr/Monocypher](https://github.com/njlr/Monocypher). 

### Language bindings

So far, I am aware of bindings for the following languages:

* [Crystal](https://github.com/konovod/monocypher.cr)
* [Lua](https://github.com/philanc/luanacha)

### Alternate distributions

So far, I am aware of the following alternate packages:

* [AUR package](https://aur.archlinux.org/packages/monocypher/) for
  Arch Linux.


Test suite
----------

    $ make all
    $ ./test.sh

It should display a nice printout of all the tests, all starting with
"OK".  If you see "FAILURE" anywhere, something has gone very wrong
somewhere.  Note: the fuzz tests depend on libsodium 1.0.12 or above.
Install it before you run them.

To run only the self contained tests, run

    $ make self
    $ ./self

*Do not* use Monocypher without running the self contained tests at
 least once.

[donna]: https://github.com/floodyberry/ed25519-donna


### More serious testing

The makefile may be modified to activate sanitising.  Just run the
previous tests under the various sanitisers.  If you compile for
coverage mapping, the `coverage.sh` mapping can generate a report.
Just run one of those (make sure the makefile is set up accordingly):

    $ ./coverage.sh self
    $ ./coverage.sh donna
    $ ./coverage.sh sodium

You can also run the tests under Valgrind:

    $ valgrind ./self
    $ valgrind ./donna
    $ valgrind ./sodium

### Serious auditing

The code may be analysed more formally with [Frama-c][] and the
[TIS interpreter][TIS].  To analyse the code with Frama-c, run:

    $ make formal-analysis
    $ ./frama-c.sh

This will have Frama-c parse, and analyse the code, then launch a GUI.
You must have Frama-c installed.  See `frama-c.sh` for the recommended
settings.  To run the code under the TIS interpreter, run

    $ make formal-analysis
    $ cd formal-analysis
    $ tis-interpreter.sh *.c

(Note: `tis-interpreter.sh` is part of TIS.  If it is not in your
path, adjust the command accordingly.)

[Frama-c]:http://frama-c.com/
[TIS]: http://trust-in-soft.com/tis-interpreter/


Speed benchmark
---------------

    $ make speed
    $ ./speed

It should tell you how well Monocypher fares against libsodium.
Results may vary between platforms.  Requires the POSIX
`clock_gettime()` function, which is generally disabled when using
-std=C99 for strict C compliance. (See the makefile to modify it.)

To make sure the benchmark is fair, compile libsodium with suitable
optimisation levels.  (My first benchmarks made libsodium look really
bad with Argon2i).


Customisation
-------------

If you want to use ed25519 with the official SHA-512 hash instead of
the default Blake2b, do as the test suite does:

- Compile monocypher.c with option -DED25519_SHA512, or modify the
  relevant preprocessor directives at the beginning of monocypher.c.

- Link the final program with a suitable SHA-512 implementation.  You
  can use the sha512.c and sha512.h files provided here.

Note that even though the default hash (Blake2b) is not "standard",
you can still upgrade to faster implementations if you really need to.
The Donna implementations of ed25519 for instance can use a custom
hash —one test does just that.
