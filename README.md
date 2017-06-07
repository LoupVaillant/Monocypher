Current status
--------------

0.7.  Interfaces are stable.  Needs a few more consistency tests.

Note: the authenticated encryption API changed slightly since 0.6, to
improve consistency.


Test suite
----------

    $ make all
    $ ./test.sh

It should display a nice printout of all the tests, all starting with
"OK".  If you see "FAILURE" anywhere, something has gone very wrong
somewhere.  Note: the fuzz tests depend on libsodium.  Install it
before you run them.

To run only the self contained tests, run

    $ make test
    $ ./test

To run only the edDSA fuzz tests (compares Monocypher with
ed25519-donna), run

    $ make donna
    $ ./donna

*Do not* use Monocypher without having run the self contained tests at
least once.

To analyse the code with frama-c, run

    $ make frama-c
    $ ./frama-c.sh

This will have frama-c parse, and analyse the code, then launch a GUI.
You must have frama-c installed.  See frama-c.sh for the recommended
settings.

Integration to your project
---------------------------

Just include src/monocypher.c and src/monocypher.h in your project.

They compile as C99, C11, C++98, C++11, C++14, and C++17. (Tested with
gcc 5.4.0 and clang 2.8.0 on GNU/Linux.)


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
hash —one of the tests does just that.
