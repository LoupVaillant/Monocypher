Monocypher
----------

Monocypher is an easy to use, easy to deploy, auditable crypto library
inspired by [libsodium][] and [TweetNaCl][], written in portable C.

[Official site.](http://loup-vaillant.fr/projects/monocypher/)

[libsodium]: http://libsodium.org
[TweetNaCl]: http://tweetnacl.cr.yp.to/


Generating the test vectors
---------------------------

You are currently using the source repository, meant for developers.
You need to generate the test vectors before you can run the test
suite.  This requires requires Libsodium 1.0.12 or later:

    $ cd tests/gen/
    $ make
    $ cd ../..

This will generate `dist/tests/vectors.h`, which contains all the test
vectors. You can now go to the `dist/` directory, then compile and
test Monocypher like end users.  There's also a
[README.md](dist/README.md) there.


Installation
------------

The easiest way to use Monocypher is to include `src/monocypher.h` and
`src/monocypher.c` directly into your project.  They compile as C99,
C11, C++98, C++11, C++14, and C++17.

Alternatively, you can go to the `dist` directory, and follow the
installation instructions there.

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
