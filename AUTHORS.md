Designers
---------

- **Chacha20:** Daniel J. Bernstein.
- **Poly1305:** Daniel J. Bernstein.
- **Blake2:**   Jean-Philippe Aumasson, Christian Winnerlein, Samuel Neves,
                and Zooko Wilcox-O'Hearn
- **Argon2:**   Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich
- **X25519:**   Daniel J. Bernstein
- **edDSA:**    Daniel J. Bernstein, Bo-Yin Yang, Niels Duif, Peter
                Schwabe, and Tanja Lange

Implementors
------------

- **Chacha20:** Loup Vaillant, implemented from spec.
- **Poly1305:** Loup Vaillant, implemented from spec.
- **Blake2b:**  Loup Vaillant, implemented from spec.
- **Argon2i:**  Loup Vaillant, implemented from spec.
- **X25519:**   Daniel J. Bernstein, taken and packaged from SUPERCOP
                ref10.
- **edDSA:**    Daniel J. Bernstein, taken and adapted from SUPERCOP
                ref10 and TweetNaCl.

Test suite
----------

Designed and implemented by Loup Vaillant, using _libsodium_ (by many
authors), and _ed25519-donna_ (by Andrew Moon —floodyberry).

Thanks
------

Mike Pechkin and André Maroneze for finding bugs in earlier versions,
and Andrew Moon for clarifying carry propagation in modular
arithmetic.

