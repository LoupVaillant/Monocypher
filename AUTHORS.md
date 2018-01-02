Designers
---------

- **Chacha20:** Daniel J. Bernstein.
- **Poly1305:** Daniel J. Bernstein.
- **Blake2:**   Jean-Philippe Aumasson, Christian Winnerlein, Samuel Neves,
                and Zooko Wilcox-O'Hearn
- **Argon2:**   Alex Biryukov, Daniel Dinu, and Dmitry Khovratovich
- **X25519:**   Daniel J. Bernstein
- **EdDSA:**    Daniel J. Bernstein, Bo-Yin Yang, Niels Duif, Peter
                Schwabe, and Tanja Lange

Implementors
------------

- **Chacha20:** Loup Vaillant, implemented from spec.
- **Poly1305:** Loup Vaillant, implemented from spec.
- **Blake2b:**  Loup Vaillant, implemented from spec.
- **Argon2i:**  Loup Vaillant, implemented from spec.
- **X25519:**   Daniel J. Bernstein, taken and packaged from SUPERCOP
                ref10.
- **EdDSA:**    Daniel J. Bernstein, taken and adapted from SUPERCOP
                ref10 and TweetNaCl.

Test suite
----------

Designed and implemented by Loup Vaillant, using _libsodium_ (by many
authors), and _ed25519-donna_ (by Andrew Moon —floodyberry).

Manual
------

Loup Vaillant did a first draft, Fabio Scotoni rewrote the manual into
proper man pages, and Michael Savage did extensive editing and
proofreading.

Thanks
------

Mike Pechkin and André Maroneze found bugs in earlier versions of
Monocypher.

Andrew Moon clarified carry propagation in modular arithmetic.

Fabio Scotoni provided much needed advice about testing, interface, and
above all, packaging.
