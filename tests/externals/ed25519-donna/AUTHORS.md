The following files have been written by Andrew Moon and have been
dedicated to the public domain:

* curve25519-donna-32bit.h
* curve25519-donna-helpers.h
* ed25519.c
* modm-donna-32bit.h

The following files carry no copyright information:

* ed25519-donna-32bit-tables.h
* ed25519-donna-basepoint-table.h
* ed25519-donna-batchverify.h
* ed25519-donna-impl-base.h
* ed25519-donna-portable-identify.h
* ed25519-donna-portable.h
* ed25519-hash-custom.h
* ed25519-hash.h
* ed25519-randombytes.h
* ed25519.h

However, their git history shows that they were written by Andrew Moon
as well; the initial check-in has public domain headers for all files
(git commit a98e950f).  Newer files lack a similar header, but it seems
the author didn't realise that that adding them would be required
(see https://github.com/floodyberry/ed25519-donna/issues/24);
issue comment 24#issuecomment-82552250 in particular seems to suggest as
much.  It is therefore assumed that they are intended to be placed in
the public domain as well.

curve25519-donna.h has been modified by Andrew Moon, based on the
amd64-51-30k implementation by Daniel J. Bernstein, Niels Duif,
Tanja Lange, Peter Schwabe, and Bo-Yin Yang.  The amd64-51-30k
implementation is contained in SUPERCOP
(<https://bench.cr.yp.to/supercop.html>);
the amd64-51-30k is part of the Ed25519 software, which has been
dedicated to the public domain by its authors
(<https://ed25519.cr.yp.to/software.html>).

The code in this directory has been obtained via
<https://www.github.com/floodyberry/ed25519-donna>.

