Security Considerations
=======================

Hashing and verifying passwords is one of the most sensitive parts of any
application. Why then should you trust pwhash to do the right thing?

The only honest answer I can give you is that you shouldn't, nevertheless
there are several measures I have taken to ensure that I don't fuck up.


Not implementing hashing functions
----------------------------------

The first measure of defense is that pwhash itself contains no code that
implements cryptographic hash functions. Instead pwhash uses libraries and
bindings to libraries that implement those hash functions that are considered
to be trustworthy and secure.

Specifically pwhash uses `CommonCrypto`_ (on OS X) and `OpenSSL`_ (everywhere
else) for PBKDF2, `py-bcrypt`_ for BCrypt and the standard library modules
:mod:`hmac` and :mod:`hashlib` for anything else.

.. _CommonCrypto: https://developer.apple.com/library/mac/#documentation/Darwin/Reference/ManPages/man3/Common%20Crypto.3cc.html
.. _OpenSSL: http://www.openssl.org/
.. _py-bcrypt: http://www.mindrot.org/projects/py-bcrypt/


Using timing-safe comparision functions
---------------------------------------

Unfortunately none of the implementations mentioned above provide a way to
verify hashes. This is a problem because the naive solution of using ``a == b``
may be algorithmically correct but leaks timing information due to `==` being
lazy. This makes it possible to determine the secret, byte by byte using a
fairly low amount of attempts in a non-negligible amount of time.

So to verify passwords pwhash uses the `timingsafe_bcmp` function OpenBSD uses,
to compare hashes in a manner that exposes only timing information about the
total length of the compared secret hash. This should prevent any timing
attacks an attacker might launch on the off chance she finds a way to control
the hashes compared in a way that is useful to her.

As the output of a cryptographic hash function is supposed to be unpredicatable
and we only compare hashes this is unlikely.
