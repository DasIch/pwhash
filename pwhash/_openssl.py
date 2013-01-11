# coding: utf-8
"""
    pwhash.openssl
    ~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from threading import Lock

from cffi import FFI


_OPENSSL_LOCK = Lock()

METHODS = frozenset(["hmac-sha1"])


ffi = FFI()
ffi.cdef("""
        int PKCS5_PBKDF2_HMAC_SHA1(
            const char *pass, int passlen,
            const unsigned char *salt, int saltlen,
            int iter,
            int keylen,
            unsigned char *out
        );
""")
openssl = ffi.verify("#include <openssl/evp.h>")


def _pbkdf2(password, salt, rounds, hash_length, method="hmac-sha1"):
    if method not in METHODS:
        raise NotImplementedError("%s is not a supported method")
    hash = ffi.new("unsigned char[]", hash_length)
    with _OPENSSL_LOCK:
        result = openssl.PKCS5_PBKDF2_HMAC_SHA1(
            password, len(password),
            ffi.new("const unsigned char[]", salt), len(salt),
            rounds,
            hash_length,
            hash
        )
    if result != 1:
        raise RuntimeError("something went wrong")
    return b"".join(ffi.buffer(hash)).encode("hex")
