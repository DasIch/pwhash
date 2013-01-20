# coding: utf-8
"""
    pwhash._openssl
    ~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from threading import Lock

from cffi import FFI


_OPENSSL_LOCK = Lock()


def parse_openssl_version(version):
    status = version & 0xF
    version >>= 4
    patch = version & 0xFF
    version >>= 8
    fix = version & 0xFF
    version >>= 8
    minor = version & 0xFF
    version >>= 8
    major = version & 0xFF
    return major, minor, fix, patch, status


ffi = FFI()
ffi.cdef("""
    unsigned long SSLeay(void);

    int PKCS5_PBKDF2_HMAC_SHA1(
        const char *pass, int passlen,
        const unsigned char *salt, int saltlen,
        int iter,
        int keylen,
        unsigned char *out
    );
""")
openssl = ffi.verify("""
    #include <openssl/crypto.h>
    #include <openssl/evp.h>
""")

if parse_openssl_version(openssl.SSLeay()) >= (1, 0, 1, 0, 15):
    ffi.cdef("""
        typedef struct env_md_st { ...; } EVP_MD;

        int EVP_MD_size(const EVP_MD *md);

        const EVP_MD *EVP_md5(void);
        const EVP_MD *EVP_sha1(void);
        const EVP_MD *EVP_sha224(void);
        const EVP_MD *EVP_sha256(void);
        const EVP_MD *EVP_sha384(void);
        const EVP_MD *EVP_sha512(void);

        int PKCS5_PBKDF2_HMAC(
            const char *pass, int passlen,
            const unsigned char *salt, int saltlen,
            int iter,
            const EVP_MD *digest,
            int keylen,
            unsigned char *out
        );
    """)
    openssl = ffi.verify("""
        #include <openssl/crypto.h>
        #include <openssl/evp.h>
    """)
    METHODS = {
        "hmac-md5": openssl.EVP_md5,
        "hmac-sha1": openssl.EVP_sha1,
        "hmac-sha224": openssl.EVP_sha224,
        "hmac-sha256": openssl.EVP_sha384,
        "hmac-sha512": openssl.EVP_sha512
    }

    def _pbkdf2(password, salt, rounds, hash_length, method="hmac-sha1"):
        if method not in METHODS:
            raise NotImplementedError("%s is not a supported method")
        hash = ffi.new("unsigned char[]", hash_length)
        with _OPENSSL_LOCK:
            result = openssl.PKCS5_PBKDF2_HMAC(
                password, len(password),
                ffi.new("const unsigned char[]", salt), len(salt),
                rounds,
                METHODS[method](),
                hash_length,
                hash
            )
        if result != 1:
            raise RuntimeError("something went wrong: %d" % result)
        return b"".join(ffi.buffer(hash))

else:
    METHODS = frozenset(["hmac-sha1"])

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
        return b"".join(ffi.buffer(hash))
