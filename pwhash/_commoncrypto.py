# coding: utf-8
"""
    pwhash._commoncrypto
    ~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from threading import Lock

from cffi import FFI


_COMMONCRYPTO_LOCK = Lock()


# CCPBKDFAlgorithm
kCCPBKDF2 = 2

# CCPseudoRandomAlgorithm
kCCPRFHmacAlgSHA1 = 1
kCCPRFHmacAlgSHA224 = 2
kCCPRFHmacAlgSHA256 = 3
kCCPRFHmacAlgSHA384 = 4
kCCPRFHmacAlgSHA512 = 5

METHODS = {
    "hmac-sha1": kCCPRFHmacAlgSHA1,
    "hmac-sha224": kCCPRFHmacAlgSHA224,
    "hmac-sha256": kCCPRFHmacAlgSHA256,
    "hmac-sha384": kCCPRFHmacAlgSHA384,
    "hmac-sha512": kCCPRFHmacAlgSHA512
}

ffi = FFI()
ffi.cdef("""
    typedef uint32_t CCPBKDFAlgorithm;
    typedef uint32_t CCPseudoRandomAlgorithm;

    int CCKeyDerivationPBKDF(
        CCPBKDFAlgorithm algorithm,
        const char *password, size_t passwordLen,
        const uint8_t *salt, size_t saltLen,
        CCPseudoRandomAlgorithm prf,
        unsigned int rounds,
        uint8_t *derivedKey, size_t derivedKeyLen
    ); // returns 0 on success
""")
common_key_derivation = ffi.verify(
    "#include <CommonCrypto/CommonKeyDerivation.h>"
)


def _pbkdf2(password, salt, rounds, hash_length, method="hmac-sha1"):
    if method not in METHODS:
        raise NotImplementedError("%s is not a supported method" % method)
    hash = ffi.new("uint8_t []", hash_length)
    with _COMMONCRYPTO_LOCK:
        result = common_key_derivation.CCKeyDerivationPBKDF(
            kCCPBKDF2,
            password, len(password),
            ffi.new("const uint8_t []", salt), len(salt),
            METHODS[method],
            rounds,
            hash,
            hash_length
        )
    if result != 0:
        raise RuntimeError("something went wrong")
    return b"".join(ffi.buffer(hash)).encode("hex")
