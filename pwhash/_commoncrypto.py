# coding: utf-8
"""
    pwhash._commoncrypto
    ~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import math
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

    unsigned int CCCalibratePBKDF(
        CCPBKDFAlgorithm algorithm,
        size_t passwordLen,
        size_t saltLen,
        CCPseudoRandomAlgorithm prf,
        size_t derivedKeyLen,
        uint32_t msec
    );
""")
common_key_derivation = ffi.verify(
    "#include <CommonCrypto/CommonKeyDerivation.h>"
)


def get_prf(method):
    if method not in METHODS:
        raise NotImplementedError("%s is not a supported method" % method)
    return METHODS[method]


def _pbkdf2(password, salt, rounds, hash_length, method="hmac-sha1"):
    hash = ffi.new("uint8_t []", hash_length)
    with _COMMONCRYPTO_LOCK:
        result = common_key_derivation.CCKeyDerivationPBKDF(
            kCCPBKDF2,
            password, len(password),
            ffi.new("const uint8_t []", salt), len(salt),
            get_prf(method),
            rounds,
            hash,
            hash_length
        )
    if result != 0:
        raise RuntimeError("something went wrong")
    return b"".join(ffi.buffer(hash))


def determine_pbkdf2_rounds(password_length, salt_length, hash_length, method,
                             duration):
    for argument, name in [
        (password_length, "password_length"),
        (salt_length, "salt_length"),
        (hash_length, "hash_length")
        ]:
        if not isinstance(argument, int):
            raise TypeError("%s must be an int, got %r" % argument.__class__)
    duration = int(math.ceil(duration * 1000))
    with _COMMONCRYPTO_LOCK:
        return common_key_derivation.CCCalibratePBKDF(
            kCCPBKDF2,
            password_length,
            salt_length,
            get_prf(method),
            hash_length,
            duration
        )
