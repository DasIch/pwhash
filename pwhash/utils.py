# coding: utf-8
"""
    pwhash.utils
    ~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import sys
import time
import math
from functools import partial

from cffi import FFI

from pwhash.algorithms import pbkdf2


PACKAGE_PATH = os.path.abspath(os.path.dirname(__file__))


if sys.platform == "darwin":
    from pwhash._commoncrypto import determine_pbkdf2_rounds
else:
    def determine_pbkdf2_rounds(password_length, salt_length, hash_length,
                                method, duration):
        # Pure Python implementation based on the CommonCrypto code found at:
        # http://opensource.apple.com/source/CommonCrypto/CommonCrypto-55010/Source/API/CommonKeyDerivation.c
        #
        # TODO: `time.clock()` is not necessarily very precise, it is the most
        #       precise clock available with 2.x though. I haven't looked into
        #       whether this might be an issue on some platforms and I haven't
        #       written bindings for higher precision clocks because the APIs
        #       are different on each platform. However if precision is an
        #       issue this might need to be done.
        round_measure = 10000
        # We use random "passwords" and "salts" to prevent the interpreter from
        # performing optimizations that mess with the timings.
        arguments = [
            (os.urandom(password_length), os.urandom(salt_length))
            for _ in range(5)
        ]
        for password, salt in arguments:
            start = time.clock()
            pbkdf2(password, salt, round_measure, hash_length, method)
            end = time.clock()
            elapsed = (end - start)
            if elapsed >= 0:
                return int(math.ceil(duration * round_measure / elapsed))
        raise RuntimeError("measurement failed")

determine_pbkdf2_rounds.__doc__ = """
    Determines how many rounds are needed for hashing to take approximately
    `duration` seconds.

    :param password_length:
        Should be the lowest allowed password length. Note that longer
        passwords take more time, take this into account when specifying the
        allowed range.
    :param salt_length: The length of the used salt in bytes.
    :param hash_length: The length of the used hash in bytes.
    :param method: The method to be used.
    :param duration:
        The amount of time that is acceptable for password hashing in seconds.
        You probably want this to be between 0.1 to 0.5 seconds.

    This works by benchmarking :func`pwhash.algorithms.pbkdf2`, so this is
    something you want to perform only once for every machine when it's idle,
    with every update of pwhash, OpenSSL or CommonCrypto and with every method
    change and obviously parameter change. If you are re-determining the number
    of rounds be careful to check that the result is not lower than the number
    of rounds you have been using so far, unless that is to be expected due to
    downgrades.
"""


ffi = FFI()
ffi.cdef("""
    int timingsafe_bcmp(const void *b1, const void *b2, size_t n);
""")
_timingsafe_bcmp = ffi.verify(
    """
        #include <timingsafe_bcmp.h>
    """,
    sources=[os.path.join(PACKAGE_PATH, "timingsafe_bcmp.c")],
    include_dirs=[PACKAGE_PATH],
    ext_packages="pwhash"
)


def constant_time_equal(a, b):
    """
    Compares two byte strings `a` and `b` for equality in time proportional to
    the length of the shortest string.

    This should be used to compare an untrusted string with a string whose
    contents must not be exposed.
    """
    if len(a) != len(b):
        return False
    return _timingsafe_bcmp.timingsafe_bcmp(a, b, len(a)) == 0


class classproperty(property):
    def __get__(self, instance, cls):
        return self.fget(cls)
    # __set__ and __delete__ can only be implemented with metaclasses if at all
