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
import random
import pkgutil
import warnings

from cffi import FFI
import pkg_resources

from pwhash.algorithms import pbkdf2


try:
    raw_input = raw_input # assignment is necessary to make it importable
except NameError: # Python 3.x
    raw_input = input


try:
    text_type = unicode
except NameError: # Python 3.x
    text_type = str


def _generate_password(length):
    return u"".join(
        random.sample(u"abcdefghijklmnopqrstuvwxyz", length)
    ).encode("ascii")



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
            (_generate_password(password_length), os.urandom(salt_length))
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

    This works by benchmarking :func:`pwhash.algorithms.pbkdf2`, so this is
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
_timingsafe_bcmp = ffi.verify("""
    /*	$OpenBSD: timingsafe_bcmp.c,v 1.1 2010/09/24 13:33:00 matthew Exp $	*/
    /*
     * Copyright (c) 2010 Damien Miller.  All rights reserved.
     *
     * Permission to use, copy, modify, and distribute this software for any
     * purpose with or without fee is hereby granted, provided that the above
     * copyright notice and this permission notice appear in all copies.
     *
     * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
     * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
     * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
     * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
     * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
     * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
     * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
     */

    #ifndef _TIMINGSAFE_BCMP_H
    #define _TIMINGSAFE_BCMP_H

    #include <stdlib.h>

    int
    timingsafe_bcmp(const void *b1, const void *b2, size_t n)
    {
        const unsigned char *p1 = b1, *p2 = b2;
        int ret = 0;

        for (; n > 0; n--)
            ret |= *p1++ ^ *p2++;
        return (ret != 0);
    }

    #endif
    """,
    ext_package="pwhash"
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
    return _timingsafe_bcmp.timingsafe_bcmp(
        ffi.new("char[]", a),
        ffi.new("char[]", b),
        len(a)
    ) == 0


class classproperty(property):
    def __get__(self, instance, cls):
        return self.fget(cls)
    # __set__ and __delete__ can only be implemented with metaclasses if at all


def _import_bcrypt():
    try:
        import bcrypt
    except ImportError:
        return None
    bcrypt_version = pkg_resources.get_distribution("py-bcrypt").version
    if bcrypt_version.split(".") < ["0", "3"]:
        warnings.warn("insecure py-bcrypt <= 0.2 installed; upgrade!")
    else:
        return bcrypt


bcrypt = _import_bcrypt()


def determine_bcrypt_cost(password_length, duration):
    """
    Determines the cost needed for hashing to take approximately `duration`
    seconds.

    The same caveats as for :func:`determine_pbkdf2_rounds` apply.
    """
    if bcrypt is None:
        raise RuntimeError("requires py-bcrypt >= 0.3")
    round_measure = previous_round_measure = 12
    while True:
        start = time.clock()
        bcrypt.hashpw(
            _generate_password(password_length),
            bcrypt.gensalt(round_measure)
        )
        end = time.clock()
        elapsed = end - start
        if elapsed < duration:
            if previous_round_measure > round_measure:
                round_measure += 1 # rounding up...
                break
            previous_round_measure = round_measure
            round_measure += 1
        else:
            if previous_round_measure < round_measure:
                break
            previous_round_measure = round_measure
            round_measure -= 1
    return round_measure


def get_root_path(import_name):
    """
    Returns the path of the package or the directory in which the module is
    contained that `import_name` refers to. If the path cannot be determined
    `None` is returned.

    If the module or package with the name defined by `import_name` cannot be
    imported an :exc:`ImportError` may be raised.
    """
    filepath = None

    # If it's imported and has a __file__ attribute use that.
    module = sys.modules.get(import_name)
    if module is not None and hasattr(module, "__file__"):
        filepath = module.__file__

    # Attempt to get the path from responsible loader.
    if filepath is None:
        loader = pkgutil.get_loader(import_name)
        if loader is not None:
            filepath = loader.get_filename(import_name)

    # Let's try to import it.
    if filepath is None:
        __import__(import_name)
        filepath = sys.modules[import_name].__file__

    if filepath is not None:
        return os.path.dirname(os.path.abspath(filepath))


if sys.version_info >= (3, 0):
    def native_to_bytes(native):
        return native.encode("ascii")

    def bytes_to_native(bytes):
        return bytes.decode("ascii")
else:
    def native_to_bytes(native):
        return native

    def bytes_to_native(bytes):
        return bytes


def int_to_bytes(n):
    """
    Safely turns an integer into a byte string.

    This is necessary because ``bytes(int)`` yields different results on 2.x
    and 3.x. On 2.x it yields the integer as ascii encoded byte string and on
    3.x it yields an `int` bytes long byte string consisting of null bytes.
    """
    return str(n).encode("ascii")
