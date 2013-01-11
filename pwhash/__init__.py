# coding: utf-8
"""
    pwhash
    ~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD
"""
import sys


if sys.platform == "darwin":
    from pwhash.commoncrypto import _pbkdf2
else:
    from pwhash.openssl import _pbkdf2


def pbkdf2(password, salt, rounds, hash_length, method="hmac-sha1"):
    if not (rounds >= 1):
        raise ValueError("rounds has to be >= 1, is %d" % rounds)
    if not (hash_length >= 1):
        raise ValueError("hash_length has to be >= 1, is %d" % hash_length)
    return _pbkdf2(password, salt, rounds, hash_length, method)
