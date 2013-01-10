# coding: utf-8
"""
    pwhash.tests.test_openssl
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2012 by Daniel Neuhäuser
    :license: BSD
"""
from pwhash.openssl import pbkdf2

from pwhash.tests.utils import TEST_VECTORS


def test_pbkdf2():
    for password, salt, rounds, hash_length, expected_hash in TEST_VECTORS:
        hash = pbkdf2(password, salt, rounds, hash_length, method="hmac-sha1")
        assert hash == expected_hash
