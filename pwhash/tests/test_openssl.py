# coding: utf-8
"""
    pwhash.tests.test_openssl
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2012 by Daniel Neuhäuser
    :license: BSD
"""
from pwhash import openssl
from pwhash.openssl import pbkdf2

from pwhash.tests.utils import PBKDF2_TEST_VECTORS


def test_pbkdf2():
    for password, salt, rounds, hash_length, expected_hashes in PBKDF2_TEST_VECTORS:
        for method, expected_hash in expected_hashes.iteritems():
            try:
                hash = openssl.pbkdf2(
                    password, salt, rounds, hash_length, method
                )
                assert hash == expected_hash
            except NotImplementedError:
                assert method not in openssl.METHODS
