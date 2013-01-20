# coding: utf-8
"""
    pwhash.tests.test_openssl
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash import _openssl
from pwhash.tests.utils import PBKDF2_TEST_VECTORS

import pytest


def test_pbkdf2():
    for password, salt, rounds, hash_length, expected_hashes in PBKDF2_TEST_VECTORS:
        for method, expected_hash in expected_hashes.iteritems():
            if method == "hmac-sha256":
                pytest.xfail("openssl issue?")
            try:
                hash = _openssl._pbkdf2(
                    password, salt, rounds, hash_length, method
                ).encode("hex")
                assert hash == expected_hash
            except NotImplementedError:
                assert method not in _openssl.METHODS
