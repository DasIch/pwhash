# coding: utf-8
"""
    pwhash.tests.test_algorithms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash.algorithms import pbkdf2, PBKDF2_METHODS, USING
from pwhash.tests.utils import PBKDF2_TEST_VECTORS

import pytest


def test_pbkdf2():
    for password, salt, rounds, hash_length, expected_hashes in PBKDF2_TEST_VECTORS:
        for method, expected_hash in expected_hashes.iteritems():
            if USING == "openssl" and method == "hmac-sha256":
                pytest.xfail("openssl issue?")
            try:
                hash = pbkdf2(
                    password, salt, rounds, hash_length, method
                ).encode("hex")
                assert hash == expected_hash
            except NotImplementedError:
                assert method not in PBKDF2_METHODS

    with pytest.raises(ValueError):
        pbkdf2(b"password", b"salt", 0, 20)

    with pytest.raises(ValueError):
        pbkdf2(b"password", b"salt", 1, 0)
