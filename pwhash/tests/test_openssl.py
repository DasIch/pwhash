# coding: utf-8
"""
    pwhash.tests.test_openssl
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from binascii import hexlify

from pwhash import _openssl
from pwhash.tests.utils import PBKDF2_TEST_VECTORS

import pytest


@pytest.mark.parametrize(("password", "salt", "rounds", "hash_length", "expected_hashes"), PBKDF2_TEST_VECTORS)
def test_pbkdf2(password, salt, rounds, hash_length, expected_hashes, run_fast):
    if rounds > 100000 and run_fast:
        pytest.skip(u"too slow for --fast")
    for method, expected_hash in expected_hashes.items():
        try:
            hash = hexlify(_openssl._pbkdf2(
                password, salt, rounds, hash_length, method
            ))
            assert hash == expected_hash
        except NotImplementedError:
            assert method not in _openssl.METHODS
