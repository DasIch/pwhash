# coding: utf-8
"""
    pwhash.tests.test_algorithms
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from binascii import hexlify

from pwhash.algorithms import pbkdf2, PBKDF2_METHODS, USING
from pwhash.tests.utils import PBKDF2_TEST_VECTORS

import pytest


@pytest.mark.parametrize(("password", "salt", "rounds", "hash_length", "expected_hashes"), PBKDF2_TEST_VECTORS)
def test_pbkdf2(password, salt, rounds, hash_length, expected_hashes, run_fast):
    if rounds > 100000 and run_fast:
        pytest.skip(u"too slow for --fast")
    for method, expected_hash in expected_hashes.items():
        try:
            hash = hexlify(pbkdf2(
                password, salt, rounds, hash_length, method
            ))
            assert hash == expected_hash
        except NotImplementedError:
            assert method not in PBKDF2_METHODS

    with pytest.raises(ValueError):
        pbkdf2(b"password", b"salt", 0, 20)

    with pytest.raises(ValueError):
        pbkdf2(b"password", b"salt", 1, 0)
