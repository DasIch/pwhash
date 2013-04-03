# coding: utf-8
"""
    pwhash.tests.test_commoncrypto
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import sys
from binascii import hexlify

import pytest

if sys.platform != "darwin":
    pytest.skip()

from pwhash import _commoncrypto
from pwhash.tests.utils import PBKDF2_TEST_VECTORS


@pytest.mark.parametrize(("password", "salt", "rounds", "hash_length", "expected_hashes"), PBKDF2_TEST_VECTORS)
def test_pbkdf2(password, salt, rounds, hash_length, expected_hashes, run_fast):
    if rounds > 100000 and run_fast:
        pytest.skip(u"too slow for --fast")
    for method, expected_hash in expected_hashes.items():
        try:
            hash = hexlify(_commoncrypto._pbkdf2(
                password, salt, rounds, hash_length, method
            ))
            assert hash == expected_hash
        except NotImplementedError:
            assert method not in _commoncrypto.METHODS


def test_determine_pbkdf2_rounds():
    for method in _commoncrypto.METHODS:
        assert _commoncrypto.determine_pbkdf2_rounds(1, 1, 1, method, 1) >= 1

        for arguments in [
            (1.0, 1, 1, method, 1),
            (1, 1.0, 1, method, 1),
            (1, 1, 1.0, method, 1)
            ]:
            with pytest.raises(TypeError):
                _commoncrypto.determine_pbkdf2_rounds(*arguments)
