# coding: utf-8
"""
    pwhash.tests.test_commoncrypto
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash import commoncrypto

from pwhash.tests.utils import PBKDF2_TEST_VECTORS


def test_pbkdf2():
    for password, salt, rounds, hash_length, expected_hashes in PBKDF2_TEST_VECTORS:
        for method, expected_hash in expected_hashes.iteritems():
            try:
                hash = commoncrypto._pbkdf2(
                    password, salt, rounds, hash_length, method
                )
                assert hash == expected_hash
            except NotImplementedError:
                assert method not in commoncrypto.METHODS
