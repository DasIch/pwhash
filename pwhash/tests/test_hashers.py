# coding: utf-8
"""
    pwhash.tests.test_hashers
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash.hashers import PBKDF2Hasher, PlainHasher


def test_pbkdf2_hasher():
    hasher = PBKDF2Hasher(1)
    assert hasher.create(b"password") != hasher.create(b"password")

    hash = hasher.create(b"password")
    assert hasher.verify(b"password", hash)
    assert not hasher.verify(b"other-password", hash)

    upgraded = PBKDF2Hasher(2)
    assert hasher.upgrade(b"password", hash) is None
    assert upgraded.upgrade(b"password", hash) is not None

    assert hasher.verify_and_upgrade(b"password", hash) == (True, None)
    assert hasher.verify_and_upgrade(b"other-password", hash) == (False, None)
    verified, new_hash = upgraded.verify_and_upgrade(b"password", hash)
    assert verified
    assert new_hash is not None

    hash = upgraded.create(b"password")
    assert hasher.verify(b"password", hash)
    assert hasher.upgrade(b"password", hash) is None
    assert hasher.verify_and_upgrade(b"password", hash) == (True, None)


def test_plain_hasher():
    hasher = PlainHasher()

    hash = hasher.create(b"password")

    assert hasher.verify(b"password", hash)
    assert not hasher.verify(b"other-password", hash)

    assert hasher.verify_and_upgrade(b"password", hash) == (True, None)
    assert hasher.verify_and_upgrade(b"other-password", hash) == (False, None)
