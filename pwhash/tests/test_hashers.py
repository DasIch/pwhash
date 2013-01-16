# coding: utf-8
"""
    pwhash.tests.test_hashers
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash.hashers import (
    PBKDF2Hasher, PlainHasher, Context, MD5Hasher, SHA1Hasher, SHA224Hasher,
    SHA256Hasher, SHA384Hasher, SHA512Hasher, HMACMD5, HMACSHA1, HMACSHA224,
    HMACSHA256, HMACSHA384, HMACSHA512, SaltedMD5Hasher, SaltedSHA1Hasher,
    SaltedSHA224Hasher, SaltedSHA256Hasher, SaltedSHA384Hasher,
    SaltedSHA512Hasher, ALL_HASHERS
)

import pytest


def test_pbkdf2_hasher():
    hasher = PBKDF2Hasher(1)
    assert hasher.create(b"password") != hasher.create(b"password")

    hash = hasher.create(b"password")
    assert hasher.verify(b"password", hash)
    assert not hasher.verify(b"other-password", hash)

    with pytest.raises(ValueError):
        hasher.verify(b"password", b"something")

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

    with pytest.raises(ValueError):
        hasher.verify(b"password", b"something")


def test_context():
    plain_hasher = PlainHasher()
    context = Context([plain_hasher])
    assert context.preferred_hasher is plain_hasher
    hash = context.create(b"password")
    assert context.verify(b"password", hash)
    assert context.verify_and_upgrade(b"password", hash) == (True, None)

    pbkdf2_hasher = PBKDF2Hasher(1)
    upgraded = Context([pbkdf2_hasher, plain_hasher])
    assert upgraded.preferred_hasher is pbkdf2_hasher
    assert upgraded.verify(b"password", hash)
    assert upgraded.upgrade(b"password", hash).startswith("pbkdf2")
    verified, hash = upgraded.verify_and_upgrade(b"password", hash)
    assert verified
    assert hash.startswith("pbkdf2")

    upgraded2 = Context([PBKDF2Hasher(2), plain_hasher])
    assert upgraded2.verify(b"password", hash)
    assert upgraded2.upgrade(b"password", hash) is not None
    verified, hash = upgraded2.verify_and_upgrade(b"password", hash)
    assert verified
    assert hash is not None

    config = {
        "pbkdf2": {
            "rounds": 1,
            "method": "hmac-sha1",
            "salt_length": 16
        }
    }
    for name, hasher, in ALL_HASHERS.iteritems():
        if name.startswith("hmac") or name.startswith("salted"):
            config[name] = {"salt_length": 16}
    context = Context.from_config(config)
    hash = context.create(b"password")
    assert context.verify(b"password", hash)


@pytest.mark.parametrize("hasher_cls", [
    MD5Hasher, SHA1Hasher, SHA224Hasher, SHA256Hasher, SHA384Hasher,
    SHA512Hasher
])
def test_digest_hashers(hasher_cls):
    hasher = hasher_cls()
    hash = hasher.create(b"password")
    assert hasher.verify(b"password", hash)
    assert not hasher.verify(b"other-password", hash)
    with pytest.raises(ValueError):
        hasher.verify(b"password", b"something")


@pytest.mark.parametrize("hasher_cls", [
    SaltedMD5Hasher, SaltedSHA1Hasher, SaltedSHA224Hasher, SaltedSHA256Hasher,
    SaltedSHA384Hasher, SaltedSHA512Hasher, HMACMD5, HMACSHA1, HMACSHA224,
    HMACSHA256, HMACSHA384, HMACSHA512
])
def test_salting_hashers(hasher_cls):
    hasher = hasher_cls(salt_length=1)
    hash = hasher.create(b"password")
    assert hasher.verify(b"password", hash)
    assert not hasher.verify(b"other-password", hash)
    with pytest.raises(ValueError):
        hasher.verify(b"password", b"something")
    assert hasher.upgrade(b"password", hash) is None
    verified, new_hash = hasher.verify_and_upgrade(b"password", hash)
    assert verified
    assert new_hash is None

    upgraded = hasher_cls(salt_length=2)
    assert upgraded.verify(b"password", hash)
    assert upgraded.upgrade(b"password", hash) is not None
    verified, new_hash = upgraded.verify_and_upgrade(b"password", hash)
    assert verified
    assert new_hash is not None
