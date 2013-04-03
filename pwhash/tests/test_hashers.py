# coding: utf-8
"""
    pwhash.tests.test_hashers
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os

from pwhash import PasswordHasher
from pwhash.hashers import (
    BCryptHasher, PBKDF2Hasher, PlainHasher, MD5Hasher, SHA1Hasher,
    SHA224Hasher, SHA256Hasher, SHA384Hasher, SHA512Hasher, HMACMD5Hasher,
    HMACSHA1Hasher, HMACSHA224Hasher, HMACSHA256Hasher, HMACSHA384Hasher,
    HMACSHA512Hasher, SaltedMD5Hasher, SaltedSHA1Hasher, SaltedSHA224Hasher,
    SaltedSHA256Hasher, SaltedSHA384Hasher, SaltedSHA512Hasher, ALL_HASHERS,
    ConfigWarning
)
from pwhash.utils import _import_bcrypt

bcrypt = _import_bcrypt()
import pytest


class HasherTestBase(object):
    @pytest.fixture(params=[u"password", b"password", "password"])
    def password(self, request):
        return request.param

    @pytest.fixture(params=[u"other-password", b"other-password",
                            "other-password"])
    def other_password(self, request):
        return request.param

    def test_verify(self, hasher, password, other_password):
        hash = hasher.create(password)
        assert hasher.verify(password, hash)
        assert not hasher.verify(other_password, hash)

        with pytest.raises(ValueError):
            hasher.verify(password, b"invalid-hash")

    def test_max_hash_length(self, hasher, password):
        assert hasher.max_hash_length >= 0
        assert len(hasher.create(password)) <= hasher.max_hash_length

    def test_min_hash_length(self, hasher, password):
        assert hasher.min_hash_length >= 0
        assert len(hasher.create(password)) >= hasher.min_hash_length


class UpgradableTestMixin(object):
    def test_upgrade(self, hasher, upgraded, password):
        hash = hasher.create(password)
        assert hasher.upgrade(password, hash) is None
        assert upgraded.upgrade(password, hash) is not None

    def test_verify_and_upgrade(self, hasher, upgraded, password, other_password):
        hash = hasher.create(password)

        assert hasher.verify_and_upgrade(password, hash) == (True, None)
        assert hasher.verify_and_upgrade(other_password, hash) == (False, None)

        verify, new_hash = upgraded.verify_and_upgrade(password, hash)
        assert verify
        assert new_hash is not None
        verify, new_hash = upgraded.verify_and_upgrade(other_password, hash)
        assert not verify
        assert new_hash is None


class SaltingTestMixin(object):
    def test_inequality(self, hasher, password):
        # salts should be unique, making the hash derived also unique and
        # therefore all hashes we create with one password unequal
        assert hasher.create(password) != hasher.create(password)


class TestPlainHasher(HasherTestBase):
    @pytest.fixture
    def hasher(self):
        return PlainHasher()

    def test_max_hash_length(self, hasher):
        assert hasher.max_hash_length is None


class TestDigestHashers(HasherTestBase):
    @pytest.fixture(params=[MD5Hasher, SHA1Hasher, SHA224Hasher, SHA256Hasher,
                            SHA384Hasher, SHA512Hasher])
    def hasher(self, request):
        return request.param()


class TestSaltingDigestHashers(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    hashers = [
        SaltedMD5Hasher, SaltedSHA1Hasher, SaltedSHA224Hasher,
        SaltedSHA256Hasher, SaltedSHA384Hasher, SaltedSHA512Hasher,
        HMACMD5Hasher, HMACSHA1Hasher, HMACSHA224Hasher, HMACSHA256Hasher,
        HMACSHA384Hasher, HMACSHA512Hasher
    ]

    @pytest.fixture(params=hashers)
    def hasher_cls(self, request):
        return request.param

    @pytest.fixture
    def hasher(self, hasher_cls):
        return hasher_cls(salt_length=10)

    @pytest.fixture
    def upgraded(self, hasher_cls):
        return hasher_cls(salt_length=11)


class TestPBKDF2Hasher(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    @pytest.fixture(params=["rounds", "method", "salt_length"])
    def argument(self, request):
        return request.param

    @pytest.fixture
    def hasher(self, argument):
        kwargs = {"rounds": 1}
        kwargs[argument] = {
            "rounds": 1,
            "method": "hmac-sha1",
            "salt_length": 10
        }[argument]
        return PBKDF2Hasher(**kwargs)

    @pytest.fixture
    def upgraded(self, argument):
        kwargs = {"rounds": 1}
        kwargs[argument] = {
            "rounds": 2,
            "method": "hmac-sha256",
            "salt_length": 11
        }[argument]
        return PBKDF2Hasher(**kwargs)


class TestBCryptHasher(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    @pytest.fixture
    def hasher(self):
        if bcrypt is None:
            pytest.skip(u"bcrypt not installed")
        return BCryptHasher(cost=1)

    @pytest.fixture
    def upgraded(self):
        if bcrypt is None:
            pytest.skip(u"bcrypt not installed")
        return BCryptHasher(cost=2)

    @pytest.mark.skipif("bcrypt is not None")
    def test_init(self):
        with pytest.raises(RuntimeError):
            BCryptHasher(cost=1)


class TestPasswordHasher(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    @pytest.fixture
    def hasher(self):
        return PasswordHasher([SaltedMD5Hasher(salt_length=10)])

    @pytest.fixture(params=["internal", "external"])
    def upgraded(self, request):
        if request.param == "internal":
            return PasswordHasher([SaltedMD5Hasher(salt_length=11)])
        elif request.param == "external":
            return PasswordHasher(
                [HMACMD5Hasher(), SaltedMD5Hasher(salt_length=10)]
            )

    def test_min_hash_length(self, hasher):
        assert hasher.min_hash_length >= hasher.min_password_length

    def test_from_config(self, recwarn):
        config = {
            "application": {
                "min_password_length": 8,
            },
            "hashers": {
                "pbkdf2": {
                    "rounds": 1,
                    "method": "hmac-sha1",
                    "salt_length": 16
                },
                "bcrypt": {
                    "cost": 12
                },
            }
        }
        for name, hasher, in ALL_HASHERS.items():
            if name.startswith("hmac") or name.startswith("salted"):
                config[name] = {"salt_length": 16}
        pw_hasher = PasswordHasher.from_config(config)
        hash = pw_hasher.create(b"password")
        assert pw_hasher.verify(b"password", hash)
        assert not recwarn.list

        pw_hasher = PasswordHasher.from_config({
            "application": {"min_password_length": 8},
            "hashers": {}
        })
        if bcrypt is not None:
            warning = recwarn.pop(ConfigWarning)
            assert "bcrypt" in str(warning.message)
        warning = recwarn.pop(ConfigWarning)
        assert "pbkdf2" in str(warning.message)
        assert not recwarn.list

    @pytest.mark.parametrize(("path", "importable"), [
        ("pwhashc.json", __name__),
        (
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)),
                "pwhashc.json"
             ),
             None
        )
    ])
    def test_from_config_file(self, recwarn, path, importable):
        hasher = PasswordHasher.from_config_file(
            path,
            relative_to_importable=importable
        )
        assert not recwarn.list # no warnings issued

        # test basic functionality
        assert hasher.verify(
            u"long-password",
            hasher.create(u"long-password")
        )

        # test that min_password_length from config is passed to
        # PasswordHasher()
        with pytest.raises(ValueError):
            hasher.create(u"password")

    def test_create_min_password_length(self, hasher):
        with pytest.raises(ValueError):
            hasher.create(u"foobar") # < min_password_length=8
