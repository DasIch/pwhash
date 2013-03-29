# coding: utf-8
"""
    pwhash.tests.test_hashers
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash import PasswordHasher
from pwhash.hashers import (
    BCryptHasher, PBKDF2Hasher, PlainHasher, MD5Hasher, SHA1Hasher,
    SHA224Hasher, SHA256Hasher, SHA384Hasher, SHA512Hasher, HMACMD5, HMACSHA1,
    HMACSHA224, HMACSHA256, HMACSHA384, HMACSHA512, SaltedMD5Hasher,
    SaltedSHA1Hasher, SaltedSHA224Hasher, SaltedSHA256Hasher,
    SaltedSHA384Hasher, SaltedSHA512Hasher, ALL_HASHERS, ConfigWarning
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
        assert hasher.create(password) != hasher.create(password)


class TestPlainHasher(HasherTestBase):
    @pytest.fixture
    def hasher(self):
        return PlainHasher()


class TestDigestHashers(HasherTestBase):
    @pytest.fixture(params=[MD5Hasher, SHA1Hasher, SHA224Hasher, SHA256Hasher,
                            SHA384Hasher, SHA512Hasher])
    def hasher(self, request):
        return request.param()


class TestSaltingDigestHashers(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    hashers = [
        SaltedMD5Hasher, SaltedSHA1Hasher, SaltedSHA224Hasher,
        SaltedSHA256Hasher, SaltedSHA384Hasher, SaltedSHA512Hasher, HMACMD5,
        HMACSHA1, HMACSHA224, HMACSHA256, HMACSHA384, HMACSHA512
    ]

    @pytest.fixture(params=hashers)
    def hasher_cls(self, request):
        return request.param

    @pytest.fixture
    def hasher(self, hasher_cls):
        return hasher_cls(salt_length=1)

    @pytest.fixture
    def upgraded(self, hasher_cls):
        return hasher_cls(salt_length=2)


class TestPBKDF2Hasher(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    @pytest.fixture
    def hasher(self):
        return PBKDF2Hasher(rounds=1)

    @pytest.fixture
    def upgraded(self):
        return PBKDF2Hasher(rounds=2)

if bcrypt is None:
    def test_bcrypt_hasher():
        with pytest.raises(RuntimeError):
            BCryptHasher(cost=1)
else:
    class TestBCryptHasher(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
        @pytest.fixture
        def hasher(self):
            return BCryptHasher(cost=1)

        @pytest.fixture
        def upgraded(self):
            return BCryptHasher(cost=2)


class TestPasswordHasher(HasherTestBase, SaltingTestMixin, UpgradableTestMixin):
    @pytest.fixture
    def hasher(self):
        return PasswordHasher([SaltedMD5Hasher(salt_length=1)])

    @pytest.fixture(params=["internal", "external"])
    def upgraded(self, request):
        if request.param == "internal":
            return PasswordHasher([SaltedMD5Hasher(salt_length=2)])
        elif request.param == "external":
            return PasswordHasher([HMACMD5(), SaltedMD5Hasher(salt_length=1)])

    def test_from_config(self, recwarn):
        config = {
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

        pw_hasher = PasswordHasher.from_config({"hashers": {}})
        if bcrypt is not None:
            warning = recwarn.pop(ConfigWarning)
            assert "bcrypt" in str(warning.message)
        warning = recwarn.pop(ConfigWarning)
        assert "pbkdf2" in str(warning.message)
        assert not recwarn.list

    def test_from_config_file(self):
        pw_hasher = PasswordHasher.from_config_file(
            "pwhashc.json",
            relative_to_importable=__name__
        )
        assert pw_hasher.verify(u"password", pw_hasher.create(u"password"))
