# coding: utf-8
"""
    pwhash.hashers
    ~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import hmac
import json
import inspect
import hashlib
import warnings
from binascii import hexlify, unhexlify
from collections import OrderedDict, namedtuple

from pwhash.algorithms import pbkdf2
from pwhash.utils import constant_time_equal, classproperty


DIGEST_SIZES = {
    "hmac-sha1": 20,
    "hmac-sha224": 28,
    "hmac-sha256": 32,
    "hmac-sha384": 48,
    "hmac-sha512": 64
}

#: The recommended minimum salt length as specified in the `NIST Special
#: Publication 800-132`_, published in December of 2010.
#:
#: .. _NIST Special Publication 800-132: http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
RECOMMENDED_MIN_SALT_LENGTH = 16 # 128 bit

#: The default salt length we are using. Due to the fact that the latest NIST
#: recommendation is more than 3 years old, we use twice the (minimum)
#: recommended length.
DEFAULT_SALT_LENGTH = RECOMMENDED_MIN_SALT_LENGTH * 2


def generate_salt(salt_length):
    return os.urandom(salt_length)


class Hasher(object):
    @classproperty
    def requires_config(cls):
        if cls.__init__ is object.__init__:
            return False
        argspec = inspect.getargspec(cls.__init__)
        arguments = argspec.args[1:-len(argspec.defaults)]
        return bool(arguments)

    def parse(self, hash):
        raise NotImplementedError()

    def create(self, password):
        raise NotImplementedError()

    def verify(self, password, hash):
        return constant_time_equal(
            self.parse(self.create(password)),
            self.parse(hash)
        )


class UpgradeableHasherMixin(object):
    def upgrade(self, password, known_hash):
        raise NotImplementedError()

    def verify_and_upgrade(self, password, known_hash):
        matches = self.verify(password, known_hash)
        if matches:
            return matches, self.upgrade(password, known_hash)
        return matches, None


class NamedHasherMixin(object):
    name = None

    def parse(self, hash):
        if not b"$" in hash:
            raise ValueError("name missing: %r" % hash)
        name, hash = hash.split(b"$", 1)
        if name != self.name:
            raise ValueError("expected %r hash, got %r" % (self.name, name))
        return hash


class UpgradeableHasher(UpgradeableHasherMixin, Hasher):
    pass


class NamedHasher(NamedHasherMixin, Hasher):
    pass


_PBKDF2Hash = namedtuple("_PBKDF2Hash", ["method", "rounds", "salt", "hash"])


class PBKDF2Hasher(UpgradeableHasherMixin, NamedHasher):
    name = b"pbkdf2"

    def __init__(self, rounds, method="hmac-sha1", salt_length=DEFAULT_SALT_LENGTH):
        self.rounds = rounds
        self.method = method
        self.salt_length = salt_length
        self.hash_length = DIGEST_SIZES[method]

    def parse(self, hash):
        hash = NamedHasher.parse(self, hash)
        method, rounds, salt, hash = hash.split(b"$")
        return _PBKDF2Hash(
            method.decode("ascii"), int(rounds), unhexlify(salt),
            unhexlify(hash)
        )

    def create(self, password):
        salt = generate_salt(self.salt_length)
        hash = hexlify(pbkdf2(
            password, salt, self.rounds, self.hash_length, self.method
        ))
        return b"$".join([
            self.name, self.method.encode("ascii"),
            str(self.rounds).encode("ascii"), hexlify(salt), hash
        ])

    def verify(self, password, known_hash):
        parsed = self.parse(known_hash)
        hash = pbkdf2(
            password,
            parsed.salt,
            parsed.rounds,
            len(parsed.hash),
            parsed.method
        )
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, known_hash):
        parsed = self.parse(known_hash)
        if (self.salt_length > len(parsed.salt) or
            self.rounds > parsed.rounds or
            self.hash_length > len(parsed.hash) or
            DIGEST_SIZES[self.method] > DIGEST_SIZES[parsed.method]
            ):
            return self.create(password)


class PlainHasher(NamedHasher):
    name = b"plain"

    def create(self, password):
        return self.name + b"$" + password


class DigestHasher(NamedHasher):
    digest = None

    def create(self, password):
        return b"$".join([
            self.name,
            hexlify(self.digest(password).digest())
        ])


class MD5Hasher(DigestHasher):
    name = b"md5"
    digest = hashlib.md5


class SHA1Hasher(DigestHasher):
    name = b"sha1"
    digest = hashlib.sha1


class SHA224Hasher(DigestHasher):
    name = b"sha224"
    digest = hashlib.sha224


class SHA256Hasher(DigestHasher):
    name = b"sha256"
    digest = hashlib.sha256


class SHA384Hasher(DigestHasher):
    name = b"sha384"
    digest = hashlib.sha384


class SHA512Hasher(DigestHasher):
    name = b"sha512"
    digest = hashlib.sha512


_SaltedDigestHash = namedtuple("_SaltedDigestHash", ["salt", "hash"])


class SaltedDigestHasher(UpgradeableHasherMixin, NamedHasher):
    digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def create(self, password):
        salt = generate_salt(self.salt_length)
        hash = hexlify(self.digest(salt + password).digest())
        return b"$".join([
            self.name,
            hexlify(salt),
            hash
        ])

    def parse(self, hash):
        hash = NamedHasher.parse(self, hash)
        salt, hash = hash.split(b"$", 2)
        return _SaltedDigestHash(unhexlify(salt), hash)

    def verify(self, password, known_hash):
        parsed = self.parse(known_hash)
        hash = hexlify(self.digest(parsed.salt + password).digest())
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, known_hash):
        parsed = self.parse(known_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class SaltedMD5Hasher(SaltedDigestHasher):
    name = b"salted-md5"
    digest = hashlib.md5


class SaltedSHA1Hasher(SaltedDigestHasher):
    name = b"salted-sha1"
    digest = hashlib.sha1


class SaltedSHA224Hasher(SaltedDigestHasher):
    name = b"salted-sha224"
    digest = hashlib.sha224


class SaltedSHA256Hasher(SaltedDigestHasher):
    name = b"salted-sha256"
    digest = hashlib.sha256


class SaltedSHA384Hasher(SaltedDigestHasher):
    name = b"salted-sha384"
    digest = hashlib.sha384


class SaltedSHA512Hasher(SaltedDigestHasher):
    name = b"salted-sha512"
    digest = hashlib.sha512


_HMACHash = namedtuple("_HMACHash", ["salt", "hash"])


class HMACHasher(UpgradeableHasherMixin, NamedHasher):
    digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def create(self, password):
        salt = generate_salt(self.salt_length)
        hash = hexlify(hmac.new(salt, password, self.digest).digest())
        return b"$".join([
            self.name,
            hexlify(salt),
            hash
        ])

    def parse(self, hash):
        salt, hash = NamedHasher.parse(self, hash).split(b"$", 1)
        return _HMACHash(unhexlify(salt), hash)

    def verify(self, password, known_hash):
        parsed = self.parse(known_hash)
        hash = hexlify(hmac.new(parsed.salt, password, self.digest).digest())
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, known_hash):
        parsed = self.parse(known_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class HMACMD5(HMACHasher):
    name = b"hmac-md5"
    digest = hashlib.md5


class HMACSHA1(HMACHasher):
    name = b"hmac-sha1"
    digest = hashlib.sha1


class HMACSHA224(HMACHasher):
    name = b"hmac-sha224"
    digest = hashlib.sha224


class HMACSHA256(HMACHasher):
    name = b"hmac-sha256"
    digest = hashlib.sha256


class HMACSHA384(HMACHasher):
    name = b"hmac-sha384"
    digest = hashlib.sha384


class HMACSHA512(HMACHasher):
    name = b"hmac-sha512"
    digest = hashlib.sha512


ALL_HASHERS = OrderedDict((hasher.name, hasher) for hasher in [
    PBKDF2Hasher,
    # hmac
    HMACSHA512, HMACSHA384, HMACSHA256, HMACSHA224, HMACSHA1,
    HMACMD5,
    # salted digest
    SaltedSHA512Hasher, SaltedSHA384Hasher, SaltedSHA256Hasher,
    SaltedSHA224Hasher, SaltedSHA1Hasher,
    SaltedMD5Hasher,
    # digest
    SHA512Hasher, SHA384Hasher, SHA256Hasher, SHA224Hasher, SHA1Hasher,
    MD5Hasher,
    # plain
    PlainHasher
])


class ConfigWarning(UserWarning):
    pass


class PasswordHasher(UpgradeableHasher):
    default_hasher_classes = ALL_HASHERS

    @classmethod
    def from_config(cls, config):
        hashers = []
        for name, hasher_cls in cls.default_hasher_classes.items():
            hasher_config = config.get(name, {})
            if hasher_cls.requires_config and not hasher_config:
                warnings.warn(
                    "configuration for %r is missing" % name,
                    ConfigWarning
                )
            else:
                hashers.append(hasher_cls(**hasher_config))
        return cls(hashers)

    @classmethod
    def from_config_file(cls, filepath):
        with open(filepath, "rb") as config_file:
            return cls.from_config(json.load(config_file))

    def __init__(self, hashers):
        self.hashers = OrderedDict((hasher.name, hasher) for hasher in hashers)

    @property
    def preferred_hasher(self):
        return next(iter(self.hashers.values()))

    def create(self, password):
        return self.preferred_hasher.create(password)

    def parse(self, hash):
        name = hash.split(b"$", 1)[0]
        return self.hashers[name], hash

    def verify(self, password, hash):
        hasher, hash = self.parse(hash)
        return hasher.verify(password, hash)

    def upgrade(self, password, hash):
        hasher, hash = self.parse(hash)
        if hasher.name != self.preferred_hasher.name:
            return self.preferred_hasher.create(password)
        elif isinstance(hasher, UpgradeableHasherMixin):
            return hasher.upgrade(password, hash)
