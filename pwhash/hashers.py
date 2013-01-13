# coding: utf-8
"""
    pwhash.hashers
    ~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import hmac
import hashlib
from collections import OrderedDict, namedtuple

from pwhash.algorithms import pbkdf2
from pwhash.utils import constant_time_equal


DIGEST_SIZES = {
    "hmac-sha1": 20,
    "hmac-sha224": 28,
    "hmac-sha256": 32,
    "hmac-sha384": 48,
    "hmac-sha512": 64
}

DEFAULT_SALT_LENGTH = 16 # 128 bit


def generate_salt(salt_length):
    return os.urandom(salt_length)


class Hasher(object):
    def parse(self, hash):
        raise NotImplementedError()

    def create(self, password):
        raise NotImplementedError()

    def verify(self, password, known_hash):
        raise NotImplementedError()


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


class ParameterlessHasherMixin(object):
    def verify(self, password, hash):
        return constant_time_equal(
            self.parse(self.create(password)),
            self.parse(hash)
        )


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
        return _PBKDF2Hash(method, int(rounds), salt.decode("hex"), hash)

    def create(self, password):
        salt = generate_salt(self.salt_length)
        hash = pbkdf2(password, salt, self.rounds, self.hash_length, self.method)
        hexed = salt.encode("hex")
        return b"$".join(
            [self.name, self.method, bytes(self.rounds), salt.encode("hex"), hash]
        )

    def verify(self, password, known_hash):
        parsed = self.parse(known_hash)
        hexed = parsed.salt.encode("hex")
        hash = pbkdf2(
            password,
            parsed.salt,
            parsed.rounds,
            len(parsed.hash.decode("hex")),
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


class PlainHasher(ParameterlessHasherMixin, NamedHasher):
    name = b"plain"

    def create(self, password):
        return self.name + b"$" + password


class DigestHasher(ParameterlessHasherMixin, NamedHasher):
    digest = None

    def create(self, password):
        return b"$".join([
            self.name,
            self.digest(password).hexdigest()
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
        hash = self.digest(salt + password).hexdigest()
        return b"$".join([
            self.name,
            salt.encode("hex"),
            hash
        ])

    def parse(self, hash):
        hash = NamedHasher.parse(self, hash)
        salt, hash = hash.split("$", 2)
        return _SaltedDigestHash(salt.decode("hex"), hash)

    def verify(self, password, known_hash):
        parsed = self.parse(known_hash)
        hash = self.digest(parsed.salt + password).hexdigest()
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, known_hash):
        parsed = self.parse(known_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class SaltedMD5Hasher(SaltedDigestHasher):
    name = "salted-md5"
    digest = hashlib.md5


class SaltedSHA1Hasher(SaltedDigestHasher):
    name = "salted-sha1"
    digest = hashlib.sha1


class SaltedSHA224Hasher(SaltedDigestHasher):
    name = "salted-sha224"
    digest = hashlib.sha224


class SaltedSHA256Hasher(SaltedDigestHasher):
    name = "salted-sha256"
    digest = hashlib.sha256


class SaltedSHA384Hasher(SaltedDigestHasher):
    name = "salted-sha384"
    digest = hashlib.sha384


class SaltedSHA512Hasher(SaltedDigestHasher):
    name = "salted-sha512"
    digest = hashlib.sha512


_HMACHash = namedtuple("_HMACHash", ["salt", "hash"])


class HMACHasher(UpgradeableHasherMixin, NamedHasher):
    digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def create(self, password):
        salt = generate_salt(self.salt_length)
        hash = hmac.new(salt, password, self.digest).hexdigest()
        return b"$".join([
            self.name,
            salt.encode("hex"),
            hash
        ])

    def parse(self, hash):
        salt, hash = NamedHasher.parse(self, hash).split("$", 1)
        return _HMACHash(salt.decode("hex"), hash)

    def verify(self, password, known_hash):
        parsed = self.parse(known_hash)
        hash = hmac.new(parsed.salt, password, self.digest).hexdigest()
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, known_hash):
        parsed = self.parse(known_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class HMACMD5(HMACHasher):
    name = "hmac-md5"
    digest = hashlib.md5


class HMACSHA1(HMACHasher):
    name = "hmac-sha1"
    digest = hashlib.sha1


class HMACSHA224(HMACHasher):
    name = "hmac-sha224"
    digest = hashlib.sha224


class HMACSHA256(HMACHasher):
    name = "hmac-sha256"
    digest = hashlib.sha256


class HMACSHA384(HMACHasher):
    name = "hmac-sha384"
    digest = hashlib.sha384


class HMACSHA512(HMACHasher):
    name = "hmac-sha512"
    digest = hashlib.sha512


DEFAULT_HASHERS = [
    PBKDF2Hasher,
    HMACSHA512, HMACSHA384, HMACSHA256, HMACSHA224, HMACSHA1,
    HMACMD5,
    SaltedSHA512Hasher, SaltedSHA384Hasher, SaltedSHA256Hasher,
    SaltedSHA224Hasher, SaltedSHA1Hasher,
    SaltedMD5Hasher,
    SHA512Hasher, SHA384Hasher, SHA256Hasher, SHA224Hasher, SHA1Hasher,
    MD5Hasher,
    PlainHasher
]


class Context(UpgradeableHasher):
    def __init__(self, hashers):
        self.hashers = {hasher.name: hasher for hasher in hashers}

    @property
    def preferred_hasher(self):
        return self.hashers.itervalues().next()

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
