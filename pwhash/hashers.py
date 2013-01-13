# coding: utf-8
"""
    pwhash.hashers
    ~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
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
    name = None

    def parse(self, hash):
        raise NotImplementedError()

    def create(self, password):
        raise NotImplementedError()

    def verify(self, password, known_hash):
        raise NotImplementedError()


class UpgradeableHasher(Hasher):
    def upgrade(self, password, known_hash):
        raise NotImplementedError()

    def verify_and_upgrade(self, password, known_hash):
        matches = self.verify(password, known_hash)
        if matches:
            return matches, self.upgrade(password, known_hash)
        return matches, None


_PBKDF2Hash = namedtuple("_PBKDF2Hash", ["method", "rounds", "salt", "hash"])


class PBKDF2Hasher(UpgradeableHasher):
    name = b"pbkdf2"

    def __init__(self, rounds, method="hmac-sha1", salt_length=DEFAULT_SALT_LENGTH):
        self.rounds = rounds
        self.method = method
        self.salt_length = salt_length
        self.hash_length = DIGEST_SIZES[method]

    def parse(self, hash):
        if hash.startswith(self.name):
            hash = hash[len(self.name) + 1:]
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


class PlainHasher(Hasher):
    name = b"plain"

    def parse(self, hash):
        return hash[len(self.name) + 1:] if hash.startswith(self.name) else hash

    def create(self, password):
        return self.name + b"$" + password

    def verify(self, password, known_password):
        return constant_time_equal(password, self.parse(known_password))


DEFAULT_HASHERS = [PBKDF2Hasher, PlainHasher]


class Context(UpgradeableHasher):
    def __init__(self, hashers=None):
        hashers = DEFAULT_HASHERS if hashers is None else hashers
        self.hashers = {hasher.name: hasher for hasher in hashers}

    @property
    def preferred_hasher(self):
        return self.hashers.itervalues().next()

    def create(self, password):
        return self.preferred_hasher.create(password)

    def parse(self, hash):
        name, hash = hash.split(b"$", 1)
        return self.hashers[name], hash

    def verify(self, password, hash):
        hasher, hash = self.parse(hash)
        return hasher.verify(password, hash)

    def upgrade(self, password, hash):
        hasher, hash = self.parse(hash)
        if hasher.name != self.preferred_hasher.name:
            return self.preferred_hasher.create(password)
        elif isinstance(hasher, UpgradeableHasher):
            return hasher.upgrade(password, hash)
