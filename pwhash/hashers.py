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
from pwhash.utils import constant_time_equal, classproperty, _import_bcrypt

bcrypt = _import_bcrypt()


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
    name = None

    @classproperty
    def requires_config(cls):
        """
        `True` if `__init__` takes any positional arguments and therefore
        configuration is needed.
        """
        if cls.__init__ is object.__init__:
            return False
        argspec = inspect.getargspec(cls.__init__)
        if argspec.defaults is None:
            default_offset = len(argspec.args)
        else:
            default_offset = -len(argspec.defaults)
        arguments = argspec.args[1:default_offset]
        return bool(arguments)

    def parse(self, formatted_hash):
        if not b"$" in formatted_hash:
            raise ValueError("name missing: %r" % formatted_hash)
        name, hash = formatted_hash.split(b"$", 1)
        if name != self.name:
            raise ValueError("expected %r hash, got %r" % (self.name, name))
        return hash

    def create(self, password):
        """
        Returns a hash for `password`.
        """
        raise NotImplementedError()

    def verify(self, password, formatted_hash):
        """
        Returns `True` if `hash` was created using `password`.
        """
        return constant_time_equal(
            self.parse(self.create(password)),
            self.parse(formatted_hash)
        )


class UpgradeableMixin(object):
    def upgrade(self, password, formatted_hash):
        """
        Returns a new hash if there is a better method than what was used for
        `hash`.
        """
        raise NotImplementedError()

    def verify_and_upgrade(self, password, formatted_hash):
        """
        Returns a tuple ``(is_correct_password, new_upgraded_hash)``.
        """
        matches = self.verify(password, formatted_hash)
        if matches:
            return matches, self.upgrade(password, formatted_hash)
        return matches, None


class UpgradeableHasher(UpgradeableMixin, Hasher):
    pass


_BCryptHash = namedtuple("_BCryptHash", ["cost", "hash"])


class BCryptHasher(UpgradeableHasher):
    """
    A hasher that uses bcrypt.
    """
    name = b"bcrypt"

    def __init__(self, cost):
        self.cost = cost

        if bcrypt is None:
            raise RuntimeError("bcrypt unavailable; requires py-bcrypt >= 0.3")

    def parse(self, formatted_hash):
        formatted_hash = UpgradeableHasher.parse(self, formatted_hash)
        cost, hash = formatted_hash.split(b"$", 1)
        return _BCryptHash(int(cost), hash)

    def format(self, context):
        return b"$".join([
            context["name"],
            str(context["cost"]).encode("ascii"),
            context["hash"]
        ])

    def create(self, password):
        return self.format({
            "name": self.name,
            "cost": self.cost,
            "hash": bcrypt.hashpw(password, bcrypt.gensalt(self.cost))
        })

    def verify(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        return constant_time_equal(
            bcrypt.hashpw(password, parsed.hash),
            parsed.hash
        )

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if self.cost > parsed.cost:
            return self.create(password)


_PBKDF2Hash = namedtuple("_PBKDF2Hash", ["method", "rounds", "salt", "hash"])


class PBKDF2Hasher(UpgradeableHasher):
    """
    A hasher that uses PBKDF2.
    """
    name = b"pbkdf2"

    def __init__(self, rounds, method="hmac-sha1", salt_length=DEFAULT_SALT_LENGTH):
        self.rounds = rounds
        self.method = method
        self.salt_length = salt_length
        self.hash_length = DIGEST_SIZES[method]

    def parse(self, formatted_hash):
        formatted_hash = UpgradeableHasher.parse(self, formatted_hash)
        method, rounds, salt, hash = formatted_hash.split(b"$")
        return _PBKDF2Hash(
            method.decode("ascii"), int(rounds), unhexlify(salt),
            unhexlify(hash)
        )

    def create(self, password):
        salt = generate_salt(self.salt_length)
        return self.format({
            "name": self.name,
            "method": self.method,
            "rounds": self.rounds,
            "salt": salt,
            "hash": pbkdf2(
                password, salt, self.rounds, self.hash_length, self.method
            )
        })

    def format(self, context):
        return b"$".join([
            context["name"],
            context["method"].encode("ascii"),
            str(context["rounds"]).encode("ascii"),
            hexlify(context["salt"]),
            hexlify(context["hash"])
        ])

    def verify(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        hash = pbkdf2(
            password,
            parsed.salt,
            parsed.rounds,
            len(parsed.hash),
            parsed.method
        )
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if (self.salt_length > len(parsed.salt) or
            self.rounds > parsed.rounds or
            self.hash_length > len(parsed.hash) or
            DIGEST_SIZES[self.method] > DIGEST_SIZES[parsed.method]
            ):
            return self.create(password)


class PlainHasher(Hasher):
    """
    A hasher that uses a plain password as "hash".
    """
    name = b"plain"

    def create(self, password):
        return self.format({"name": self.name, "hash": password})

    def format(self, context):
        return context["name"] + b"$" + context["hash"]


class DigestHasher(Hasher):
    digest = None

    def create(self, password):
        return self.format(
            {"name": self.name, "hash": self.digest(password).digest()}
        )

    def format(self, context):
        return b"$".join([
            context["name"],
            hexlify(context["hash"])
        ])


class MD5Hasher(DigestHasher):
    """
    A hasher that used MD5.
    """
    name = b"md5"
    digest = hashlib.md5


class SHA1Hasher(DigestHasher):
    """
    A hasher that used SHA1.
    """
    name = b"sha1"
    digest = hashlib.sha1


class SHA224Hasher(DigestHasher):
    """
    A hasher that uses SHA224.
    """
    name = b"sha224"
    digest = hashlib.sha224


class SHA256Hasher(DigestHasher):
    """
    A hasher that uses SHA256.
    """
    name = b"sha256"
    digest = hashlib.sha256


class SHA384Hasher(DigestHasher):
    """
    A hasher that uses SHA384.
    """
    name = b"sha384"
    digest = hashlib.sha384


class SHA512Hasher(DigestHasher):
    """
    A hasher that uses SHA512.
    """
    name = b"sha512"
    digest = hashlib.sha512


_SaltedDigestHash = namedtuple("_SaltedDigestHash", ["salt", "hash"])


class SaltedDigestHasher(UpgradeableHasher):
    digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def create(self, password):
        salt = generate_salt(self.salt_length)
        return self.format({
            "name": self.name,
            "salt": salt,
            "hash": self.digest(salt + password).digest()
        })

    def format(self, context):
        return b"$".join([
            context["name"],
            hexlify(context["salt"]),
            hexlify(context["hash"])
        ])

    def parse(self, formatted_hash):
        formatted_hash = Hasher.parse(self, formatted_hash)
        salt, hash = formatted_hash.split(b"$", 2)
        return _SaltedDigestHash(unhexlify(salt), hash)

    def verify(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        hash = hexlify(self.digest(parsed.salt + password).digest())
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class SaltedMD5Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and MD5.
    """
    name = b"salted-md5"
    digest = hashlib.md5


class SaltedSHA1Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA1.
    """
    name = b"salted-sha1"
    digest = hashlib.sha1


class SaltedSHA224Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA224.
    """
    name = b"salted-sha224"
    digest = hashlib.sha224


class SaltedSHA256Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA256.
    """
    name = b"salted-sha256"
    digest = hashlib.sha256


class SaltedSHA384Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA384.
    """
    name = b"salted-sha384"
    digest = hashlib.sha384


class SaltedSHA512Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA512.
    """
    name = b"salted-sha512"
    digest = hashlib.sha512


_HMACHash = namedtuple("_HMACHash", ["salt", "hash"])


class HMACHasher(UpgradeableHasher):
    digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def create(self, password):
        salt = generate_salt(self.salt_length)
        return self.format({
            "name": self.name,
            "salt": salt,
            "hash": hmac.new(salt, password, self.digest).digest()
        })

    def format(self, context):
        return b"$".join([
            context["name"],
            hexlify(context["salt"]),
            hexlify(context["hash"])
        ])

    def parse(self, formatted_hash):
        salt, hash = UpgradeableHasher.parse(self, formatted_hash).split(b"$", 1)
        return _HMACHash(unhexlify(salt), hash)

    def verify(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        hash = hexlify(hmac.new(parsed.salt, password, self.digest).digest())
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class HMACMD5(HMACHasher):
    """
    A hasher that uses HMAC with a salt and MD5.
    """
    name = b"hmac-md5"
    digest = hashlib.md5


class HMACSHA1(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA1.
    """
    name = b"hmac-sha1"
    digest = hashlib.sha1


class HMACSHA224(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA224.
    """
    name = b"hmac-sha224"
    digest = hashlib.sha224


class HMACSHA256(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA256.
    """
    name = b"hmac-sha256"
    digest = hashlib.sha256


class HMACSHA384(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA384.
    """
    name = b"hmac-sha384"
    digest = hashlib.sha384


class HMACSHA512(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA512.
    """
    name = b"hmac-sha512"
    digest = hashlib.sha512


ALL_HASHERS = OrderedDict((hasher.name, hasher) for hasher in filter(None, [
    None if bcrypt is None else BCryptHasher,
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
]))


class ConfigWarning(UserWarning):
    pass


class PasswordHasher(UpgradeableMixin):
    #: An :class:`~collections.OrderedDict` containing the hashers
    #: :class:`PasswordHasher` uses in descending order of recommendation.
    default_hasher_classes = ALL_HASHERS

    @classmethod
    def from_config(cls, config):
        """
        Creates a :class:`PasswordHasher` from `config`.

        The hashers will be looked up in :attr:`default_hasher_classes`.
        """
        hashers = []
        for name, hasher_cls in cls.default_hasher_classes.items():
            hasher_config = config["hashers"].get(name, {})
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
        """
        Like :meth:`from_config` but loads the config from a json file at
        `filepath` first.
        """
        with open(filepath, "rb") as config_file:
            return cls.from_config(json.load(config_file))

    def __init__(self, hashers):
        self.hashers = OrderedDict((hasher.name, hasher) for hasher in hashers)

    @property
    def preferred_hasher(self):
        """
        The hasher used to create new password hashes.
        """
        return next(iter(self.hashers.values()))

    def create(self, password):
        """
        Returns the a hash for the given `password` using
        :attr:`preferred_hasher`.
        """
        return self.preferred_hasher.create(password)

    def get_hasher(self, formatted_hash):
        return self.hashers[formatted_hash.split(b"$", 1)[0]]

    def verify(self, password, formatted_hash):
        return self.get_hasher(formatted_hash).verify(password, formatted_hash)

    def upgrade(self, password, formatted_hash):
        hasher = self.get_hasher(formatted_hash)
        if hasher.name != self.preferred_hasher.name:
            return self.create(password)
        elif isinstance(hasher, UpgradeableMixin):
            return hasher.upgrade(password, formatted_hash)
