# coding: utf-8
"""
    pwhash.hashers
    ~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import hmac
import inspect
import hashlib
import warnings
from binascii import hexlify, unhexlify
from collections import OrderedDict

from pwhash.algorithms import pbkdf2
from pwhash.utils import (
    constant_time_equal, classproperty, _import_bcrypt, get_root_path,
    text_type, native_to_bytes, bytes_to_native, int_to_bytes
)

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


class PasswordHash(object):
    """
    Represents a password hash.

    A password hash in general consists of the `name` of the hash function
    used, the `hash` returned by that function and optionally further
    `parameters` (excluding the hashed string) that were passed to the hash
    function and are necessary to reconstruct the `hash`. All arguments passed
    to :class:`PasswordHash` are accessible as attributes on the returned
    instance.

    Each parameter is available as a read-only attribute for convenience.
    """
    def __init__(self, name, hash, **parameters):
        self.name = name
        self.hash = hash
        self.parameters = parameters

    def __getattr__(self, attribute_name):
        try:
            return self.parameters[attribute_name]
        except KeyError:
            raise AttributeError(attribute_name)


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

    @property
    def max_hash_length(self):
        """
        The maximum length of the hash returned by :meth:`create` or `None` if
        a maximum length cannot be determined.
        """
        return len(self.create(u"password"))

    @property
    def min_hash_length(self):
        """
        The minimum length of the hash returned by :meth:`create`.
        """
        return 0 if self.max_hash_length is None else self.max_hash_length

    def parse(self, formatted_hash):
        """
        Parses `formatted_hash` as returned by :meth:`format` and returns a
        :class:`PasswordHash`.
        """
        if not b"$" in formatted_hash:
            raise ValueError("name missing: %r" % formatted_hash)
        name, hash = formatted_hash.split(b"$", 1)
        name = bytes_to_native(name)
        if name != self.name:
            raise ValueError("expected %r hash, got %r" % (self.name, name))
        return hash

    def _normalize_password(self, password):
        if isinstance(password, text_type):
            password = password.encode("utf-8")
        return password

    def create(self, password):
        """
        Returns a hash for `password`. If `password` is a unicode string it is
        encoded using utf-8.

        The hash returned is created by calling :meth:`format` with a
        :class:`PasswordHash` instance.
        """
        password = self._normalize_password(password)
        # py-bcrypt does not allow \0 in passwords. That is a very annoying
        # restriction however at the moment there is no other implementation,
        # that is maintained and trustworthy.
        if b"\0" in password:
            raise ValueError("\\0 not allowed in passwords")
        return self._create_from_bytes(password)

    def _create_from_bytes(self, password):
        raise NotImplementedError()

    def format(self, parsed_hash):
        """
        Takes a :class:`PasswordHash` instance and returns a byte string
        containing all information needed to verify a hash.
        """
        return b"$".join([
            native_to_bytes(parsed_hash.name),
            hexlify(parsed_hash.hash)
        ])

    def verify(self, password, formatted_hash):
        """
        Returns `True` if `formatted_hash` was created using `password`.
        """
        return self._verify_from_bytes(
            self._normalize_password(password),
            formatted_hash
        )

    def _verify_from_bytes(self, password, formatted_hash):
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


class BCryptHasher(UpgradeableHasher):
    """
    A hasher that uses bcrypt, implemented using py-bcrypt_. The `cost`
    argument can be used to increase the performance/time required to hash a
    password.

    A good `cost` value can be determined using
    :func:`pwhash.utils.determine_bcrypt_cost`.

    Creating an instance may raise a :exc:`RuntimeError` if py-bcrypt_ is not
    installed.

    .. _py-bcrypt: http://www.mindrot.org/projects/py-bcrypt/
    """
    name = "bcrypt"

    def __init__(self, cost):
        self.cost = cost

        if bcrypt is None:
            raise RuntimeError("bcrypt unavailable; requires py-bcrypt >= 0.3")

    def parse(self, formatted_hash):
        """
        Parses a `formatted_hash` as returned by :meth:`format` and returns a
        :class:`PasswordHash` object.

        The returned hash object is expected to have a `cost` parameter,
        corresponding to the arguments passed to :class:`BCryptHasher`.
        """
        formatted_hash = UpgradeableHasher.parse(self, formatted_hash)
        cost, hash = formatted_hash.split(b"$", 1)
        return PasswordHash(self.name, hash, cost=int(cost))

    def format(self, parsed_hash):
        """
        Takes a :class:`PasswordHash` object as returned by :meth:`parse` and
        returns a byte string that must be parseable by :meth:`parse`.

        The given hash object is expected to have an `cost` parameter
        corresponding to the `cost` argument :class:`BCryptHasher` takes.
        """
        return b"$".join([
            native_to_bytes(parsed_hash.name),
            int_to_bytes(parsed_hash.cost),
            parsed_hash.hash
        ])

    def _create_from_bytes(self, password):
        return self.format(PasswordHash(
            self.name,
            bcrypt.hashpw(password, bcrypt.gensalt(self.cost)),
            cost=self.cost
        ))

    def _verify_from_bytes(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        return constant_time_equal(
            bcrypt.hashpw(password, parsed.hash),
            parsed.hash
        )

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if self.cost > parsed.cost:
            return self.create(password)


class PBKDF2Hasher(UpgradeableHasher):
    """
    A hasher that uses PBKDF2.

    :param rounds: The number of rounds/iterations to be performed by pbkdf2,
                   this parameter can be increased to increase performance/time
                   required to hash passwords.

    :param method: The hash function that should be used by pbkdf2 internally,
                   theoretically possible values are
                   ``"hmac-sha{1,224,256,384,512}"``, which of these can
                   actually be used depends on the underlying implementation.

    :param salt_length: The length of the salt that should be used.

    PBKDF2 is implemented with bindings to CommonCrypto_ and OpenSSL_. As Apple
    has deprecated OpenSSL due to issues with ABI compatibilty, CommonCrypto is
    used on OS X.

    .. _CommonCrypto: https://developer.apple.com/library/mac/#documentation/Darwin/Reference/ManPages/man3/Common%20Crypto.3cc.html
    .. _OpenSSL: http://www.openssl.org/
    """
    name = "pbkdf2"

    def __init__(self, rounds, method="hmac-sha1",
                 salt_length=DEFAULT_SALT_LENGTH):
        self.rounds = rounds
        self.method = method
        self.salt_length = salt_length
        self.hash_length = DIGEST_SIZES[method]

    def parse(self, formatted_hash):
        """
        Parses a `formatted_hash` as returned by :meth:`format` and returns a
        :class:`PasswordHash` object.

        The returned hash object is expected to have a `rounds`, `method` and
        `salt_length` parameter, corresponding to the arguments passed to
        :class:`PBKDF2Hasher`.
        """
        formatted_hash = UpgradeableHasher.parse(self, formatted_hash)
        method, rounds, salt, hash = formatted_hash.split(b"$")
        return PasswordHash(
            self.name,
            unhexlify(hash),
            method=method.decode("ascii"),
            rounds=int(rounds),
            salt=unhexlify(salt)
        )

    def _create_from_bytes(self, password):
        salt = generate_salt(self.salt_length)
        return self.format(PasswordHash(
            self.name,
            pbkdf2(
                password, salt, self.rounds, self.hash_length, self.method
            ),
            method=self.method,
            rounds=self.rounds,
            salt=salt
        ))

    def format(self, parsed_hash):
        """
        Takes a :class:`PasswordHash` object as returned by :meth:`parse` and
        returns a byte string that must be parseable by :meth:`parse`.

        The given hash object is expected to have a `rounds` and `method`
        parameter, corresponding to the arguments passed to
        :class:`PBKDF2Hasher` as well as a `salt` parameter of type `str`.
        """
        return b"$".join([
            native_to_bytes(parsed_hash.name),
            parsed_hash.method.encode("ascii"),
            int_to_bytes(parsed_hash.rounds),
            hexlify(parsed_hash.salt),
            hexlify(parsed_hash.hash)
        ])

    def _verify_from_bytes(self, password, formatted_hash):
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
    name = "plain"

    @property
    def max_hash_length(self):
        return None

    def _create_from_bytes(self, password):
        return self.format(PasswordHash(self.name, password))


class DigestHasher(Hasher):
    _digest = None

    def _create_from_bytes(self, password):
        return self.format(
            PasswordHash(self.name, self._digest(password).digest())
        )


class MD5Hasher(DigestHasher):
    """
    A hasher that used MD5.
    """
    name = "md5"
    _digest = hashlib.md5


class SHA1Hasher(DigestHasher):
    """
    A hasher that used SHA1.
    """
    name = "sha1"
    _digest = hashlib.sha1


class SHA224Hasher(DigestHasher):
    """
    A hasher that uses SHA224.
    """
    name = "sha224"
    _digest = hashlib.sha224


class SHA256Hasher(DigestHasher):
    """
    A hasher that uses SHA256.
    """
    name = "sha256"
    _digest = hashlib.sha256


class SHA384Hasher(DigestHasher):
    """
    A hasher that uses SHA384.
    """
    name = "sha384"
    _digest = hashlib.sha384


class SHA512Hasher(DigestHasher):
    """
    A hasher that uses SHA512.
    """
    name = "sha512"
    _digest = hashlib.sha512


class SaltedDigestHasher(UpgradeableHasher):
    _digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def _create_from_bytes(self, password):
        salt = generate_salt(self.salt_length)
        return self.format(PasswordHash(
            self.name,
            self._digest(salt + password).digest(),
            salt=salt
        ))

    def format(self, parsed_hash):
        """
        Takes a :class:`PasswordHash` object as returned by :meth:`parse` and
        returns a byte string that must be parseable by :meth:`parse`.

        The given hash object is expected to have a `salt` parameter of type
        `str`.
        """
        return b"$".join([
            native_to_bytes(parsed_hash.name),
            hexlify(parsed_hash.salt),
            hexlify(parsed_hash.hash)
        ])

    def parse(self, formatted_hash):
        """
        Parses a `formatted_hash` as returned by :meth:`format` and returns a
        :class:`PasswordHash` object.

        The returned hash object is expected to have a `salt` parameter.
        """
        formatted_hash = Hasher.parse(self, formatted_hash)
        salt, hash = formatted_hash.split(b"$", 2)
        return PasswordHash(self.name, hash, salt=unhexlify(salt))

    def _verify_from_bytes(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        hash = hexlify(self._digest(parsed.salt + password).digest())
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class SaltedMD5Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and MD5.
    """
    name = "salted-md5"
    _digest = hashlib.md5


class SaltedSHA1Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA1.
    """
    name = "salted-sha1"
    _digest = hashlib.sha1


class SaltedSHA224Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA224.
    """
    name = "salted-sha224"
    _digest = hashlib.sha224


class SaltedSHA256Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA256.
    """
    name = "salted-sha256"
    _digest = hashlib.sha256


class SaltedSHA384Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA384.
    """
    name = "salted-sha384"
    _digest = hashlib.sha384


class SaltedSHA512Hasher(SaltedDigestHasher):
    """
    A hasher that uses a salted password and SHA512.
    """
    name = "salted-sha512"
    _digest = hashlib.sha512


class HMACHasher(UpgradeableHasher):
    _digest = None

    def __init__(self, salt_length=DEFAULT_SALT_LENGTH):
        self.salt_length = salt_length

    def _create_from_bytes(self, password):
        salt = generate_salt(self.salt_length)
        return self.format(PasswordHash(
            self.name,
            hmac.new(salt, password, self._digest).digest(),
            salt=salt
        ))

    def format(self, parsed_hash):
        """
        Takes a :class:`PasswordHash` object as returned by :meth:`parse` and
        returns a byte string that must be parseable by :meth:`parse`.

        The given hash object is expected to have a `salt` parameter of type
        `str`.
        """
        return b"$".join([
            native_to_bytes(parsed_hash.name),
            hexlify(parsed_hash.salt),
            hexlify(parsed_hash.hash)
        ])

    def parse(self, formatted_hash):
        """
        Parses a `formatted_hash` as returned by :meth:`format` and returns a
        :class:`PasswordHash` object.

        The returned hash object is expected to have a `salt` parameter.
        """
        salt, hash = UpgradeableHasher.parse(self, formatted_hash).split(b"$", 1)
        return PasswordHash(self.name, hash, salt=unhexlify(salt))

    def _verify_from_bytes(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        hash = hexlify(hmac.new(parsed.salt, password, self._digest).digest())
        return constant_time_equal(hash, parsed.hash)

    def upgrade(self, password, formatted_hash):
        parsed = self.parse(formatted_hash)
        if self.salt_length > len(parsed.salt):
            return self.create(password)


class HMACMD5Hasher(HMACHasher):
    """
    A hasher that uses HMAC with a salt and MD5.
    """
    name = "hmac-md5"
    _digest = hashlib.md5


class HMACSHA1Hasher(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA1.
    """
    name = "hmac-sha1"
    _digest = hashlib.sha1


class HMACSHA224Hasher(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA224.
    """
    name = "hmac-sha224"
    _digest = hashlib.sha224


class HMACSHA256Hasher(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA256.
    """
    name = "hmac-sha256"
    _digest = hashlib.sha256


class HMACSHA384Hasher(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA384.
    """
    name = "hmac-sha384"
    _digest = hashlib.sha384


class HMACSHA512Hasher(HMACHasher):
    """
    A hasher that uses HMAC with a salt and SHA512.
    """
    name = "hmac-sha512"
    _digest = hashlib.sha512


ALL_HASHERS = OrderedDict((hasher.name, hasher) for hasher in filter(None, [
    None if bcrypt is None else BCryptHasher,
    PBKDF2Hasher,
    # hmac
    HMACSHA512Hasher, HMACSHA384Hasher, HMACSHA256Hasher, HMACSHA224Hasher,
    HMACSHA1Hasher, HMACMD5Hasher,
    # salted digest
    SaltedSHA512Hasher, SaltedSHA384Hasher, SaltedSHA256Hasher,
    SaltedSHA224Hasher, SaltedSHA1Hasher,
    SaltedMD5Hasher,
    # digest
    SHA512Hasher, SHA384Hasher, SHA256Hasher, SHA224Hasher, SHA1Hasher,
    MD5Hasher
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
        return cls(
            hashers,
            min_password_length=config["application"]["min_password_length"]
        )

    @classmethod
    def from_config_file(cls, filepath, relative_to_importable=None):
        """
        Like :meth:`from_config` but loads the config from a json file at
        `filepath` first.

        If `relative_to_importable` is given loads the config from a file
        relative to a directory that is either the directory of a package or
        the directory in which a module is contained, depending on whether the
        name passed as `relative_to_importable` refers to a package or module.
        """
        from pwhash import config
        if relative_to_importable is not None:
            importable_dir = get_root_path(relative_to_importable)
            if importable_dir is None:
                raise ValueError(
                    "cannot determine path for importable: %r" % relative_to_importable
                )
            filepath = os.path.join(importable_dir, filepath)
        return cls.from_config(config.load(filepath))

    def __init__(self, hashers, min_password_length=8):
        self.hashers = OrderedDict((hasher.name, hasher) for hasher in hashers)
        self.min_password_length = min_password_length

    @property
    def preferred_hasher(self):
        """
        The hasher used to create new password hashes.
        """
        return next(iter(self.hashers.values()))

    @property
    def max_hash_length(self):
        """
        The maximum hash length or `None` if it depends on the hashed
        passsword. Take a look at :attr:`min_hash_length` for the latter case.
        """
        result = 0
        for hasher in self.hashers.values():
            if hasher.max_hash_length is None:
                return None
            if hasher.max_hash_length > result:
                result = hasher.max_hash_length
        return result

    @property
    def min_hash_length(self):
        """
        The minimum length of a hash returned by :meth:`create`.

        Assuming the length of hashes depends on the length of your password,
        you can compute the maximum hash length for your application using::

           max_hash_len = min_hash_len + max_password_len
        """
        return max(
            hasher.min_hash_length for hasher in self.hashers.values()
        )

    def create(self, password):
        """
        Returns a hash for the given `password` using :attr:`preferred_hasher`.
        """
        password_length = len(password)
        if password_length < self.min_password_length:
            raise ValueError(
                "password is below minimum length: %d < %d" % (
                    password_length, self.min_password_length
                )
            )
        return self.preferred_hasher.create(password)

    def get_hasher(self, formatted_hash):
        hasher_name = bytes_to_native(formatted_hash.split(b"$", 1)[0])
        try:
            return self.hashers[hasher_name]
        except KeyError:
            raise ValueError(
                "unknown name (%r) or invalid hash: %r" % (
                    hasher_name, formatted_hash
                )
            )

    def verify(self, password, formatted_hash):
        """
        Returns `True` if `formatted_hash` was created from `password`.
        """
        return self.get_hasher(formatted_hash).verify(password, formatted_hash)

    def upgrade(self, password, formatted_hash):
        """
        Returns a new formatted hash if `formatted_hash` was created using an
        outdated hash function or parameters and `None` if it wasn't.
        """
        hasher = self.get_hasher(formatted_hash)
        if hasher.name != self.preferred_hasher.name:
            return self.create(password)
        elif isinstance(hasher, UpgradeableMixin):
            return hasher.upgrade(password, formatted_hash)
