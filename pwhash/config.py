# coding: utf-8
"""
    pwhash.config
    ~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash import hashers
from pwhash.utils import determine_pbkdf2_rounds


_missing = object()
def get_int(prompt, default=_missing):
    raw_int = raw_input(prompt)
    return int(raw_int) if raw_int or default is _missing else default


def get_float(prompt):
    return float(raw_input(prompt))


def create_config():
    print u"pwhash config creation"
    print u"general"
    salt_length = get_int(
        u"Which salt length should be used in bytes? [default: %d] " % hashers.DEFAULT_SALT_LENGTH,
        hashers.DEFAULT_SALT_LENGTH
    )
    print
    print u"pbkdf2"
    rounds = get_int(u"How many rounds should be used? [default: auto] ", None)
    if rounds is None:
        password_length = get_int(u"What is the minimum password length? ")
        duration = get_float(
            u"How much time are you willing to spend on hashing in seconds? "
        )
        method = "hmac-sha1"
        rounds = determine_pbkdf2_rounds(
            password_length,
            salt_length,
            hashers.DIGEST_SIZES[method],
            method,
            duration
        )
        print u"Using %d rounds" % rounds

    config = {}
    for name, hasher in hashers.ALL_HASHERS.iteritems():
        if name.startswith("salted") or name.startswith("hmac"):
            config[name] = {"salt_length": salt_length}
    config["pbkdf2"] = {
        "rounds": rounds,
        "method": method,
        "salt_length": salt_length
    }
    return config
