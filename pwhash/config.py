# coding: utf-8
"""
    pwhash.config
    ~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import sys
import json
from argparse import ArgumentParser

from pwhash import hashers
from pwhash.utils import determine_pbkdf2_rounds


_missing = object()
def get_int(prompt, default=_missing):
    raw_int = raw_input(prompt)
    return int(raw_int) if raw_int or default is _missing else default


def get_float(prompt):
    return float(raw_input(prompt))


def get_bool(prompt, default=False):
    raw_bool = raw_input(prompt)
    if raw_bool == "y":
        return True
    elif raw_bool == "n":
        return False
    else:
        return default


def create_config(argv=sys.argv):
    parser = ArgumentParser()
    parser.add_argument(
        "-o", "--out", metavar="OUTFILE", dest="outfile",
        default="pwhash.json"
    )
    outfilename = parser.parse_args(argv[1:]).outfile

    print u"pwhash config creation"
    print u"general"
    while True:
        salt_length = get_int(
            u"Which salt length should be used in bytes? [default: %d] " % hashers.DEFAULT_SALT_LENGTH,
            hashers.DEFAULT_SALT_LENGTH
        )
        if salt_length < hashers.RECOMMENDED_MIN_SALT_LENGTH:
            print u"That's below the NIST recommended minimum salt length of %d bytes" % hashers.RECOMMENDED_MIN_SALT_LENGTH
            if get_bool(u"Are you sure you want to use that salt length? [n] "):
                break
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

    with open(outfilename, "wb") as outfile:
        json.dump(config, outfile, indent=4)
