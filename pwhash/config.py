# coding: utf-8
"""
    pwhash.config
    ~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from __future__ import print_function
import sys
import json
import codecs
import textwrap

from docopt import docopt

from pwhash import hashers, __version__
from pwhash.utils import (
    determine_pbkdf2_rounds, determine_bcrypt_cost, raw_input
)


#: Current application configuration version.
APPLICATION_VERSION = 1

#: Current deployment configuration version.
DEPLOYMENT_VERSION = 1

_missing = object()


def typed_input(type, prompt, fail_message, default=_missing):
    while True:
        raw = raw_input(prompt)
        if raw or default is _missing:
            try:
                return type(raw)
            except ValueError:
                print(fail_message % raw)
        else:
            return default


def compile(application_config):
    """
    Compiles `application_config` and returns a deployment config, raises
    :exc:`ValueError` if `application_config` is outdated or has been created
    with a more recent incompatible version of pwhash.
    """
    # If you change `config` and nobody documented incrementing
    # DEPLOYMENT_VERSION in CHANGELOG.rst, increment DEPLOYMENT_VERSION and
    # document that in CHANGELOG.rst.
    if application_config["application_version"] != APPLICATION_VERSION:
        raise ValueError("application_config outdated or pwhash outdated")
    pbkdf2_method = "hmac-sha1"
    config = {
        "version": DEPLOYMENT_VERSION,
        "application": application_config,
        "hashers": {
            "pbkdf2": {
                "rounds": determine_pbkdf2_rounds(
                    application_config["min_password_length"],
                    hashers.DEFAULT_SALT_LENGTH,
                    hashers.DIGEST_SIZES[pbkdf2_method],
                    pbkdf2_method,
                    application_config["duration"]
                ),
                "method": pbkdf2_method,
                "salt_length": hashers.DEFAULT_SALT_LENGTH
            }
        }
    }
    try:
        config["hashers"]["bcrypt"] = {
            "cost": determine_bcrypt_cost(
                application_config["min_password_length"],
                application_config["duration"]
            )
        }
    except RuntimeError:
        pass
    for name, hasher in hashers.ALL_HASHERS.items():
        if name.startswith("salted") or name.startswith("hmac"):
            config["hashers"][name] = {
                "salt_length": hashers.DEFAULT_SALT_LENGTH
            }
    return config


def load(path):
    """
    Loads a pwhash configuration from the given `path` and returns it.
    """
    with codecs.open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def dump(path, config):
    """
    Dumps the given pwhash `config` to the given `path`.
    """
    with codecs.open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)


class ConfigCLI(object):
    def __init__(self):
        self.commands = {
            "create": self.create,
            "compile": self.compile,
            "upgrade": self.upgrade
        }

    def run(self, argv=sys.argv):
        """
        usage: pwhash-config [-hv] <command> [<args>...]
               pwhash-config (-h | --help)
               pwhash-config (-v | --version)

        options:
          -h, --help     Shows this text
          -v, --version  Shows the version number.

        commands:
          create   Create pwhash application configuration
          compile  Compile application configuration for deployment
          upgrade  Upgraded pwhash application configuration
        """
        arguments = docopt(
            textwrap.dedent(self.run.__doc__),
            argv=argv[1:],
            options_first=True,
            version=textwrap.dedent(u"""\
                pwhash version: %s
                application config version: %d
                deployment config version: %d"""
            ) % (__version__, APPLICATION_VERSION, DEPLOYMENT_VERSION)
        )
        command_arguments = [arguments["<command>"]] + arguments["<args>"]
        command = self.commands.get(arguments["<command>"])
        if command is None:
            self.fail(
                u"%r is not a pwhash-config command" % arguments["<command>"]
            )
        else:
            command(
                docopt(
                    textwrap.dedent(command.__doc__),
                    argv=command_arguments
                )
            )

    def fail(self, message):
        print(message)
        sys.exit(1)

    def info(self, message):
        print(message)
        sys.exit(0)

    def create(self, arguments):
        """
        usage: pwhash-config create [-o <file>]

        Creates an application config file.

        options:
          -o, --out=<file>  Configuration file [default: pwhash.json]
        """
        while True:
            min_password_length = typed_input(
                int,
                u"What is the minimum password length? ",
                u"%r is not an integer"
            )
            if min_password_length > 0:
                break
            print(u"Passwords must be at least one character long")

        while True:
            duration = typed_input(
                float,
                u"How long should hashing take in seconds? ",
                "%r is not a float"
            )
            if duration > 0:
                break
            print(u"The duration must be more than 0s")

        # If you change `config` and nobody documented incrementing
        # APPLICATION_VERSION in CHANGELOG.rst, increment APPLICATION_VERSION
        # and document that in CHANGELOG.rst.

        config = {
            "application_version": APPLICATION_VERSION,
            "min_password_length": min_password_length,
            "duration": duration
        }

        dump(arguments["--out"], config)
        self.info(u"\n%r created!" % arguments["--out"])

    def compile(self, arguments):
        """
        usage: pwhash-config compile [-o <file>] <application-config>

        Compiles an application config into a deployment config. This should be
        done on the machine on which the application is being deployed and
        repeated everytime that machine is upgraded.

        options:
          -o, --out=<file>  Configuration file [default: pwhashc.json]
        """
        application_config = load(arguments["<application-config>"])

        if application_config["application_version"] < APPLICATION_VERSION:
            self.fail(u"Configuration needs to be upgraded.")
        elif application_config["application_version"] > APPLICATION_VERSION:
            self.fail(u"Configuration incompatible; upgrade pwhash")

        dump(arguments["--out"], compile(application_config))
        self.info(u"%r created!" % arguments["--out"])

    def upgrade(self, arguments):
        """
        usage: pwhash-config upgrade <application-config>

        Instead of re-creating the application config using `pwhash-config create`,
        this will help you to incrementally upgrade it to the newest version.
        """
        config = load(arguments["<application-config>"])

        if config["application_version"] == APPLICATION_VERSION:
            self.info(u"application config already at most recent version")
        else:
            self.fail(u"invalid application config")

        dump(arguments["<application-config>"], config)


run = ConfigCLI().run
