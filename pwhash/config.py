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
import textwrap

from docopt import docopt

from pwhash import hashers, __version__
from pwhash.utils import determine_pbkdf2_rounds, determine_bcrypt_cost


APPLICATION_VERSION = 1
DEPLOYMENT_VERSION = 1

_missing = object()

try:
    raw_input
except NameError:
    raw_input = input


def int_input(prompt, fail_message, default=_missing):
    while True:
        raw = raw_input(prompt)
        if raw or default is _missing:
            try:
                return int(raw)
            except ValueError:
                print(fail_message % raw)
        else:
            return default


def float_input(prompt, fail_message, default=_missing):
    while True:
        raw = raw_input(prompt)
        if raw or default is _missing:
            try:
                return float(raw)
            except ValueError:
                print(fail_message % raw)
        else:
            return default


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

        options:
          -o, --out=<file>  Configuration file [default: pwhash.json]
        """
        while True:
            min_password_length = int_input(
                u"What is the minimum password length? ",
                u"%r is not an integer"
            )
            if min_password_length > 0:
                break
            print(u"Passwords must be at least one character long")

        while True:
            duration = float_input(
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

        with open(arguments["--out"], "wb") as config_file:
            json.dump(config, config_file, indent=4)

        self.info(u"\n%r created!" % arguments["--out"])

    def compile(self, arguments):
        """
        usage: pwhash-config compile [-o <file>] <application-config>

        options:
          -o, --out=<file>  Configuration file [default: pwhashc.json]

        Compiles an application config into a deployment config. This should be
        done on the machine on which the application is being deployed.
        """
        with open(arguments["<application-config>"], "rb") as config_file:
            application_config = json.load(config_file)

        if application_config["application_version"] < APPLICATION_VERSION:
            self.fail(u"Configuration needs to be upgraded.")
        elif application_config["application_version"] > APPLICATION_VERSION:
            self.fail(u"Configuration incompatible; upgrade pwhash")

        # If you change `config` and nobody documented incrementing
        # DEPLOYMENT_VERSION in CHANGELOG.rst, increment DEPLOYMENT_VERSION and
        # document that in CHANGELOG.rst.

        pbkdf2_method = "hmac-sha1"
        config = {
            "version": {
                "application": application_config["application_version"],
                "deployment": DEPLOYMENT_VERSION
            },
            "hashers": {
                b"pbkdf2": {
                    "rounds": determine_pbkdf2_rounds(
                        application_config["min_password_length"],
                        hashers.DEFAULT_SALT_LENGTH,
                        hashers.DIGEST_SIZES[pbkdf2_method],
                        pbkdf2_method,
                        application_config["duration"]
                    ),
                    "method": pbkdf2_method,
                    "salt_length": hashers.DEFAULT_SALT_LENGTH
                },
                b"bcrypt": {
                    "cost": 12
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
            if name.startswith(b"salted") or name.startswith(b"hmac"):
                config["hashers"][name] = {
                    "salt_length": hashers.DEFAULT_SALT_LENGTH
                }

        with open(arguments["--out"], "wb") as config_file:
            json.dump(config, config_file, indent=4)

        self.info(u"%r created!" % arguments["--out"])

    def upgrade(self, arguments):
        """
        usage: pwhash-config upgrade <application-config>

        Helps you upgrade the application config without having to redo
        everything.
        """
        with open(arguments["<application-config>"], "rb") as config_file:
            config = json.load(config_file)

        if config["application_version"] == APPLICATION_VERSION:
            self.info(u"application config already at most recent version")
        else:
            self.fail(u"invalid application config")

        with open(arguments["<application-config>"], "wb") as config_file:
            json.dump(config, config_file, indent=4)


run = ConfigCLI().run
