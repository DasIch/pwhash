# coding: utf-8
"""
    pwhash.tests.test_config
    ~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import sys
from contextlib import contextmanager

import pytest
import pexpect

import pwhash
from pwhash import config


class TestConfigCLI(object):
    @contextmanager
    def spawn(self, command, *args, **kwargs):
        p = pexpect.spawn(
            "pwhash-config %s" % command,
            logfile=sys.stderr,
            *args, **kwargs
        )
        try:
            yield p
            p.expect(pexpect.EOF)
            assert not p.isalive()
        finally:
            p.close()

    @pytest.mark.parametrize("command", ["-v", "--version"])
    def test_version(self, command):
        with self.spawn(command) as p:
            p.expect("pwhash version: ([\d\.\-a-z]+)")
            assert p.match.group(1) == pwhash.__version__
            p.expect("application config version: (\d+)")
            assert int(p.match.group(1)) == config.APPLICATION_VERSION
            p.expect("deployment config version: (\d+)")
            assert int(p.match.group(1)) == config.DEPLOYMENT_VERSION

    @pytest.mark.parametrize(("command", "filename"), [
        ("create", "pwhash.json"),
        ("create -o foo.json", "foo.json"),
        ("create --out bar.json", "bar.json")
    ])
    def test_create(self, tmpdir, command, filename):
        tmpdir = str(tmpdir)
        with self.spawn(command, cwd=tmpdir) as p:
            p.expect("What is the minimum password length?")
            p.sendline("a")
            p.expect("'a' is not an integer")
            p.expect("What is the minimum password length?")
            p.sendline("0")
            p.expect("Passwords must be at least one character long")
            p.expect("What is the minimum password length?")
            p.sendline("8")

            p.expect("How long should hashing take in seconds?")
            p.sendline("a")
            p.expect("'a' is not a float")
            p.expect("How long should hashing take in seconds?")
            p.sendline("0")
            p.expect("The duration must be more than 0s")
            p.expect("How long should hashing take in seconds?")
            p.sendline("0.1")
            p.expect("%r created!" % filename)

        assert os.listdir(tmpdir) == [filename]

    def create_config(self, min_password_length, duration, directory,
                      name="pwhash.json"):
        with self.spawn("create -o %s" % name, cwd=directory) as p:
            p.expect("What is the minimum password length?")
            p.sendline(str(min_password_length))
            p.expect("How long should hashing take in seconds?")
            p.sendline(str(duration))
            p.expect("%r created!" % name)

    @pytest.mark.parametrize(("command", "filename"), [
        ("compile pwhash.json", "pwhashc.json"),
        ("compile -o foo.json pwhash.json", "foo.json"),
        ("compile --out bar.json pwhash.json", "bar.json")
    ])
    def test_compile(self, tmpdir, command, filename):
        tmpdir = str(tmpdir)
        self.create_config(8, 0.1, tmpdir)
        assert os.listdir(tmpdir) == ["pwhash.json"]
        with self.spawn(command, cwd=tmpdir) as p:
            p.expect("%r created!" % filename)
        assert set(os.listdir(tmpdir)) == {"pwhash.json", filename}

    def test_upgrade(self, tmpdir):
        tmpdir = str(tmpdir)
        self.create_config(8, 0.1, tmpdir)
        with self.spawn("upgrade pwhash.json", cwd=tmpdir) as p:
            p.expect("application config already at most recent version")
