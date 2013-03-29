# coding: utf-8
"""
    pwhash.tests.test_packaging
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import sys
import subprocess
from shutil import rmtree
from functools import partial

import pytest


PACKAGE_PATH = os.path.dirname(os.path.abspath(__file__))
TEST_PACKAGE_PATH = os.path.join(PACKAGE_PATH, "package")
KNOWN_FILES = frozenset(map(partial(os.path.join, TEST_PACKAGE_PATH), [
    "setup.py",
    "MANIFEST.in",
    "package"
]))


def get_subdir(root, dirname):
    for root, dirs, _ in os.walk(root):
        for dir in dirs:
            if dir == dirname:
                return os.path.join(root, dir)


def install_setuppy(root):
    returncode = subprocess.call(
        [
            sys.executable, os.path.join(TEST_PACKAGE_PATH, "setup.py"),
            "install", "--root", root
        ],
        cwd=TEST_PACKAGE_PATH
    )
    assert returncode == 0
    site_packages = get_subdir(root, "site-packages")
    assert site_packages is not None
    return site_packages

def install_pip(root):
    returncode = subprocess.call(
        ["pip", "install", "--target", root, "."],
        cwd=TEST_PACKAGE_PATH
    )
    assert returncode == 0
    return root


@pytest.mark.parametrize("install", [install_setuppy, install_pip])
def test_install(install, tmpdir):
    tmpdir = str(tmpdir)
    try:
        assert os.path.isfile(
            os.path.join(install(tmpdir), "package", "pwhashc.json")
        )
    finally:
        for name in os.listdir(TEST_PACKAGE_PATH):
            name = os.path.join(TEST_PACKAGE_PATH, name)
            if name not in KNOWN_FILES:
                rmtree(name)
