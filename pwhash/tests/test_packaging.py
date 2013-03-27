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

from pwhash.tests.utils import create_temp_dir


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


def test_install():
    try:
        with create_temp_dir() as root:
            returncode = subprocess.call(
                [
                    sys.executable, os.path.join(TEST_PACKAGE_PATH, "setup.py"),
                    "install",
                    "--root", root
                ],
                cwd=TEST_PACKAGE_PATH
            )
            assert returncode == 0
            site_packages = get_subdir(root, "site-packages")
            assert site_packages is not None
            assert os.path.isfile(
                os.path.join(site_packages, "package", "pwhashc.json")
            )
    finally:
        for name in os.listdir(TEST_PACKAGE_PATH):
            name = os.path.join(TEST_PACKAGE_PATH, name)
            if name not in KNOWN_FILES:
                rmtree(name)
