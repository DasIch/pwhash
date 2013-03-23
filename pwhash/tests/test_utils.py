# coding: utf-8
"""
    pwhash.tests.test_utils
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash.utils import (
    determine_pbkdf2_rounds, constant_time_equal, _import_bcrypt,
    determine_bcrypt_cost
)

import pytest


def test_determine_pbkdf2_rounds():
    method = "hmac-sha1"
    for arguments in [
        (1.0, 1, 1, method, 1),
        (1, 1, 1.0, method, 1),
        ]:
        with pytest.raises(TypeError):
            determine_pbkdf2_rounds(*arguments)


def test_constant_time_equal():
    # We can't sanely check timing so we just test whether comparision works as
    # expected.
    assert constant_time_equal(b"foo", b"foo")
    assert not constant_time_equal(b"foo", b"bar")
    assert not constant_time_equal(b"bar", b"foo")


def test_determine_bcrypt_cost():
    bcrypt = _import_bcrypt()
    if bcrypt is None:
        with pytest.raises(RuntimeError):
            determine_bcrypt_cost(8, 0.1)
    else:
        assert determine_bcrypt_cost(8, 0.1) > 0
