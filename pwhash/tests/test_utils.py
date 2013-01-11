# coding: utf-8
"""
    pwhash.tests.test_utils
    ~~~~~~~~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
from pwhash.utils import determine_pbkdf2_rounds

import pytest


def test_determine_pbkdf2_rounds():
    method = "hmac-sha1"
    for arguments in [
        (1.0, 1, 1, method, 1),
        (1, 1, 1.0, method, 1),
        ]:
        with pytest.raises(TypeError):
            determine_pbkdf2_rounds(*arguments)
