# coding: utf-8
"""
    conftest
    ~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import pytest


def pytest_addoption(parser):
    parser.addoption("--fast", action="store_true", help="skip slow tests")


@pytest.fixture
def run_fast(pytestconfig):
    return pytestconfig.getoption("--fast")
