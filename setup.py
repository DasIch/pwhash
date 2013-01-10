# coding: utf-8
from setuptools import setup

import pwhash.openssl


setup(
    name="pwhash",
    version="0.1-dev",
    license="BSD",
    author="Daniel Neuhäuser",
    author_email="dasdasich@gmail.com",
    description="simple safe password hashing",
    packages=["pwhash"],
    install_requires=["cffi"],
    zip_safe=False,
    ext_modules=[pwhash.openssl.ffi.verifier.get_extension()]
)
