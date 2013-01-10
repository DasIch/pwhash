# coding: utf-8
from setuptools import setup

import pwhash


setup(
    name="pwhash",
    version="0.1-dev",
    license="BSD",
    author="Daniel Neuhäuser",
    author_email="dasdasich@gmail.com",
    description="simple safe password hashing",
    py_modules=["pwhash"],
    install_requires=["cffi"],
    zip_safe=False,
    ext_modules=[pwhash.ffi.verifier.get_extension()]
)
