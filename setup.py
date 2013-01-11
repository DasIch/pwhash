# coding: utf-8
from setuptools import setup

import pwhash._openssl
import pwhash._commoncrypto


setup(
    name="pwhash",
    version="0.1-dev",
    license="BSD",
    author="Daniel Neuhäuser",
    author_email="dasdasich@gmail.com",
    description="simple safe password hashing",
    url="https://github.com/DasIch/pwhash",
    packages=["pwhash", "pwhash.tests"],
    install_requires=["cffi"],
    zip_safe=False,
    ext_modules=[
        pwhash._openssl.ffi.verifier.get_extension(),
        pwhash._commoncrypto.ffi.verifier.get_extension()
    ]
)
