# coding: utf-8
import sys
from setuptools import setup

import pwhash._openssl

ext_modules = [pwhash._openssl.ffi.verifier.get_extension()]

if sys.platform == "darwin":
    import pwhash._commoncrypto
    ext_modules.append(pwhash._commoncrypto.ffi.verifier.get_extension())


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
    ext_modules=ext_modules,
    classifiers=[
        "Development Status :: 1 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 2.7"
    ]
)
