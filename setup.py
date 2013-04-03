# coding: utf-8
import sys
from setuptools import setup

import pwhash
import pwhash.utils
import pwhash._openssl

ext_modules = [
    pwhash.utils.ffi.verifier.get_extension(),
    pwhash._openssl.ffi.verifier.get_extension()
]

if sys.platform == "darwin":
    import pwhash._commoncrypto
    ext_modules.append(pwhash._commoncrypto.ffi.verifier.get_extension())


if sys.version_info >= (3, 0):
    extras_require = {}
else:
    extras_require = {
        "bcrypt": ["py-bcrypt>=0.3"]
    }


setup(
    name="pwhash",
    version=pwhash.__version__,
    license="BSD",
    author="Daniel Neuhäuser",
    author_email="dasdasich@gmail.com",
    description="simple safe password hashing",
    url="https://github.com/DasIch/pwhash",
    packages=[
        "pwhash",
        "pwhash.tests",
        "pwhash.tests.package"
    ],
    include_package_data=True,
    entry_points = {
        "console_scripts": [
            "pwhash-config = pwhash.config:run"
        ]
    },
    install_requires=["cffi>=0.5", "docopt>=0.6.0"],
    extras_require=extras_require,
    zip_safe=False,
    ext_modules=ext_modules,
    classifiers=[
        "Development Status :: 1 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ]
)
