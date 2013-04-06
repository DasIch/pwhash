# coding: utf-8
import os
import sys
from setuptools import setup

try:
    import __pypy__
except ImportError:
    __pypy__ = None

try:
    import pypissh
except ImportError:
    # non-developer
    pass
else:
    pypissh.monkeypatch()

# If cffi is available we can import all our ffi stuff and compile it as
# extensions, if it isn't for example when installing from PyPI we skip this.
try:
    import pwhash.utils
    import pwhash._openssl
except ImportError:
    ext_modules = []
else:
    ext_modules = [
        pwhash.utils.ffi.verifier.get_extension(),
        pwhash._openssl.ffi.verifier.get_extension()
    ]

if sys.platform == "darwin":
    try:
        import pwhash._commoncrypto
        ext_modules.append(pwhash._commoncrypto.ffi.verifier.get_extension())
    except ImportError:
        pass


# py-bcrypt doesn't support Python 3.x
if sys.version_info >= (3, 0):
    extras_require = {}
else:
    extras_require = {
        "bcrypt": ["py-bcrypt>=0.3"]
    }


def get_version():
    # We can't import pwhash because the cffi dependency and in the future
    # others are not installed, yet, so we have to parse pwhash/__init__.py
    with open(os.path.join(os.path.dirname(__file__), "pwhash", "__init__.py")) as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].replace('"', '').strip()
                break
        else:
            raise ValueError("__version__ not found")


def get_long_description():
    with open("README.rst") as f:
        return f.read()


setup(
    name="pwhash",
    version=get_version(),
    license="BSD",
    author="Daniel Neuhäuser",
    author_email="dasdasich@gmail.com",
    description="simple safe password hashing",
    long_description=get_long_description(),
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
    install_requires=[
        "cffi>=0.5" if __pypy__ is None else "cffi==0.4",
        "docopt>=0.6.0"
    ],
    extras_require=extras_require,
    zip_safe=False,
    ext_modules=ext_modules,
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ]
)
