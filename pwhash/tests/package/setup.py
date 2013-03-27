from setuptools import setup

from pwhash.packaging import Install


setup(
    name="PackagingTest",
    cmdclass={"install": Install},
    include_package_data=True,
    packages=["package"]
)
