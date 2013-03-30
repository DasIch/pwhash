# coding: utf-8
"""
    pwhash.packaging
    ~~~~~~~~~~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
from distutils import log
from setuptools.command.install import install as InstallBase

from pwhash import config


def get_install_dir(install_lib, package):
    return os.path.join(*([install_lib] + package.split(".")))


class Install(InstallBase):
    """
    A :mod:`distutils` command to be used instead of
    :class:`distutils.command.install.install` which compiles any `pwhash.json`
    files that have been included as package data to `pwhashc.json` files.

    In order to use it you have to add the following to your `setup.py`::

       from pwhash.packaging import Install

       setup(
           ...
           cmdclass={"install": Install},
           include_package_data=True
       )

    You also have to add the following line to your `MANIFEST.in` file::

       global-include pwhash.json

    This will add all pwhash.json files as package data, if you want to be more
    specific take a look at the :ref:`distutils documentation on the topic
    <manifest_template>`
    """
    def run(self):
        InstallBase.run(self)

        for package in self.distribution.packages:
            package_dir = get_install_dir(self.install_lib, package)
            application_config_path = os.path.join(package_dir, "pwhash.json")
            deployment_config_path = os.path.join(package_dir, "pwhashc.json")
            if os.path.isfile(application_config_path):
                log.info(
                    u"Compiling %r to %r" % (application_config_path, deployment_config_path)
                )
                if not self.dry_run:
                    application_config = config.load(application_config_path)
                    config.dump(
                        deployment_config_path,
                        config.compile(application_config)
                    )
