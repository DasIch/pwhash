Deploying Applications
======================

Running ``pwhash-config compile`` everytime your application is deployed, is
inconvenient and it is not something you can expect non-developers to do.
Instead this is something that should happen if your application is deployed be
it by installing using ``python setup.py install`` or ``pip install your-app``.


setup.py and pip
----------------

This can be achieved by using :class:`pwhash.packaging.Install`, this is an
implementation of the command that is invoked when you execute
``python setup.py install`` (which is also executed by `pip`).
:class:`~pwhash.packaging.Install` automatically compiles all `pwhash.json`
files you have declared as package data and are found within a python package.

In order to use this you have to first make :func:`setuptools.setup` use
:class:`pwhash.packaging.Install`, this is done by overriding the default
`install` implementation using the `cmdclass` keyword argument::

   from pwhash.packaging import Install

   setup(
       ...
       cmdclass={"install": Install}
   )

Once you have done that you to make :func:`setuptools.setup` include package
data, which you can do using the `include_package_data` keyword argument::

   setup(
       ...
       include_package_data=True
   )

The next step is to teach :func:`setuptools.setup` which files are package
data, which you can do using a `MANIFEST.in` file. You can simply include all
`pwhash.json` files using the following command::

   global-include pwhash.json

If you want to be more restrictive take a look at the
:ref:`distutils documentation <manifest_template>` which describes the format
of `MANIFEST.in` files in more detail.


Other Deployments
-----------------

If the above is not a solution in your case, you can roll your own. The
:mod:`pwhash.config` module provides the :func:`~pwhash.config.load`,
:func:`~pwhash.config.compile` and :func:`~pwhash.config.dump` functions which
can be used to compile application configuration. If you feel your solution
warrants inclusion into pwhash or if you feel you have a problem that is in
need of a solution to warrants inclusion, please
`create an issue in the tracker <https://github.com/DasIch/pwhash/issues/new>`_.
