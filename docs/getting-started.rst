Getting Started
===============

In order to use pwhash you first have to install it, you can do that with pip::

  $ pip install pwhash

The next step is to generate the necessary configuration, which depends on your
application and the machine it is deployed on, so it has to be created for
every deployment. How exactly we can create a new configuration on every
deployment conveniently will be covered later, for now let us just create the
configuration on the current machine, to do this simply run::

  $ pwhash-config create

This will ask you some questions, unless you have a good reason to, you should
go with the defaults whenever those are provided. Once you are finished you
will find a ``pwhash.json`` file, containing the configuration, in your current
working directory. The next step you have to take is compiling this application
configuration into the deployment configuration::

  $ pwhash-config compile pwhash.json

This creates another file `pwhashc.json`, which is the deployment
configuration. The deployment configuration has to be re-created for every
machine on which your application is deployed. It contains information derived
from the information about your application as well as machine specific
information determined during compilation. This allows pwhash to adopt
algorithmic cost to the machine you are deploying on, making it as difficult as
difficult as possible for an attacker to get the hashed passwords.

Using that configuration we can now use it to create a
:class:`~pwhash.PasswordHasher`::

  from pwhash import PasswordHasher

  pwhasher = PasswordHasher.from_config_file("pwhashc.json")

You can use the `pwhasher` object to hash, verify and upgrade (we will learn
later what that is) passwords. You can create a hash using
:meth:`~pwhash.PasswordHasher.create`::

  hash = pwhasher.create(u"password")

In order to verify a password against that hash use::

  pwhash.verify_and_upgrade(u"password", hash)

This will return a tuple ``(is_correct_password, upgraded_hash)``,
`is_correct_password` is `True` if ``u"password"`` is actually the correct
password and `False` otherwise. `upgraded_hash` will be `None` or a new more
secure hash you should replace the old one with.

`pwhash` will upgrade a hash and provide you with an `upgraded_hash` if a new
more secure hashing function is available or if the parameters for the hash
function changed, which happens if you upgrade machines and re-compile the
configuration.
