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
working directory

You are here because you wanted to hash passwords, so let us go do that now::

  from pwhash import PasswordHasher

  pwhasher = PasswordHasher.from_config_file("pwhash.json")


This will create a :class:`~pwhash.PasswordHasher` that can be used to hash,
verify and upgrade (we will learn later what that is) passwords. You can
create a hash using :meth:`~pwhash.PasswordHasher.create`::

  hash = pwhasher.create(b"password")

This will create a hash that will look kind of like this::

  b"pbkdf2$hmac-sha1$144927$7dc6eb3780faf9135901aa738cae76e4689cc9d973a7197e8ffab6174fab5544$fa57328ba4cbbf1f13626b21b19bf5d4ff82d364"

This hash contains the method used for hashing (`pbkdf2`), the parameters
needed if we want to verify a password (in this case the hashing function used
by pbkdf2, the number of rounds and the salt) and the actual hash.

Once we have such a hash, we can verify that a certain password matches that
hash::

  pwhash.verify(b"password", hash)

This will return ``True`` if the ``b"password"`` is the password that produced
`hash`, which is the case here.

In real applications it is not a good idea to just verify the password though.
If we upgrade our server and thereby change the configuration or the method of
hashing is compromised and pwhash introduced a new safer hashing method, we
want to replace the hash with a new safer one. In pwhash terms this is called
upgrading. We cannot do this without knowing the password, so we verify and
upgrade in one step::

  pwhash.verify_and_upgrade(b"password", hash)

This will return a tuple ``(is_correct_password, upgraded_hash)``,
`is_correct_password` is simply the same boolean
:meth:`~pwhash.PasswordHasher.verify` returns and `upgraded_hash` is either
`None` or a new hash with which we can replace the old one.

There is also a method for just upgrading called
:meth:`~pwhash.PasswordHasher.upgrade` but it will *assume* not check, that the
password and hash you pass to it match. I really recommend you use
:meth:`~pwhash.PasswordHasher.verify_and_upgrade` instead, this way nothing can
go wrong here.
