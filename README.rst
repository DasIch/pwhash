pwhash
======

.. image:: https://travis-ci.org/DasIch/pwhash.png?branch=master
   :target: https://travis-ci.org/DasIch/pwhash


pwhash is a password hashing library, relying on well known and trusted implementations
of cryptographic hashing functions, making password hashing as simple as:

.. code:: python

   from pwhash import PasswordHasher

   pwhasher = PasswordHasher.from_config_file("pwhashc.json")

   hash = pwhash.create(u"password")
   verified, new_hash = pwhasher.verify_and_upgrade(u"password", hash)
   if verified:
       authenticate()
       if new_hash is not None:
           save_new_safer_hash(new_hash)

There is no reason to make password hashing more difficult or upgrading your
hash function less seamless.

Want to learn more or contribute? Take a look at our documentation_.


.. _documentation: http://pwhash.rtfd.org
