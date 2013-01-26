pwhash documentation
====================

pwhash makes password hashing simple and safe. Instead of staying up at
night wondering whether your hash function is compromised, pwhash does
that for you, upgrading your hashes to the latest technology available
on the fly.::

   from pwhash import PasswordHasher

   pwhasher = PasswordHasher.from_config(config)
   hash = pwhasher.create(b"password")
   verified, new_hash = pwhasher.verify_and_upgrade(b"password", hash)
   if verified:
       print(u"Valid Password")
       if new_hash is not None:
           save_new_safer_password_hash(hash)

Get to know pwhash
------------------

.. toctree::

   getting-started.rst


API
---

.. toctree::

   api/pwhash.rst
   api/hashers.rst