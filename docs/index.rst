pwhash documentation
====================

pwhash makes password hashing simple and safe. Instead of staying up at
night wondering whether your hash function is compromised, pwhash does
that for you, upgrading your hashes to the latest technology available
on the fly::

   from pwhash import PasswordHasher

   pwhasher = PasswordHasher.from_config_file("pwhashc.json")
   hash = pwhasher.create(u"password")
   verified, new_hash = pwhasher.verify_and_upgrade(u"password", hash)
   if verified:
       print(u"Valid Password")
       if new_hash is not None:
           save_new_safer_password_hash(hash)

Get to know pwhash
------------------

.. toctree::

   getting-started.rst
   deployment.rst
   storage.rst


API
---

.. toctree::

   api/pwhash.rst
   api/config.rst
   api/hashers.rst
   api/packaging.rst
   api/utils.rst


Additional Notes
----------------

.. toctree::

   other/security.rst
   other/contributing.rst
   other/versioning.rst
   other/changelog.rst
   other/license.rst
