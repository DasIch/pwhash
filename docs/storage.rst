Storing Hashes
==============

When storing any kind of data you often need to know the size of the data,
at least to do storage efficiently. If you use a hash function like bcrypt
directly that's not a problem because you know the length of the hash in that
case and don't have to worry about the length changing.

If you are using pwhash that is not the case. Everytime you update your pwhash
version or your configuration the hash functions that are used or the
parameters to these functions may change causing the password hash itself to
change in length.

In order to solve this issue pwhash exposes the
:attr:`~pwhash.PasswordHasher.max_hash_length` and
:attr:`~pwhash.PasswordHasher.min_hash_length`. You can use these to either get
an upper bound directly or calculate it yourself if you use hashers whose hash
length depends on application specific factors like the password length.

In practice this means that everytime pwhash is updated or you update your
configuration you possibly need to run database migrations.
