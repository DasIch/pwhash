Versioning
==========

pwhash versions allow for three different kinds of releases: major, minor and
bugfix releases that are encoded as `major.minor.bugfix` in the version. Each
type of release makes it possible to quickly ascertain which kinds of changes
have been made and how that affects compatibilty.

Major releases are made whenever a backwards incompatible change has been
introduced, minor releases are made whenever a new feature has been introduced
and bugfix releases are made whenever a bugfix has been introduced.

In other words when using pwhash make sure to declare it as a dependency in a
way that prevents the install mechanism to use a different pwhash version it
was intended for. If you want to support multiple major releases you should run
your tests with both.

Maintenance
-----------

Which versions are maintained or supported is decided based on a simple set of
rules:

1. Bugfix releases are made for all supported minor versions.
2. The latest minor versions of all supported major versions are supported.
3. Minor releases are made for the latest major version.
4. The latest major version is supported.
5. The major version prior to the last major version is supported at most until
   a minor release has been made.
