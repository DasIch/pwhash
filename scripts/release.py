#!/usr/bin/env python
# coding: utf-8
"""
    release
    ~~~~~~~

    :copyright: 2013 by Daniel Neuhäuser
    :license: BSD, see LICENSE.rst for details
"""
import os
import re
import sys
import errno
import shutil
import logging
import textwrap
import posixpath
import subprocess
from tempfile import NamedTemporaryFile
from contextlib import nested
from StringIO import StringIO as StringIOBase

import docopt
import requests


FORCE = False
PROJECT_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.path.pardir)
)

changelog_version_re = re.compile(r"^Version (\d+\.\d+.\d+)$")
version_re = re.compile(r"^(__version__\s*=\s*[\"'])(.+?)([\"'])$")
version_info_re = re.compile(r"^(__version_info__\s*=\s*)(.+?)$")


def fail(message, *args, **kwargs):
    """
    Should be used to report errors that do not prevent execution, may fail
    with exit code 1.
    """
    logging.error(message, *args)
    if not FORCE:
        sys.exit(1)


def panic(message, *args):
    """
    Should be used to report errors that prevent execution, fails with exit
    code 1.
    """
    logging.fatal(message, *args)
    sys.exit(1)


class Version(object):
    """
    Represents a version as used by pwhash.
    """

    @classmethod
    def from_string(cls, string):
        """
        Returns a :class:`Version` object from a string in the form
        ``\d+.\d+.\d+(-.+)?``.
        """
        parts = string.split("-", 1)
        if len(parts) == 2:
            numbers, tag = parts
        else:
            numbers, tag = parts[0], None
        major, minor, bugfix = numbers.split(".")
        return cls(int(major), int(minor), int(bugfix), tag)

    def __init__(self, major, minor, bugfix, tag=None):
        self.major = major
        self.minor = minor
        self.bugfix = bugfix
        self.tag = tag

    def to_string(self, release=True):
        """
        Returns the version as string, if `release` is `True` `bugfix` is
        included.
        """
        if release:
            result = "%d.%d.%d" % (self.major, self.minor, self.bugfix)
        else:
            result = "%d.%d" % (self.major, self.minor)
        if self.tag is not None:
            result += "-" + self.tag
        return result

    def to_info(self):
        """
        Returns the version as version info string ``(major, minor, bugfix)``.
        """
        return str((self.major, self.minor, self.bugfix))

    def bumped(self, type="bugfix", tag=None):
        """
        Returns a new :class:`Version` object with either `major`, `minor` or
        `bugfix` increased by one or `tag` changed, depending on the value of
        `type`.
        """
        major, minor, bugfix = self.major, self.minor, self.bugfix
        if type == "major":
            major += 1
        elif type == "minor":
            minor += 1
        elif type == "bugfix":
            bugfix += 1
        else:
            raise ValueError("invalid type: %r" % type)
        return self.__class__(
            major, minor, bugfix, self.tag if tag is None else tag
        )

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return "%s(%r, %r, %r, tag=%r)" % (
            self.__class__.__name__, self.major, self.minor, self.bugfix, self.tag
        )


class StringIO(StringIOBase):
    """
    A :class:`StringIO.StringIO` variant that can be used as a context manager.
    """
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        self.close()


class Git(object):
    """
    Represents a git repository and provides some useful utilities in dealing
    with one.
    """
    def __init__(self, repository_path, dry_run=False):
        self.repository_path = repository_path
        self.dry_run = dry_run

    def start_process(self, command, **kwargs):
        return subprocess.Popen(command,
            cwd=self.repository_path,
            **kwargs
        )

    def get_is_clean(self):
        """
        Returns True if there are no modified or untracked files.
        """
        process = self.start_process(
            ["git", "status", "--porcelain"],
            stdout=subprocess.PIPE
        )
        stdout, _ = process.communicate()
        if process.returncode != 0:
            fail("git failure while checking cleanliness")
        return not bool(stdout)

    def get_tags(self):
        """
        Returns the names of all tags.
        """
        process = self.start_process(["git", "tag"], stdout=subprocess.PIPE)
        stdout, _ = process.communicate()
        if process.returncode != 0:
            fail("git failure while retrieving tags")
        return set(stdout.splitlines())

    def get_branch(self):
        """
        Returns the name of the current branch.
        """
        process = self.start_process(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stdout=subprocess.PIPE
        )
        stdout, _ = process.communicate()
        if process.returncode != 0:
            fail("git failure retrieving branch")
        return stdout.strip()

    def get_branches(self):
        """
        Returns a set with the names of all branches.
        """
        process = self.start_process(
            ["git", "for-each-ref", "--format", "%(refname:short)s", "refs/heads"],
            stdout=subprocess.PIPE
        )
        stdout, _ = process.communicate()
        if process.returncode != 0:
            fail("git failure retrieving branches")
        return set(stdout.splitlines())

    def get_current_commit(self):
        """
        Returns a hash identifying the current commit.
        """
        process = self.start_process(
            ["git", "rev-parse", "--verify", "HEAD"],
            stdout=subprocess.PIPE
        )
        stdout, _ = process.communicate()
        if process.returncode != 0:
            fail("git failure retrieving current commit")
        return stdout.strip()

    def get_ignored_files(self, directory=True):
        """
        Yields ignored files. If `directory` is `True` directories
        are included instead of files if they or their contents are ignored.
        """
        command = ["git", "ls-files", "--other"]
        if directory:
            command.append("--directory")
        process = self.start_process(command, stdout=subprocess.PIPE)
        stdout, _ = process.communicate()
        if process.returncode != 0:
            fail("git failure retrieving ignored files")
        for path in stdout.splitlines():
            yield os.path.join(self.repository_path, path)

    def remove_ignored_files(self):
        """
        Removes all ignored files and directories.
        """
        for path in self.get_ignored_files():
            try:
                shutil.rmtree(path)
            except OSError as error:
                if error.errno == errno.ENOTDIR:
                    os.remove(path)
                else:
                    raise

    def tag(self, tag):
        """
        Creates `tag`.
        """
        if not self.dry_run:
            process = self.start_process(["git", "tag", tag])
            if process.wait() != 0:
                fail("git failure while tagging")
        logging.info("tagged: %s", tag)

    def commit(self, message):
        """
        Commits everything with `message`.
        """
        if not self.dry_run:
            process = self.start_process(
                ["git", "commit", "--all", "--message", message]
            )
            if process.wait() != 0:
                fail("git failure while committing")
        logging.info("committed: %s", message)

    def checkout(self, branch):
        """
        Performs a checkout to `branch`.
        """
        if not self.dry_run:
            process = self.start_process(
                ["git", "checkout", "-q", branch]
            )
            if process.wait() != 0:
                fail("git failure while checking out")
        logging.info("checked out: %s", branch)

    def branch(self, branch):
        """
        Creates `branch`.
        """
        if not self.dry_run:
            process = self.start_process(["git", "branch", branch])
            if process.wait() != 0:
                fail("git failure while branching")
        logging.info("branched: %s", branch)


class Travis(object):
    """
    Represents a server providing a travis api.
    """
    def __init__(self, user, repository, host="https://api.travis-ci.org"):
        self.user = user
        self.repository = repository
        self.host = host

    def get(self, path):
        path = path % {
            "user": self.user,
            "repository": self.repository
        }
        return requests.get(posixpath.join(self.host, path.lstrip("/")))

    def get_repo_state(self):
        """
        Returns the current state of the repository as dictionary.
        """
        return self.get("/repos/%(user)s/%(repository)s").json()

    def get_build(self, id):
        """
        Returns the build with `id` as dictionary.
        """
        return self.get("/repos/%(user)s/%(repository)s/builds/" + str(id)).json()

    def get_last_build(self):
        """
        Returns the last build as dictionary.
        """
        repo_state = self.get_repo_state()
        return self.get_build(repo_state["last_build_id"])


def parse_changelog(changelog_path):
    """
    Returns the most recent version from the `CHANGELOG.rst˜ as
    ``(major, minor, bugfix)``. May raise a :exc:`ValueError` if no version can
    be found.
    """
    with open(changelog_path) as f:
        lines = iter(f)
        for line in lines:
            line = line.rstrip()
            match = changelog_version_re.match(line)
            if match is not None and lines.next().rstrip() == "-" * len(line):
                break
        else:
            panic("no version in %s", changelog_path)
        return Version.from_string(match.group(1))


def set_file_version(version_file_path, version, dry_run=False):
    """
    Updates `__version__` and `__version_info__` assignments in
    `version_file_path` to `version`.

    Does not perform any changes on disk if `dry_run` is ``True``.
    """
    result = StringIO()
    with open(version_file_path) as f:
        for line in f:
            version_match = version_re.match(line)
            version_info_match = version_info_re.match(line)
            if version_match is None and version_info_match is None:
                result.write(line)
                continue
            if version_match:
                before, old_version, after = version_match.groups()
                result.write(before)
                result.write(version.to_string())
                result.write(after)
                logging.debug("__version__ replaced")
            elif version_info_match:
                before, old_version_info = match.groups()
                result.write(before)
                result.write(version.to_info())
                logging.debug("__version_info__ replaced")
            else:
                assert False, "should not be reached"
            if line.endswith(os.linesep):
                result.write(os.linesep)

    if not dry_run:
        with open(version_file_path, "w") as f:
            f.write(result.getvalue())
    logging.info("version in %s updated to %s", version_file_path, version)


def run_tox():
    """
    Runs tox in the project directory.
    """
    if subprocess.Popen(["tox"], cwd=PROJECT_DIR).wait() != 0:
        fail("tests failed")


def build_and_upload():
    """
    Build a distribution and upload it to PyPI.
    """
    if subprocess.Popen([sys.executable, "setup.py", "sdist", "upload"]).wait() != 0:
        fail("build or upload failed")


def main(argv=sys.argv):
    """
    usage: release.py [options]

    Options:
      -h, --help           Show this text.
      --final              Do not update to new dev version after release.
      --force              Skip errors that do not prevent further execution,
                           this may lead to unpredictable and very bad results.
      --dry-run            Don't actually do anything.
      --log-level=<LEVEL>  The kind of information to be logged, possible
                           values are debug, info, warning, error and fatal,
                           former kinds include the latter ones. [default: info]
    """
    arguments = docopt.docopt(textwrap.dedent(main.__doc__), argv=argv[1:])

    global FORCE
    FORCE = arguments["--force"]
    dry_run = arguments["--dry-run"]

    try:
        log_level = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "fatal": logging.FATAL
        }[arguments["--log-level"]]
    except KeyError:
        fail("unkown log level: %s", arguments["--log-level"])
        log_level = logging.INFO

    logging.basicConfig(
        format="%(levelname)s: %(message)s",
        level=log_level
    )

    repository = Git(PROJECT_DIR, dry_run)

    if not repository.get_is_clean():
        fail("the repository is dirty")
    if not dry_run:
        repository.remove_ignored_files()

    next_version = parse_changelog(os.path.join(PROJECT_DIR, "CHANGELOG.rst"))

    if next_version.to_string() in repository.get_tags():
        panic("%s is already tagged", next_version)

    logging.info("Releasing %s", next_version)

    branch_name = next_version.to_string(release=False)
    if repository.get_branch() != branch_name:
        if branch_name not in repository.get_branches():
            repository.checkout("master")
            repository.branch(branch_name)
        repository.checkout(branch_name)

    run_tox()

    travis = Travis("DasIch", "pwhash")
    last_build = travis.get_last_build()
    if last_build["commit"] != repository.get_current_commit():
        fail("commit of last build on travis and local commit don't match")
    if last_build["result"] != 0:
        fail("travis build failed")

    set_file_version(
        os.path.join(PROJECT_DIR, "pwhash", "__init__.py"),
        next_version,
        dry_run
    )
    repository.commit("update version number to %s" % next_version)
    repository.tag(next_version.to_string())

    if not dry_run:
        repository.remove_ignored_files()
        build_and_upload()
    logging.info("built and uploaded")

    dev_version = next_version.bumped(tag="dev")
    set_file_version(
        os.path.join(PROJECT_DIR, "pwhash", "__init__.py"),
        dev_version,
        dry_run
    )
    repository.commit("update version number to %s" % dev_version)


if __name__ == "__main__":
    main()
