# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every install hint names an install that resolves to the ASH that is running.

Why this file exists
--------------------
ASH is not published to PyPI, and the PyPI project with ASH's distribution name
is unrelated, so a hint that asks an index for that name installs the wrong
project. The first fix pinned every hint to the git tag ``v<version>``. That is
wrong on every build between releases: main reports 3.7.0 while its tree has
moved on, and ``v3.7.0`` has no ``symbols`` extra at all, so the symbols hint
asked for an extra the tag does not define and the reinstall hints downgraded
a main install to the release.

What the hints name now
-----------------------
* The symbols hint names the extra's packages, read from the running
  distribution's own metadata, so it cannot disagree with the installed ASH.
* The reinstall hints name where the running ASH was installed from, as the
  installer recorded it in the PEP 610 ``direct_url.json``: the commit of a git
  install, the directory of an editable or local install, the archive of an
  archive install. Only an install with no record falls back to the release tag
  of its version, and an unknown version to the repository without a ref.

``ash_install._direct_url`` is the one seam the shape tests replace; every
other step, including the quoting and the extra, runs for real.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from importlib.metadata import distribution
from pathlib import Path
from unittest.mock import patch
from urllib.request import url2pathname

import pytest
import typer

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.utils import ash_install
from automated_security_helper.utils.get_ash_version import get_ash_version
from tests.utils.bare_install_names import find_bare_installs, normalize
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMIT = "0123456789abcdef0123456789abcdef01234567"  # pragma: allowlist secret
GIT_INSTALL = {
    "url": "https://github.com/awslabs/automated-security-helper.git",
    "vcs_info": {"vcs": "git", "commit_id": COMMIT, "requested_revision": "main"},
}
WHEEL_NAME = "automated_security_helper-3.7.0-py3-none-any.whl"
#: Every printed command installs with the interpreter that runs ASH and the uv
#: it depends on, into that same interpreter's environment.
#: The hint's fixed head: the running interpreter, with -P where it accepts it
#: (3.11 and later), `-m uv pip install --no-config`, and the interpreter again as
#: the target environment.
UV_PIP = [
    sys.executable,
    *(["-P"] if sys.version_info >= (3, 11) else []),
    "-m",
    "uv",
    "pip",
    "install",
    "--no-config",
    "--python",
    sys.executable,
]
REINSTALL = [*UV_PIP, "--reinstall-package", "automated-security-helper"]
REMOTE_WHEEL_INSTALL = {
    "url": "https://example.invalid/automated_security_helper-3.7.0-py3-none-any.whl",
    "archive_info": {},
}


def _editable(path: Path) -> dict:
    return {"url": path.as_uri(), "dir_info": {"editable": True}}


def _local_directory(path: Path) -> dict:
    return {"url": path.as_uri(), "dir_info": {}}


def _local_wheel(path: Path) -> dict:
    return {"url": path.as_uri(), "archive_info": {}}


@pytest.fixture
def checkout(tmp_path) -> Path:
    """A directory an editable or local install was made from, still present."""
    path = tmp_path / "automated-security-helper"
    path.mkdir()
    return path


@pytest.fixture
def wheel(tmp_path) -> Path:
    """A local wheel an archive install was made from, still present."""
    path = tmp_path / "dist" / WHEEL_NAME
    path.parent.mkdir()
    path.write_bytes(b"PK")
    return path


@pytest.fixture
def records(checkout, wheel) -> dict:
    """Every record shape, by name, with local paths that exist."""
    return {
        "git": GIT_INSTALL,
        "editable": _editable(checkout),
        "local-directory": _local_directory(checkout),
        "local-archive": _local_wheel(wheel),
        "remote-archive": REMOTE_WHEEL_INSTALL,
        "no-record": None,
    }


@pytest.fixture(autouse=True)
def _fresh_symbols_command():
    """The symbols command is built once per process; these tests vary its inputs."""
    from automated_security_helper.utils import symbol_spans

    clear = getattr(symbol_spans.symbols_extra_install_command, "cache_clear", None)
    if clear is not None:
        clear()
    yield
    if clear is not None:
        clear()


def _origin(monkeypatch, direct_url, version=None):
    monkeypatch.setattr(ash_install, "_direct_url", lambda: direct_url)
    if version is not None:
        monkeypatch.setattr(ash_install, "get_ash_version", lambda: version)


def _words(command: str) -> list[str]:
    return shlex.split(command)


@pytest.mark.unit
class TestReinstallNamesWhereThisAshCameFrom:
    def test_a_git_install_is_pinned_to_its_commit(self, monkeypatch):
        _origin(monkeypatch, GIT_INSTALL, version="3.7.0")
        command = ash_install.ash_reinstall_command()
        assert _words(command) == [*REINSTALL, f"git+{GIT_INSTALL['url']}@{COMMIT}"]
        assert "@v3.7.0" not in command

    def test_a_git_install_keeps_its_subdirectory(self, monkeypatch):
        _origin(monkeypatch, {**GIT_INSTALL, "subdirectory": "pkg"})
        assert _words(ash_install.ash_install_arguments())[-1].endswith(
            f"@{COMMIT}#subdirectory=pkg"
        )

    @pytest.mark.parametrize(
        "recorded, printed",
        [
            (
                "https://user:token@github.example/ash.git",  # pragma: allowlist secret
                "https://github.example/ash.git",
            ),
            (
                "https://u:t@host.example:8443/r.git",
                "https://host.example:8443/r.git",
            ),
            ("https://u:t@[::1]:8443/r.git", "https://[::1]:8443/r.git"),
            # The ssh user is how the remote is addressed, not a credential.
            ("ssh://git@github.com/o/r.git", "ssh://git@github.com/o/r.git"),
        ],
        ids=["user-and-token", "port", "ipv6-and-port", "ssh-git-user"],
    )
    def test_credentials_in_a_recorded_url_are_not_repeated(
        self, monkeypatch, recorded, printed
    ):
        """PEP 610 tells installers to strip them; a hint must not depend on that."""
        _origin(monkeypatch, {**GIT_INSTALL, "url": recorded})
        command = ash_install.ash_reinstall_command()
        assert _words(command)[-1] == f"git+{printed}@{COMMIT}", command
        assert "u:t@" not in command and "user:token" not in command, command

    @pytest.mark.parametrize(
        "shape", [_editable, _local_directory], ids=lambda f: f.__name__
    )
    def test_a_path_with_a_space_and_brackets_is_quoted_for_a_shell(
        self, monkeypatch, tmp_path, shape
    ):
        """A shell reads the printed command back to the same words.

        zsh treats an unquoted ``[dev]`` as a glob and refuses the command, and a
        space splits the path in two.
        """
        checkout = tmp_path / "a b[dev]"
        checkout.mkdir()
        _origin(monkeypatch, shape(checkout))
        for command in (
            ash_install.ash_reinstall_command(),
            f"pip install {ash_install.ash_install_arguments('symbols')}",
        ):
            assert shlex.join(_words(command)) == command, command
            assert any(str(checkout) in word for word in _words(command)), command

    def test_an_editable_install_names_its_directory(self, monkeypatch, checkout):
        _origin(monkeypatch, _editable(checkout), version="3.7.0")
        assert _words(ash_install.ash_reinstall_command()) == [
            *REINSTALL,
            "-e",
            str(checkout),
        ]

    def test_a_local_directory_install_names_its_directory(self, monkeypatch, checkout):
        _origin(monkeypatch, _local_directory(checkout), version="3.7.0")
        assert _words(ash_install.ash_install_arguments()) == [str(checkout)]

    def test_a_local_archive_install_names_its_archive(self, monkeypatch, wheel):
        _origin(monkeypatch, _local_wheel(wheel), version="3.7.0")
        assert _words(ash_install.ash_install_arguments()) == [wheel.as_uri()]

    @pytest.mark.parametrize(
        "shape", [_editable, _local_directory, _local_wheel], ids=lambda f: f.__name__
    )
    def test_a_local_path_that_is_gone_falls_back_to_the_release_tag(
        self, monkeypatch, tmp_path, shape
    ):
        """A recorded local source that no longer exists is not named.

        The container image installs ASH from a wheel and then deletes it, so a
        reinstall naming that wheel cannot work. No commit is recorded for a
        wheel install (assets/ASH_INSTALLED_REVISION holds a branch name), so
        the release tag of the running version is the remaining source.
        """
        gone = tmp_path / "deleted" / WHEEL_NAME
        _origin(monkeypatch, shape(gone), version="3.9.1")
        for extra, expected in (
            (None, f"git+{ASH_REPO_URL}.git@v3.9.1"),
            ("cdk", f"automated-security-helper[cdk] @ git+{ASH_REPO_URL}.git@v3.9.1"),
        ):
            arguments = ash_install.ash_install_arguments(extra)
            assert _words(arguments) == [expected], arguments
            assert str(gone) not in arguments

    def test_a_remote_archive_install_names_its_url(self, monkeypatch):
        _origin(monkeypatch, REMOTE_WHEEL_INSTALL, version="3.7.0")
        assert _words(ash_install.ash_install_arguments()) == [
            REMOTE_WHEEL_INSTALL["url"]
        ]

    @pytest.mark.parametrize(
        "recorded, printed",
        [
            ("https://example.invalid/a.whl", "https://example.invalid/a.whl"),
            ("http://example.invalid/a.whl", "http://example.invalid/a.whl"),
            ("https://u:t@example.invalid/a.whl", "https://example.invalid/a.whl"),
            # A scheme is case-insensitive (RFC 3986, section 3.1), but uv reads
            # `HTTPS://host/a.whl` as a relative path, so it is printed lowercase.
            ("HTTPS://example.invalid/a.whl", "https://example.invalid/a.whl"),
            ("HtTp://example.invalid/a.whl", "http://example.invalid/a.whl"),
        ],
        ids=["https", "http", "credentials", "upper-case", "mixed-case"],
    )
    def test_a_remote_archive_over_http_is_named_in_a_form_uv_reads(
        self, monkeypatch, recorded, printed
    ):
        _origin(monkeypatch, {"url": recorded, "archive_info": {}}, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [printed]
        assert _words(ash_install.ash_install_arguments("symbols")) == [
            f"automated-security-helper[symbols] @ {printed}"
        ]

    @pytest.mark.parametrize(
        "recorded",
        [
            "ftp://example.invalid/a.whl",
            "data:application/zip;base64,UEsFBgAAAAAAAAAAAAAAAAAAAAAAAA==",
            "git+https://example.invalid/a.whl",
            "//example.invalid/a.whl",
            "a.whl",
            "https:///a.whl",
            "https://example.invalid:99999/a.whl",
            "https://u:t@example.invalid:99999/a.whl",
            "https://[::1/a.whl",
        ],
        ids=[
            "ftp",
            "data",
            "vcs-scheme",
            "no-scheme",
            "relative-path",
            "no-host",
            "port-out-of-range",
            "port-out-of-range-with-credentials",
            "unterminated-ipv6-host",
        ],
    )
    def test_a_remote_archive_uv_cannot_fetch_falls_back_to_the_release_tag(
        self, monkeypatch, recorded
    ):
        """Only an http or https URL with a host and a valid port is named.

        uv refuses every one of these (measured with uv 0.12.22: a parse error,
        or the URL read as a relative path), so naming it would print a command
        that cannot work. None of them may raise either: the hint is built while
        a scan or ``ash mcp`` reports something else.
        """
        _origin(monkeypatch, {"url": recorded, "archive_info": {}}, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]

    def test_a_local_archive_url_in_upper_case_is_named_as_this_hosts_file_url(
        self, monkeypatch, wheel
    ):
        """A ``file:`` archive is named by its path here, never as recorded."""
        recorded = "FILE" + wheel.as_uri()[len("file") :]
        _origin(monkeypatch, {"url": recorded, "archive_info": {}}, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [wheel.as_uri()]

    def test_a_local_archive_url_naming_a_directory_falls_back_to_the_release_tag(
        self, monkeypatch, checkout
    ):
        _origin(monkeypatch, _local_wheel(checkout), version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]

    def test_an_install_with_no_record_falls_back_to_the_release_tag(self, monkeypatch):
        _origin(monkeypatch, None, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]

    def test_an_unknown_version_with_no_record_names_no_ref(self, monkeypatch):
        """get_version() returns "unknown" when it cannot read a version.

        There is no tag ``vunknown``; the URL without a ref installs the default
        branch, which is the closest working install there is.
        """
        _origin(monkeypatch, None, version="unknown")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git"
        ]

    @pytest.mark.parametrize(
        "record",
        [
            {"url": "https://example.invalid/x", "vcs_info": {"vcs": "git"}},
            {"url": 7, "dir_info": {}},
            {"dir_info": {"editable": True}},
            {"url": "https://example.invalid/dir", "dir_info": {}},
            ["not", "a", "mapping"],
            {**GIT_INSTALL, "url": "https://u:t@example.invalid:99999/r.git"},
            {**GIT_INSTALL, "url": "https://[::1/r.git"},
        ],
        ids=[
            "vcs-without-commit",
            "url-not-a-string",
            "no-url",
            "remote-dir",
            "list",
            "vcs-port-out-of-range",
            "vcs-unterminated-ipv6-host",
        ],
    )
    def test_an_unusable_record_falls_back_to_the_release_tag(
        self, monkeypatch, record
    ):
        _origin(monkeypatch, record, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]


@pytest.mark.unit
class TestTwoDistributionsProvideThisModule:
    """The first distribution located for this module decides which record is read.

    Two distributions provide ``automated_security_helper`` when, for example, a
    fork is installed beside ASH or an older dist-info was left behind. The
    second one's record describes another install, so naming it could reinstall
    a different tree. Whatever the first one gives decides: its record, or no
    record when it has none, when it does not parse, or when it cannot be read,
    and then the hint falls back to the release tag.
    """

    SIBLING = json.dumps(GIT_INSTALL)

    @staticmethod
    def _located(monkeypatch, first):
        """``first`` and then a sibling with a git record provide this module.

        ``first`` is the text of the first one's direct_url.json, None for no
        file, or an exception: PackageNotFoundError is raised looking the
        distribution up, anything else reading the file.
        """
        texts = {
            "first-dist": first,
            "sibling-dist": TestTwoDistributionsProvideThisModule.SIBLING,
        }

        class _Distribution:
            def __init__(self, name):
                self.name = name

            def read_text(self, filename):
                assert filename == "direct_url.json", filename
                text = texts[self.name]
                if isinstance(text, Exception):
                    raise text
                return text

        def lookup(name):
            if isinstance(texts[name], ash_install.PackageNotFoundError):
                raise texts[name]
            return _Distribution(name)

        monkeypatch.setattr(
            ash_install,
            "_distributions_declaring_this_module",
            lambda _root: list(texts),
        )
        monkeypatch.setattr(ash_install, "distribution", lookup)
        monkeypatch.setattr(ash_install, "get_ash_version", lambda: "3.9.1")

    @pytest.mark.parametrize(
        "first",
        [
            None,
            "",
            "{not json",
            ash_install.PackageNotFoundError("first-dist"),
            PermissionError("direct_url.json"),
        ],
        ids=["no-record", "empty-record", "unparsable", "not-found", "unreadable"],
    )
    def test_the_first_distribution_without_a_usable_record_gives_none(
        self, monkeypatch, first
    ):
        self._located(monkeypatch, first)
        assert ash_install._direct_url() is None
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]

    def test_the_first_distributions_record_is_read_not_the_siblings(self, monkeypatch):
        first = {
            **GIT_INSTALL,
            "vcs_info": {**GIT_INSTALL["vcs_info"], "commit_id": "f" * 40},
        }
        self._located(monkeypatch, json.dumps(first))
        assert ash_install._direct_url() == first
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{GIT_INSTALL['url']}@{'f' * 40}"
        ]


@pytest.mark.unit
class TestAnExtraGoesOnTheSameSource:
    @pytest.mark.parametrize(
        "shape, expected",
        [
            (
                "git",
                [f"automated-security-helper[cdk] @ git+{GIT_INSTALL['url']}@{COMMIT}"],
            ),
            ("editable", ["-e", "{checkout}[cdk]"]),
            ("local-directory", ["{checkout}[cdk]"]),
            ("local-archive", ["automated-security-helper[cdk] @ {wheel_url}"]),
            (
                "remote-archive",
                [f"automated-security-helper[cdk] @ {REMOTE_WHEEL_INSTALL['url']}"],
            ),
            (
                "no-record",
                [f"automated-security-helper[cdk] @ git+{ASH_REPO_URL}.git@v3.9.1"],
            ),
        ],
    )
    def test_each_source_takes_the_extra(
        self, monkeypatch, records, checkout, wheel, shape, expected
    ):
        _origin(monkeypatch, records[shape], version="3.9.1")
        arguments = ash_install.ash_install_arguments("cdk")
        assert _words(arguments) == [
            word.format(checkout=checkout, wheel_url=wheel.as_uri())
            for word in expected
        ]
        assert find_bare_installs(f"pip install {arguments}") == []


@pytest.mark.unit
@pytest.mark.parametrize(
    "shape",
    [
        "git",
        "editable",
        "local-directory",
        "local-archive",
        "remote-archive",
        "no-record",
    ],
)
@pytest.mark.parametrize(
    "template",
    [
        "pip install {}",
        "pip install --force-reinstall {}",
        "pipx install {}",
        "uv tool install {}",
    ],
)
def test_every_installer_form_resolves_to_ash(monkeypatch, records, shape, template):
    _origin(monkeypatch, records[shape], version="3.7.0")
    for extra in (None, "symbols"):
        command = template.format(ash_install.ash_install_arguments(extra))
        assert find_bare_installs(command) == [], command


@pytest.mark.unit
def test_this_installation_is_reinstalled_from_its_own_record():
    """The real environment, read without the seam.

    The test suite runs from an installed checkout, so the distribution carries a
    direct_url.json. Whatever it records, the hint must name it and must not
    fall back to the release tag, which on main names an older tree.
    """
    raw = distribution("automated-security-helper").read_text("direct_url.json")
    assert raw, "the suite is expected to run from an installed checkout"
    record = json.loads(raw)
    command = ash_install.ash_reinstall_command()
    assert f"@v{get_ash_version()}" not in command, command
    if "vcs_info" in record:
        expected = record["vcs_info"]["commit_id"]
    else:
        expected = str(Path(url2pathname(record["url"].removeprefix("file://"))))
    assert any(expected in word for word in _words(command)), (expected, command)


@pytest.mark.unit
def test_distributions_are_found_from_their_record_on_every_python():
    """ASH's distribution is found by what it installed, not by top_level.txt.

    On Python 3.10 the standard library's ``packages_distributions()`` reads only
    ``top_level.txt``, and hatchling writes none, so on 3.10 a non-editable
    install (a wheel, ``pip install git+...``, ``uv tool install``, uvx) was not
    found and every hint fell back to the release tag. The ``importlib_metadata``
    backport, already a dependency, also reads RECORD. Runners on 3.11 and later
    cannot observe the difference, so this pins the function in use; the
    behavior on 3.10 is measured by
    tests/integration/test_install_hints_on_python310.py.
    """
    import importlib_metadata

    assert (
        ash_install.packages_distributions is importlib_metadata.packages_distributions
    )


@pytest.mark.unit
class TestExtraRequirementsFromMetadata:
    def test_the_symbols_extra_is_read_from_this_distribution(self):
        declared = ash_install.extra_requirements_from_metadata("symbols")
        assert declared, "the symbols extra could not be read from metadata"
        names = {normalize(re.match(r"[A-Za-z0-9._-]+", r).group(0)) for r in declared}
        assert "tree-sitter" in names and "tree-sitter-python" in names, declared
        assert all(";" not in r for r in declared), declared

    def test_the_cdk_scanner_reads_its_extra_through_the_same_function(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _cdk_extra_requirements_from_metadata,
        )

        assert _cdk_extra_requirements_from_metadata() == (
            ash_install.extra_requirements_from_metadata("cdk")
        )

    def test_an_extra_no_distribution_declares_reads_as_none(self):
        assert ash_install.extra_requirements_from_metadata("no-such-extra") is None

    def test_an_extra_name_is_matched_whole(self):
        """``extra == 'cdk'`` must not be read as part of ``extra == 'cdk2'``."""
        declared = [
            "a>=1; extra == 'cdk2'",
            'b>=1; extra == "cdk"',
            "c>=1; extra=='cdk'",
        ]
        # The requirements are read through the located distribution's own
        # object (_requirements_declared), not the by-name ``requires`` call,
        # so the fake sits at that seam; a located name is given too, so the
        # read runs the same where ASH is not installed as a distribution.
        with (
            patch.object(
                ash_install,
                "_distributions_declaring_this_module",
                return_value=["automated-security-helper"],
            ),
            patch.object(
                ash_install, "_requirements_declared", return_value=[declared]
            ),
        ):
            assert ash_install.extra_requirements_from_metadata("cdk") == [
                "b>=1",
                "c>=1",
            ]


class TestTheSymbolsHint:
    @pytest.mark.unit
    def test_it_names_the_packages_of_the_installed_extra(self, monkeypatch):
        """No tag, no ASH name: v3.7.0 has no symbols extra, main reports 3.7.0."""
        from automated_security_helper.utils.symbol_spans import (
            SYMBOLS_EXTRA,
            symbols_extra_install_command,
        )

        _origin(monkeypatch, None, version="3.7.0")
        command = symbols_extra_install_command()
        declared = ash_install.extra_requirements_from_metadata(SYMBOLS_EXTRA)
        assert _words(command)[: len(UV_PIP)] == UV_PIP, command
        assert _words(command)[len(UV_PIP) :] == declared, command
        # The exact text, quoted for a shell: every requirement holds `<` or `>`,
        # which an unquoted command turns into a redirection.
        assert command == shlex.join([*UV_PIP, *declared]), command
        # The requirements, not the interpreter path in front of them, which holds the
        # checkout's directory name wherever that is called automated-security-helper.
        requirements = _words(command)[len(UV_PIP) :]
        assert not any("automated-security-helper" in word for word in requirements)
        assert "@v" not in command
        assert find_bare_installs(command) == []

    @pytest.mark.unit
    def test_without_readable_metadata_it_falls_back_to_this_install(self, monkeypatch):
        from automated_security_helper.utils.symbol_spans import (
            symbols_extra_install_command,
        )

        _origin(monkeypatch, GIT_INSTALL)
        monkeypatch.setattr(
            ash_install, "extra_requirements_from_metadata", lambda extra: None
        )
        assert _words(symbols_extra_install_command()) == [
            *UV_PIP,
            f"automated-security-helper[symbols] @ git+{GIT_INSTALL['url']}@{COMMIT}",
        ]

    @pytest.mark.integration
    @pytest.mark.runs_real_tools(
        reason="a dry run of the printed command through the real uv, against "
        "this environment, is what this test checks"
    )
    def test_the_printed_command_reaches_this_environment(self, tmp_path):
        """The command installs into the environment ASH runs in, wherever that is.

        uv environments have no pip, so a bare ``pip`` runs whatever pip comes next
        on PATH, often another Python's. Here the extra is installed, so a dry run
        of the printed command against this environment changes nothing.
        """
        from automated_security_helper.utils.symbol_spans import (
            symbols_extra_install_command,
        )

        words = _words(symbols_extra_install_command())
        assert words[: len(UV_PIP)] == UV_PIP, words
        dry_run = [*words[: len(UV_PIP)], "--dry-run", *words[len(UV_PIP) :]]
        result = subprocess.run(
            dry_run,
            capture_output=True,
            text=True,
            # uv's cache outside the test's HOME, which the unit tests' tool
            # guard reads after the test.
            env={
                **os.environ,
                "UV_OFFLINE": "1",
                "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
            },
            check=False,
            timeout=CHILD_TIMEOUT_SECONDS,
        )
        assert result.returncode == 0, result.stderr
        assert "Would make no changes" in result.stderr, result.stderr

    @pytest.mark.unit
    def test_it_points_at_the_docs_for_uvx(self, monkeypatch):
        """uvx runs ASH from a cached environment; its users need the docs page."""
        from automated_security_helper.utils.symbol_spans import (
            symbols_extra_install_command,
            symbols_extra_install_hint,
        )

        url = f"{ASH_DOCS_URL}/docs/suppressions/#installing-the-extra"
        hint = symbols_extra_install_hint()
        assert url in hint, hint
        assert f"`{symbols_extra_install_command()}`" in hint, hint
        assert find_bare_installs(hint) == []
        # The docs rewrite moved the suppressions page to how-to/suppress-findings.md;
        # docs/redirects.yml sends the old URL in the hint to it, and the section's
        # explicit anchor keeps the fragment working.
        page = REPO_ROOT / "docs" / "content" / "how-to" / "suppress-findings.md"
        assert "\n### Installing the extra {#installing-the-extra}\n" in page.read_text(
            encoding="utf-8"
        )


def _name_and_clauses(requirement: str) -> tuple[str, frozenset[str]]:
    """A requirement as its normalized name and its unordered specifier clauses.

    importlib.metadata reorders clauses: ``>=0.26,<0.27`` comes back as
    ``<0.27,>=0.26``.
    """
    name = re.match(r"[A-Za-z0-9._-]+", requirement).group(0)
    clauses = requirement[len(name) :].split(",")
    return normalize(name), frozenset(c.strip() for c in clauses if c.strip())


@pytest.mark.unit
def test_the_suppressions_page_lists_the_packages_of_the_extra():
    """The docs page's install command installs what the metadata declares.

    It is a copy of the extra, so it is checked against the running
    distribution's metadata rather than trusted to stay current.
    """
    page = REPO_ROOT / "docs" / "content" / "how-to" / "suppress-findings.md"
    text = page.read_text(encoding="utf-8")
    section = text.split("### Installing the extra {#installing-the-extra}", 1)[1]
    section = section.split("\n## ", 1)[0].split("\n### ", 1)[0]
    # The form the hint prints, with the interpreter as a placeholder (and
    # without the -P the hint adds on 3.11 and later, which the page does not
    # tie to a version).
    prefix = "<python> -m uv pip install --no-config --python <python> "
    pip_lines = [line for line in section.splitlines() if line.startswith(prefix)]
    assert len(pip_lines) == 1, pip_lines
    documented = {
        _name_and_clauses(r) for r in shlex.split(pip_lines[0][len(prefix) :])
    }
    declared = ash_install.extra_requirements_from_metadata("symbols")
    assert declared, "the symbols extra could not be read from metadata"
    assert documented == {_name_and_clauses(r) for r in declared}


#: The first release whose pyproject.toml defines the ``symbols`` extra, as a
#: version tuple. None until one is tagged: v3.7.0 and v3.7.1 define only
#: ``cdk``. Set it when that release ships; docs may then pin it or a later one.
FIRST_RELEASE_WITH_SYMBOLS: tuple[int, ...] | None = None

_SYMBOLS_PIN = re.compile(r"\[symbols\][^\n]*?@v(\d+(?:\.\d+)*)")


@pytest.mark.unit
def test_no_docs_page_pins_the_symbols_extra_to_a_release_without_it():
    """A ``[symbols]`` requirement pinned to a tag must name a tag that has it.

    Asking a release for an extra it does not define installs that release
    without it (uv and pip only warn), so the command does nothing for symbol
    suppressions while replacing the ASH it runs on.
    """
    pages = [
        *sorted((REPO_ROOT / "docs").rglob("*.md")),
        *sorted((REPO_ROOT / "docs").rglob("*.md.template")),
        REPO_ROOT / "README.md",
        REPO_ROOT / "README.md.template",
    ]
    pins = [
        (page.relative_to(REPO_ROOT).as_posix(), match.group(1))
        for page in pages
        for match in _SYMBOLS_PIN.finditer(page.read_text(encoding="utf-8"))
    ]
    if FIRST_RELEASE_WITH_SYMBOLS is None:
        assert pins == [], pins
        page = REPO_ROOT / "docs" / "content" / "how-to" / "suppress-findings.md"
        assert "next release" in page.read_text(encoding="utf-8")
    else:
        too_old = [
            (path, pin)
            for path, pin in pins
            if tuple(int(part) for part in pin.split(".")) < FIRST_RELEASE_WITH_SYMBOLS
        ]
        assert too_old == [], too_old


@pytest.mark.unit
@pytest.mark.parametrize("shape", ["git", "editable-with-space-and-brackets"])
def test_the_mcp_reinstall_hint_names_this_install_on_one_line(
    capsys, monkeypatch, tmp_path, shape
):
    """``ash mcp`` without its dependencies prints a reinstall that resolves to ASH.

    stderr is usually not a terminal when an MCP client runs the server, and
    rich wraps non-terminal output at 80 columns. A wrap before the source
    leaves an install command with no requirement on the first line, so the whole
    command has to stay on one line. A path holding ``[dev]`` must print as is:
    rich reads an unescaped ``[dev]`` as markup and drops it.
    """
    from rich.console import Console

    from automated_security_helper.cli import mcp as mcp_module
    from automated_security_helper.cli.mcp import mcp_command

    checkout = tmp_path / "a b[dev]"
    checkout.mkdir()
    record, source = {
        "git": (GIT_INSTALL, [f"git+{GIT_INSTALL['url']}@{COMMIT}"]),
        "editable-with-space-and-brackets": (
            _editable(checkout),
            ["-e", str(checkout)],
        ),
    }[shape]
    _origin(monkeypatch, record)
    # The width rich uses when stderr is not a terminal. Set on the console
    # itself: rich reads COLUMNS once, when the module creates the console.
    monkeypatch.setattr(mcp_module, "_stderr", Console(stderr=True, width=80))
    with patch(
        "automated_security_helper.cli.mcp.validate_mcp_dependencies",
        return_value=False,
    ):
        with pytest.raises(typer.Exit):
            mcp_command(_Context())

    # FORCE_COLOR in the environment makes rich emit color codes, which sit
    # between the words of the command; the text a user reads is what is checked.
    err = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().err)
    reinstall = [line for line in err.splitlines() if "--reinstall-package" in line]
    assert len(reinstall) == 2, err
    assert find_bare_installs(reinstall[0]) == [], reinstall[0]
    assert _words(reinstall[0]) == [*REINSTALL, *source], reinstall[0]
    # For a checkout: the same sync the MCP testing guide gives, which keeps the
    # extras installed there; a plain `uv sync` removes them.
    assert _words(reinstall[1]) == [
        "uv",
        "sync",
        "--inexact",
        "--reinstall-package",
        "automated-security-helper",
    ], reinstall[1]


class _Context:
    """The one attribute of typer's context that ``mcp_command`` reads first."""

    resilient_parsing = False
