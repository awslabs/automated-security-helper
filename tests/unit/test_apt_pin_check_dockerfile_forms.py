# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The apt pin check reads every form of install the Dockerfile can spell.

Why this file exists
--------------------
``scripts/check_pinned_tool_versions.py`` promises that an ``apt-get install`` of a
package with no ``=version`` is refused rather than skipped. The reader behind that
promise saw one shape only, and the rest either went unread, so a retired or missing
pin was never reported, or were refused for the wrong reason:

* only an uppercase ``RUN`` started an instruction, only ``apt-get`` was an install,
  an exec-form array and a here-document body were not joined into the command, a
  blank line inside a continuation closed the instruction, and an instruction still
  open at the end of the file was dropped;
* every word after ``install`` that did not start with ``-`` was a package, so the
  value of ``-t suite`` or ``-o Name=value``, a redirection, or the closing quote of
  a command given to ``with-retry '...'`` stopped the whole run with exit 2;
* the Debian codename was the last ``-`` part of the base image tag, so
  ``python:3.12-slim`` and ``debian:bookworm-slim`` named the suite ``slim``;
* ``NODE_MAJOR`` was read only as ``NODE_MAJOR=<digits>`` anywhere in the text, so
  a quoted value, a comment, or no value at all gave the wrong NodeSource index or
  none, and the nodejs pin was then judged against Debian's own nodejs;
* a Debian version was split at the last colon, an index that answered with no
  package stanza was read as an empty archive, and a version dpkg cannot order
  raised out of ``check_apt`` instead of becoming an error result.

No network: the indexes are strings handed to ``check_apt``.
"""

from __future__ import annotations

import importlib.util
import socket
import sys
import urllib.request
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"

CURL = "curl=7.88.1-10+deb12u15"


def _load_script():
    spec = importlib.util.spec_from_file_location(
        "_check_pinned_apt_dockerfile_forms", SCRIPT
    )
    assert spec and spec.loader, f"cannot load {SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_script()


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("a unit test reached the network")

    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", refuse)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", refuse)
    monkeypatch.setattr(urllib.request.FTPHandler, "ftp_open", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def _dockerfile(
    tmp_path: Path,
    body: str,
    base: str = "public.ecr.aws/docker/library/python:3.12-slim-bookworm",
) -> Path:
    """A Dockerfile whose first two lines are the base image; ``body`` starts at 3."""
    path = tmp_path / "Dockerfile"
    path.write_text(
        f"ARG BASE_IMAGE={base}\nFROM ${{BASE_IMAGE}} AS core\n" + body,
        encoding="utf-8",
    )
    return path


def _pins(path: Path) -> dict[str, tuple[str, tuple[int, ...]]]:
    return {p.package: (p.version, p.lines) for p in checker.enumerate_apt_pins(path)}


# ---------------------------------------------------------------------------
# The instruction a pin sits in
# ---------------------------------------------------------------------------


class TestRunInstructionForms:
    def test_a_lowercase_run_is_read(self, tmp_path):
        # Red at the base: only an uppercase RUN started an instruction.
        path = _dockerfile(tmp_path, f"run apt-get install -y {CURL}\n")
        assert _pins(path) == {"curl": ("7.88.1-10+deb12u15", (3,))}

    def test_apt_install_is_an_install(self, tmp_path):
        path = _dockerfile(tmp_path, f"RUN apt install -y {CURL}\n")
        assert set(_pins(path)) == {"curl"}

    def test_an_unpinned_apt_install_is_refused(self, tmp_path):
        path = _dockerfile(tmp_path, "RUN apt install -y git\n")
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            checker.enumerate_apt_pins(path)

    def test_an_exec_form_install_is_read(self, tmp_path):
        path = _dockerfile(
            tmp_path, 'RUN ["apt-get", "install", "-y", "curl=7.88.1-10+deb12u15"]\n'
        )
        assert _pins(path) == {"curl": ("7.88.1-10+deb12u15", (3,))}

    def test_an_exec_form_shell_command_is_read(self, tmp_path):
        path = _dockerfile(
            tmp_path,
            'RUN ["/bin/sh", "-c", "apt-get update && apt-get install -y '
            'curl=7.88.1-10+deb12u15"]\n',
        )
        assert set(_pins(path)) == {"curl"}

    def test_an_unpinned_exec_form_install_is_refused(self, tmp_path):
        path = _dockerfile(tmp_path, 'RUN ["apt-get", "install", "-y", "git"]\n')
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            checker.enumerate_apt_pins(path)

    def test_a_here_document_body_is_read_line_by_line(self, tmp_path):
        body = (
            "RUN <<EOF\n"
            "set -e\n"
            "apt-get update\n"
            f"apt-get install -y {CURL}\n"
            "echo done\n"
            "EOF\n"
        )
        # The install is on line 6, and "echo" and "done" are the next command, not
        # packages of this one.
        assert _pins(_dockerfile(tmp_path, body)) == {
            "curl": ("7.88.1-10+deb12u15", (6,))
        }

    def test_a_comment_in_a_here_document_is_not_an_install(self, tmp_path):
        body = f"RUN <<EOF\n# apt-get install -y git\napt-get install -y {CURL}\nEOF\n"
        assert set(_pins(_dockerfile(tmp_path, body))) == {"curl"}

    def test_an_unpinned_install_in_a_here_document_is_refused(self, tmp_path):
        body = "RUN <<-EOF\n\tapt-get install -y git\nEOF\n"
        with pytest.raises(checker.PinEnumerationError, match="Dockerfile:3 installs"):
            checker.enumerate_apt_pins(_dockerfile(tmp_path, body))

    def test_a_blank_line_inside_a_continuation_does_not_end_the_instruction(
        self, tmp_path
    ):
        # Red at the base: the blank line has no trailing backslash and closed the
        # instruction, so the install after it was never read.
        body = f"RUN apt-get update && \\\n\n    apt-get install -y {CURL}\n"
        assert _pins(_dockerfile(tmp_path, body)) == {
            "curl": ("7.88.1-10+deb12u15", (5,))
        }

    def test_an_instruction_still_open_at_the_end_of_the_file_is_read(self, tmp_path):
        # Red at the base: the block was only kept when a line without a backslash
        # closed it.
        body = f"RUN apt-get install -y {CURL} \\\n"
        assert set(_pins(_dockerfile(tmp_path, body))) == {"curl"}

    def test_a_here_string_is_not_a_here_document(self, tmp_path):
        """Control: ``<<<`` does not swallow the lines that follow it."""
        body = (
            "RUN cat <<<hello\n"
            f"RUN apt-get install -y {CURL}\n"
            "RUN apt-get install -y git=1:2.39.5-0+deb12u3\n"
        )
        assert set(_pins(_dockerfile(tmp_path, body))) == {"curl", "git"}


# ---------------------------------------------------------------------------
# The words after "install"
# ---------------------------------------------------------------------------


class TestInstallArguments:
    @pytest.mark.parametrize(
        "options",
        [
            "-t bookworm-backports",
            "-yt bookworm-backports",
            "--target-release bookworm-backports",
            "-o Dpkg::Options::=--force-confold",
            "--option Acquire::Retries=3",
            "-c /etc/apt/custom.conf",
            "-tbookworm-backports",
            "-oAcquire::Retries=3",
        ],
    )
    def test_the_value_of_an_option_is_not_a_package(self, tmp_path, options):
        # Red at the base for every separate-word form: the value was read as an
        # unpinned package and the run was refused.
        path = _dockerfile(tmp_path, f"RUN apt-get install -y {options} {CURL}\n")
        assert set(_pins(path)) == {"curl"}

    def test_an_attached_option_value_does_not_swallow_the_next_package(self, tmp_path):
        """Control: -tfoo-test is one word, so ``git`` after it is still checked."""
        path = _dockerfile(tmp_path, "RUN apt-get install -tfoo-test git\n")
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            checker.enumerate_apt_pins(path)

    @pytest.mark.parametrize(
        "tail",
        [
            "> /dev/null",
            "2>/dev/null",
            ">> /var/log/install.log",
            "2>&1 | tail -n 1",
        ],
    )
    def test_a_redirection_is_not_a_package(self, tmp_path, tail):
        path = _dockerfile(tmp_path, f"RUN apt-get install -y {CURL} {tail}\n")
        assert set(_pins(path)) == {"curl"}

    @pytest.mark.parametrize("quote", ["'", '"'])
    def test_a_command_quoted_for_a_wrapper_is_read(self, tmp_path, quote):
        body = f"RUN with-retry {quote}apt-get install -y {CURL}{quote}\n"
        assert _pins(_dockerfile(tmp_path, body)) == {
            "curl": ("7.88.1-10+deb12u15", (3,))
        }

    def test_an_unpinned_package_in_a_quoted_command_is_refused_by_name(self, tmp_path):
        path = _dockerfile(tmp_path, "RUN with-retry 'apt-get install -y git'\n")
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            checker.enumerate_apt_pins(path)


# ---------------------------------------------------------------------------
# The indexes
# ---------------------------------------------------------------------------


class TestBaseImageCodename:
    @pytest.mark.parametrize(
        ("base", "codename"),
        [
            ("python:3.12-slim-bookworm", "bookworm"),
            ("debian:bookworm-slim", "bookworm"),
            ("public.ecr.aws/docker/library/python:3.11-slim-bullseye", "bullseye"),
            ("python:3.12-bookworm", "bookworm"),
        ],
    )
    def test_the_codename_is_the_suite_not_the_variant(self, tmp_path, base, codename):
        # Red at the base for debian:bookworm-slim: the last part, "slim", was taken.
        labels = [i.label for i in checker.apt_indexes(_dockerfile(tmp_path, "", base))]
        assert labels[:3] == [codename, f"{codename}-updates", f"{codename}-security"]

    @pytest.mark.parametrize("base", ["python:3.12-slim", "python:3.12-alpine"])
    def test_a_tag_with_only_a_variant_is_refused_as_having_no_codename(
        self, tmp_path, base
    ):
        # Red at the base: "slim" and "alpine" passed as codenames and every index
        # lookup then answered 404.
        with pytest.raises(checker.PinEnumerationError, match="codename"):
            checker.apt_indexes(_dockerfile(tmp_path, "", base))


NODESOURCE = "https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main"


class TestNodeSourceIndex:
    def _labels(self, tmp_path, body):
        return [i.label for i in checker.apt_indexes(_dockerfile(tmp_path, body))]

    def test_a_quoted_node_major_is_read(self, tmp_path):
        # Red at the base: NODE_MAJOR= had to be followed by the digits.
        body = f'RUN NODE_MAJOR="20" && echo "deb {NODESOURCE}"\n'
        assert "nodesource node_20.x" in self._labels(tmp_path, body)

    def test_an_env_instruction_is_read(self, tmp_path):
        body = f"ENV NODE_MAJOR 22\nRUN echo 'deb {NODESOURCE}'\n"
        assert "nodesource node_22.x" in self._labels(tmp_path, body)

    def test_a_comment_does_not_choose_the_major(self, tmp_path):
        # Red at the base: the first NODE_MAJOR= anywhere in the text won.
        body = (
            "# NODE_MAJOR=18 was the old value\n"
            f"RUN NODE_MAJOR=22 && echo 'deb {NODESOURCE}'\n"
        )
        labels = self._labels(tmp_path, body)
        assert "nodesource node_22.x" in labels
        assert "nodesource node_18.x" not in labels

    def test_nodesource_without_a_readable_major_is_refused(self, tmp_path):
        # Red at the base: no index was added, the nodejs pin was judged against
        # Debian's own nodejs, and the report said to pin its older version.
        body = f"RUN NODE_MAJOR=$WANTED && echo 'deb {NODESOURCE}'\n"
        with pytest.raises(checker.PinEnumerationError, match="NODE_MAJOR"):
            checker.apt_indexes(_dockerfile(tmp_path, body))

    def test_two_majors_are_refused_as_ambiguous(self, tmp_path):
        body = (
            f"RUN NODE_MAJOR=20 && echo 'deb {NODESOURCE}'\n"
            f"RUN NODE_MAJOR=22 && echo 'deb {NODESOURCE}'\n"
        )
        with pytest.raises(checker.PinEnumerationError, match="ambiguous"):
            checker.apt_indexes(_dockerfile(tmp_path, body))

    def test_no_nodesource_and_no_major_is_the_debian_indexes_only(self, tmp_path):
        """Control: a Dockerfile that never uses NodeSource is not refused."""
        labels = self._labels(tmp_path, f"RUN apt-get install -y {CURL}\n")
        assert labels == ["bookworm", "bookworm-updates", "bookworm-security"]


# ---------------------------------------------------------------------------
# Ordering versions and reading an index
# ---------------------------------------------------------------------------


class TestEpochAndMalformedVersions:
    def test_the_epoch_ends_at_the_first_colon(self):
        # Red at the base: rpartition took "1:2" as the epoch and int() raised.
        assert checker.compare_debian_versions("1:2:3-4", "1:2:4-1") < 0
        assert checker.compare_debian_versions("1:2:4-1", "1:2:3-4") > 0
        assert checker.compare_debian_versions("1:2:3-4", "1:2:3-4") == 0

    def test_an_epoch_still_outranks_the_rest(self):
        """Control: the case the first-colon split must not change."""
        assert checker.compare_debian_versions("2.39.5-0+deb12u3", "1:2.0-1") < 0


def _index(*stanzas: tuple[str, str]) -> str:
    return "\n\n".join(f"Package: {p}\nVersion: {v}\n" for p, v in stanzas)


ONE_INDEX = [checker.AptIndex("only", "https://deb.debian.org/{arch}/Packages")]


class TestCheckApt:
    def _check(self, text_for, pins):
        return checker.check_apt(pins, ONE_INDEX, text_for, architectures=("amd64",))

    def test_an_index_with_no_package_is_an_error_not_every_pin_retired(self):
        # Red at the base: parse_packages_index returned {} without complaint and the
        # pin read "unavailable" (exit 1, "the image build fails now").
        pin = checker.AptPin("curl", "7.1-1", (3,))
        (result,) = self._check(lambda url: "<html>try again later</html>", [pin])
        assert result.status == "error"
        assert "no packages" in result.detail
        assert checker.apt_exit_code([result], fail_on_outdated=False) == 2

    def test_a_version_dpkg_cannot_order_is_an_error_for_that_pin_only(self):
        # Red at the base: the comparison ran outside the per-index handler and the
        # ValueError left check_apt, and with it main.
        text = _index(("curl", "7.1-1"), ("curl", "x:1.0-1"), ("git", "1:2.0-1"))
        pins = [
            checker.AptPin("curl", "7.1-1", (3,)),
            checker.AptPin("git", "1:2.0-1", (4,)),
        ]
        by_package = {r.pin.package: r for r in self._check(lambda url: text, pins)}
        assert by_package["curl"].status == "error"
        assert "ValueError" in by_package["curl"].detail
        assert by_package["git"].status == "current"

    def test_a_listed_index_still_judges_its_pins(self):
        """Control: a well-formed answer is judged as it always was."""
        text = _index(("curl", "7.1-1"), ("curl", "7.2-1"))
        pin = checker.AptPin("curl", "7.1-1", (3,))
        (result,) = self._check(lambda url: text, [pin])
        assert (result.status, result.candidate) == ("outdated", "7.2-1")
