# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The weekly pin check reads the Dockerfile's apt pins and catches a retired one.

Why this file exists
--------------------
The root Dockerfile pins every apt package to an exact Debian or NodeSource
version. Debian keeps one version per suite, so the next point release or
security update retires some of those pins and the image build starts failing
with "Version '...' was not found". ``scripts/check_pinned_tool_versions.py``
looks the pins up in the indexes apt reads, so the weekly job fails first and
says which version to move to.

The indexes here are recorded: trimmed copies of the real bookworm,
bookworm-updates, bookworm-security and NodeSource node_22.x ``Packages`` files
for amd64 and arm64, taken 2026-10-07 and cut down to the stanzas of the pinned
packages, under ``tests/test_data/apt_indices/<host>/<path>``. The Debian ones are
served xz-compressed, as the archive serves them, so the decompression path runs
too. No test reaches the network: the HTTP and HTTPS transports fail the test if
anything reaches them.

Each assertion that the real Dockerfile is clean is paired with a negative
control that removes or changes one thing and shows the same check going red.
"""

from __future__ import annotations

import importlib.util
import lzma
import socket
import sys
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"
DOCKERFILE = REPO_ROOT / "Dockerfile"
FIXTURES = REPO_ROOT / "tests" / "test_data" / "apt_indices"


def _load_script():
    spec = importlib.util.spec_from_file_location("_check_pinned_apt", SCRIPT)
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

    # At the transport, which every opener goes through, urlopen's and the script's
    # own redirect-checking opener alike.
    monkeypatch.setattr(urllib.request.HTTPSHandler, "https_open", refuse)
    monkeypatch.setattr(urllib.request.HTTPHandler, "http_open", refuse)
    monkeypatch.setattr(urllib.request.FTPHandler, "ftp_open", refuse)
    # A backstop beneath every transport, the ones not patched above included.
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def _fixture_path(url: str) -> Path:
    assert url.startswith("https://"), url
    return FIXTURES / url[len("https://") :].removesuffix(".xz")


def recorded(url: str, overrides: dict[str, str] | None = None) -> str:
    """What fetch_index would return for ``url``, from the recorded indexes.

    Goes through the script's own decompression for ``.xz`` URLs by handing it
    xz bytes, rather than reading the plain fixture straight back.
    """
    path = _fixture_path(url)
    text = (overrides or {}).get(path.relative_to(FIXTURES).as_posix())
    if text is None:
        text = path.read_text(encoding="utf-8")
    data = text.encode("utf-8")
    if url.endswith(".xz"):
        data = lzma.compress(data)

    original = checker._get_bytes
    checker._get_bytes = lambda _url, headers=None: data
    try:
        return checker.fetch_index(url)
    finally:
        checker._get_bytes = original


def _write_dockerfile(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "Dockerfile"
    path.write_text(
        "ARG BASE_IMAGE=public.ecr.aws/docker/library/python:3.12-slim-bookworm\n"
        "FROM ${BASE_IMAGE} AS core\n" + body,
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# Reading the pins
# ---------------------------------------------------------------------------


class TestEnumeration:
    def test_every_apt_install_in_the_dockerfile_is_read(self):
        pins = {p.package: p for p in checker.enumerate_apt_pins(DOCKERFILE)}
        # Counted independently: every name=version word on a line of an
        # apt-get install, which is what hadolint's DL3008 looks at.
        assert set(pins) == {
            "build-essential",
            "ca-certificates",
            "curl",
            "git",
            "gnupg",
            "nodejs",
            "python3-venv",
            "ripgrep",
            "ruby",
            "ruby-dev",
            "tree",
        }
        assert all(p.lines for p in pins.values()), "a pin was read with no line"

    def test_a_package_in_two_stages_is_one_pin_on_both_lines(self):
        pins = {p.package: p for p in checker.enumerate_apt_pins(DOCKERFILE)}
        assert len(pins["git"].lines) == 2

    def test_an_unpinned_apt_install_is_refused(self, tmp_path):
        dockerfile = _write_dockerfile(
            tmp_path,
            "RUN apt-get update && \\\n"
            "    apt-get install -y --no-install-recommends curl=7.88.1-10+deb12u15 \\\n"
            "    git && \\\n"
            "    rm -rf /var/lib/apt/lists/*\n",
        )
        with pytest.raises(checker.PinEnumerationError, match="'git'"):
            checker.enumerate_apt_pins(dockerfile)

    def test_one_package_pinned_two_ways_is_refused(self, tmp_path):
        dockerfile = _write_dockerfile(
            tmp_path,
            "RUN apt-get install -y curl=7.88.1-10+deb12u15\n"
            "RUN apt-get install -y curl=7.88.1-10+deb12u5\n",
        )
        with pytest.raises(checker.PinEnumerationError, match="every stage"):
            checker.enumerate_apt_pins(dockerfile)

    def test_purge_and_the_install_recommends_flag_are_not_installs(self, tmp_path):
        dockerfile = _write_dockerfile(
            tmp_path,
            "RUN apt-get install -y --no-install-recommends ruby-dev=1:3.1 && \\\n"
            "    apt-get purge -y --auto-remove ruby-dev\n",
        )
        assert [p.package for p in checker.enumerate_apt_pins(dockerfile)] == [
            "ruby-dev"
        ]

    def test_the_indexes_follow_the_base_image_and_node_major(self):
        labels = [i.label for i in checker.apt_indexes(DOCKERFILE)]
        assert labels == [
            "bookworm",
            "bookworm-updates",
            "bookworm-security",
            "nodesource node_22.x",
        ]

    def test_a_base_image_with_no_codename_is_refused(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text(
            "ARG BASE_IMAGE=python:3.12\nFROM ${BASE_IMAGE}\n", encoding="utf-8"
        )
        with pytest.raises(checker.PinEnumerationError, match="codename"):
            checker.apt_indexes(path)


# ---------------------------------------------------------------------------
# Debian version ordering
# ---------------------------------------------------------------------------


class TestDebianVersions:
    @pytest.mark.parametrize(
        "older, newer",
        [
            ("7.88.1-10+deb12u5", "7.88.1-10+deb12u15"),  # numeric, not string, order
            ("1:2.39.5-0+deb12u2", "1:2.39.5-0+deb12u3"),
            ("2.39.5-0+deb12u3", "1:2.0-1"),  # the epoch wins
            ("1.0~rc1", "1.0"),  # ~ sorts before the empty string
            ("20230311+deb12u1", "20250419~deb12u1"),
            ("22.9.0-1nodesource1", "22.23.3-1nodesource1"),
            ("3.11.2-1", "3.11.2-1+b1"),
        ],
    )
    def test_order(self, older, newer):
        assert checker.compare_debian_versions(older, newer) < 0
        assert checker.compare_debian_versions(newer, older) > 0

    def test_equal(self):
        assert checker.compare_debian_versions("1:3.1", "1:3.1") == 0


# ---------------------------------------------------------------------------
# Checking against the recorded indexes
# ---------------------------------------------------------------------------


def _check(overrides: dict[str, str] | None = None, dockerfile: Path = DOCKERFILE):
    return checker.check_apt(
        checker.enumerate_apt_pins(dockerfile),
        checker.apt_indexes(dockerfile),
        lambda url: recorded(url, overrides),
    )


def _drop(rel: str, package: str, version: str) -> dict[str, str]:
    """The recorded index at ``rel`` with ``package``'s ``version`` stanza removed."""
    text = (FIXTURES / rel).read_text(encoding="utf-8")
    stanzas = [
        s
        for s in text.split("\n\n")
        if not (
            f"Package: {package}\n" in s + "\n" and f"Version: {version}\n" in s + "\n"
        )
    ]
    assert len(stanzas) < len(text.split("\n\n")), f"{package} {version} not in {rel}"
    return {rel: "\n\n".join(stanzas)}


class TestAgainstTheRecordedIndexes:
    def test_every_pin_is_current_on_both_architectures(self):
        results = _check()
        assert {r.arch for r in results} == {"amd64", "arm64"}
        assert len(results) == 2 * len(checker.enumerate_apt_pins(DOCKERFILE))
        assert [
            (r.pin.package, r.arch, r.status) for r in results if r.status != "current"
        ] == []
        assert checker.apt_exit_code(results, fail_on_outdated=True) == checker.EXIT_OK

    def test_negative_control_a_retired_pin_is_unavailable_and_fails(self):
        # A point release: git's pinned version leaves the main suite, and the
        # security suite still carries only the older deb12u2.
        overrides = {}
        for arch in ("amd64", "arm64"):
            overrides.update(
                _drop(
                    f"deb.debian.org/debian/dists/bookworm/main/binary-{arch}/Packages",
                    "git",
                    "1:2.39.5-0+deb12u3",
                )
            )
        results = _check(overrides)
        git = [r for r in results if r.pin.package == "git"]
        assert [r.status for r in git] == ["unavailable", "unavailable"]
        assert all(r.candidate == "1:2.39.5-0+deb12u2" for r in git)
        assert [
            r for r in results if r.pin.package != "git" and r.status != "current"
        ] == []
        # Fails whether or not --fail-on-outdated is given: the build is already broken.
        assert (
            checker.apt_exit_code(results, fail_on_outdated=False)
            == checker.EXIT_OUTDATED
        )

        report = checker.render_apt_report(results)
        assert "git=1:2.39.5-0+deb12u3 -> git=1:2.39.5-0+deb12u2" in report
        lines = ", ".join(f"Dockerfile:{n}" for n in git[0].pin.lines)
        assert lines in report

    def test_a_pin_retired_on_one_architecture_is_caught(self):
        rel = "deb.debian.org/debian/dists/bookworm/main/binary-arm64/Packages"
        results = _check(_drop(rel, "ripgrep", "13.0.0-4+b2"))
        assert [
            (r.pin.package, r.arch, r.candidate)
            for r in results
            if r.status != "current"
        ] == [("ripgrep", "arm64", None)]
        assert (
            checker.apt_exit_code(results, fail_on_outdated=False)
            == checker.EXIT_OUTDATED
        )
        assert "ripgrep=13.0.0-4+b2 in Dockerfile:" in checker.render_apt_report(
            results
        )

    def test_a_newer_security_update_is_outdated_and_fails_only_with_the_flag(self):
        rel = "deb.debian.org/debian-security/dists/bookworm-security/main/binary-amd64/Packages"
        text = (FIXTURES / rel).read_text(encoding="utf-8")
        text += "\nPackage: curl\nVersion: 7.88.1-10+deb12u16\nArchitecture: amd64\n"
        results = _check({rel: text})
        curl = [r for r in results if r.pin.package == "curl" and r.arch == "amd64"]
        assert [(r.status, r.candidate) for r in curl] == [
            ("outdated", "7.88.1-10+deb12u16")
        ]
        assert checker.apt_exit_code(results, fail_on_outdated=False) == checker.EXIT_OK
        assert (
            checker.apt_exit_code(results, fail_on_outdated=True)
            == checker.EXIT_OUTDATED
        )

    def test_a_nodesource_pin_is_looked_up_in_nodesource(self):
        overrides = {}
        for arch in ("amd64", "arm64"):
            overrides.update(
                _drop(
                    f"deb.nodesource.com/node_22.x/dists/nodistro/main/binary-{arch}/Packages",
                    "nodejs",
                    "22.23.3-1nodesource1",
                )
            )
        results = _check(overrides)
        nodejs = {r.status for r in results if r.pin.package == "nodejs"}
        assert nodejs == {"unavailable"}

    def test_an_index_that_cannot_be_read_is_an_error_not_current(self):
        def broken(url: str) -> str:
            if "security" in url:
                raise OSError("connection reset")
            return recorded(url)

        results = checker.check_apt(
            checker.enumerate_apt_pins(DOCKERFILE),
            checker.apt_indexes(DOCKERFILE),
            broken,
        )
        assert {r.status for r in results} == {"error"}
        assert (
            checker.apt_exit_code(results, fail_on_outdated=False) == checker.EXIT_ERROR
        )


class TestMain:
    def _run(self, monkeypatch, capsys, overrides=None, argv=()):
        monkeypatch.setattr(
            checker, "APT_INDEX_FETCHER", lambda url: recorded(url, overrides)
        )
        monkeypatch.setattr(
            checker,
            "DEFAULT_FETCHERS",
            {
                eco: (
                    lambda project: {
                        p.project: p.version
                        for p in checker.enumerate_pins(checker.load_pins_module())
                    }[project]
                )
                for eco in (checker.GITHUB, checker.PYPI, checker.RUBYGEMS)
            },
        )
        code = checker.main(list(argv))
        return code, capsys.readouterr().out

    def test_all_current_exits_zero_and_reports_the_apt_table(
        self, monkeypatch, capsys
    ):
        code, out = self._run(monkeypatch, capsys, argv=["--fail-on-outdated"])
        assert code == checker.EXIT_OK, out
        assert "Dockerfile apt pins" in out
        assert "Every apt pin is the version apt would choose today." in out

    def test_a_retired_apt_pin_fails_main_without_the_flag(self, monkeypatch, capsys):
        overrides = _drop(
            "deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages",
            "tree",
            "2.1.0-1",
        )
        code, out = self._run(monkeypatch, capsys, overrides)
        assert code == checker.EXIT_OUTDATED
        assert "tree=2.1.0-1" in out and "unavailable" in out


class TestTheArchivesAreAllowlisted:
    @pytest.mark.parametrize(
        "url",
        [
            "https://deb.debian.org/debian/dists/bookworm/main/binary-amd64/Packages.xz",
            "https://deb.nodesource.com/node_22.x/dists/nodistro/main/binary-arm64/Packages",
        ],
    )
    def test_the_index_urls_pass_the_host_check(self, url):
        assert checker._checked_url(url) == url

    def test_plain_http_to_the_archive_is_refused(self):
        with pytest.raises(ValueError, match="refusing to fetch"):
            checker._checked_url("http://deb.debian.org/debian/dists/bookworm/Release")
