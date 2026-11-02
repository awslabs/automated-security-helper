# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OCI runner and its wrapper are read as the run-in-a-container page says.

``oci_runner_for_this_run`` reads the value of ``--oci-runner`` (or the ``oci_runner``
of a ``--cli-json-input`` document, which the CLI reads as typed) and the value of
``OCI_RUNNER`` (``from_environment``); ``_get_oci_wrapper_prefix`` reads the first word
of ``OCI_RUNNER_WRAPPER``. A relative path with a directory part names a file under
the working directory, which for a scan is usually the repository being scanned:

* typed, it is read against the working directory;
* from ``OCI_RUNNER``, or as the wrapper's first word, it is not run, and a warning
  names it.

A leading ``~`` is expanded, and with no usable home directory a ``~/`` value is not
used. A command name and an absolute path are used as given, and a ``$`` is not
expanded.

tests/unit/docs/test_page_claims.py probes the same claims through the CLI and child
processes. These run in process, on every platform that has the path they need.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.interactions import run_ash_container as rac

pytestmark = pytest.mark.unit

#: A warning the container module asked for: (variable, value, message).
Seen = Tuple[str, str, str]


@pytest.fixture
def warnings_seen(monkeypatch: pytest.MonkeyPatch) -> List[Seen]:
    """The relative-value warnings the container module asks for.

    The module's name for the once-per-process warning is replaced, so a warning
    already given in this process cannot hide one, and what is asserted is what the
    module asked to say, not how a log handler shows it.
    """
    seen: List[Seen] = []
    monkeypatch.setattr(
        rac,
        "warn_relative_value_once",
        lambda variable, value, message: seen.append((variable, value, message)),
    )
    return seen


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An absolute home directory, named by HOME and USERPROFILE, with the working
    directory another place."""
    directory = tmp_path / "home"
    directory.mkdir()
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(directory))
    working = tmp_path / "cwd"
    working.mkdir()
    monkeypatch.chdir(working)
    return directory


def _under_the_working_directory(*parts: str) -> str:
    return os.path.join(os.getcwd(), *parts)


def _wrapper_prefix(monkeypatch: pytest.MonkeyPatch, value: str) -> List[str]:
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", value)
    return rac._get_oci_wrapper_prefix()


def _named(seen: List[Seen]) -> List[Tuple[str, str]]:
    return [(variable, value) for variable, value, _ in seen]


@pytest.mark.parametrize(
    "from_environment", [False, True], ids=["typed", "from-the-environment"]
)
def test_a_command_name_or_an_absolute_path_is_used_as_given(
    home: Path, tmp_path: Path, warnings_seen: List[Seen], from_environment: bool
) -> None:
    absolute = str(tmp_path / "opt" / "docker")

    assert rac.oci_runner_for_this_run("docker", from_environment) == "docker"
    assert rac.oci_runner_for_this_run(absolute, from_environment) == absolute
    assert warnings_seen == []


@pytest.mark.parametrize(
    "from_environment", [False, True], ids=["typed", "from-the-environment"]
)
def test_no_value_is_no_runner(
    home: Path, warnings_seen: List[Seen], from_environment: bool
) -> None:
    assert rac.oci_runner_for_this_run(None, from_environment) is None
    assert rac.oci_runner_for_this_run("", from_environment) == ""
    assert warnings_seen == []


def test_a_relative_path_typed_is_read_against_the_working_directory(
    home: Path, warnings_seen: List[Seen]
) -> None:
    read = rac.oci_runner_for_this_run("bin/docker", from_environment=False)

    assert read == _under_the_working_directory("bin", "docker")
    assert warnings_seen == []


def test_a_relative_path_from_the_environment_is_not_used_and_is_named(
    home: Path, warnings_seen: List[Seen]
) -> None:
    read = rac.oci_runner_for_this_run("bin/docker", from_environment=True)

    assert read is None
    assert _named(warnings_seen) == [("OCI_RUNNER", "bin/docker")]
    assert repr("bin/docker") in warnings_seen[0][2]


def test_a_dollar_is_not_expanded(home: Path, warnings_seen: List[Seen]) -> None:
    read = rac.oci_runner_for_this_run("$HOME/bin/docker", from_environment=False)

    assert read == _under_the_working_directory("$HOME", "bin", "docker")
    assert warnings_seen == []


@pytest.mark.parametrize(
    "from_environment", [False, True], ids=["typed", "from-the-environment"]
)
def test_a_leading_tilde_names_the_home_directory(
    home: Path, warnings_seen: List[Seen], from_environment: bool
) -> None:
    read = rac.oci_runner_for_this_run("~/bin/docker", from_environment)

    assert read == str(home) + "/bin/docker"
    assert warnings_seen == []


@pytest.mark.skipif(
    os.name == "nt", reason="an empty USERPROFILE falls back to HOMEDRIVE and HOMEPATH"
)
@pytest.mark.parametrize(
    "from_environment", [False, True], ids=["typed", "from-the-environment"]
)
def test_a_leading_tilde_with_an_empty_home_is_not_used(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    warnings_seen: List[Seen],
    from_environment: bool,
) -> None:
    monkeypatch.setenv("HOME", "")
    monkeypatch.chdir(tmp_path)

    read = rac.oci_runner_for_this_run("~/bin/docker", from_environment)

    # The warning about HOME is the constants module's own; none is about a relative
    # path, which the value is not.
    assert read is None
    assert warnings_seen == []


def test_a_relative_first_word_of_the_wrapper_is_not_used_and_is_named(
    home: Path, monkeypatch: pytest.MonkeyPatch, warnings_seen: List[Seen]
) -> None:
    assert _wrapper_prefix(monkeypatch, "bin/sudo -n") == []
    assert _named(warnings_seen) == [("OCI_RUNNER_WRAPPER", "bin/sudo")]
    assert repr("bin/sudo") in warnings_seen[0][2]


def test_only_the_first_word_of_the_wrapper_is_read_as_a_path(
    home: Path, monkeypatch: pytest.MonkeyPatch, warnings_seen: List[Seen]
) -> None:
    prefix = _wrapper_prefix(monkeypatch, "sudo bin/helper -n")

    assert prefix == ["sudo", "bin/helper", "-n"]
    assert warnings_seen == []


def test_a_leading_tilde_of_the_wrappers_first_word_is_expanded(
    home: Path, monkeypatch: pytest.MonkeyPatch, warnings_seen: List[Seen]
) -> None:
    prefix = _wrapper_prefix(monkeypatch, "~/bin/sudo -n")

    assert prefix == [str(home) + "/bin/sudo", "-n"]
    assert warnings_seen == []


def test_an_absolute_wrapper_is_used_as_given(
    home: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    warnings_seen: List[Seen],
) -> None:
    absolute = str(tmp_path / "opt" / "sudo")
    if len(absolute.split()) != 1:
        pytest.skip("the wrapper is split at whitespace and this path holds some")

    assert _wrapper_prefix(monkeypatch, f"{absolute} -n") == [absolute, "-n"]
    assert warnings_seen == []


@pytest.mark.skipif(
    os.name == "nt", reason="an empty USERPROFILE falls back to HOMEDRIVE and HOMEPATH"
)
def test_a_leading_tilde_of_the_wrapper_with_an_empty_home_is_no_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, warnings_seen: List[Seen]
) -> None:
    monkeypatch.setenv("HOME", "")
    monkeypatch.chdir(tmp_path)

    assert _wrapper_prefix(monkeypatch, "~/bin/sudo -n") == []
    assert warnings_seen == []
