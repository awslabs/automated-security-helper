# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The OCI runner and its wrapper are read as the run-in-a-container page says.

``oci_runner_for_this_run`` reads the value of ``--oci-runner`` (or the ``oci_runner``
of a ``--cli-json-input`` document, which the CLI reads as typed) and the value of
``OCI_RUNNER`` (``from_environment``); ``_get_oci_wrapper_prefix`` reads the first word
of ``OCI_RUNNER_WRAPPER``. A relative path with a directory part names a file under
the working directory, which for a scan is usually the repository being scanned:

* typed, it is read against the working directory;
* from ``OCI_RUNNER``, or as the wrapper's first word, it is refused
  (``OciValueRefused``, exit code 3): not run, not replaced by looking for another
  runtime, and not dropped so that the runtime starts without the wrapper. The message
  names the variable and the value.

A leading ``~`` is expanded, and with no usable home directory a ``~/`` value is
refused the same way. A command name and an absolute path are used as given, and a
``$`` is not expanded.

tests/unit/docs/test_page_claims.py probes the same claims through the CLI and child
processes. These run in process, on every platform that has the path they need.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.core import constants
from automated_security_helper.interactions import run_ash_container as rac

pytestmark = pytest.mark.unit

#: A warning that was asked for: (variable, value, message).
Seen = Tuple[str, str, str]


@pytest.fixture
def warnings_seen(monkeypatch: pytest.MonkeyPatch) -> List[Seen]:
    """The relative-value warnings anything asks for, the HOME warning included.

    The constants module's name for the once-per-process warning is replaced, so a
    warning already given in this process cannot hide one, and what is asserted is
    what was asked to be said, not how a log handler shows it. A refused value says
    its piece in the refusal, so none is expected.
    """
    seen: List[Seen] = []
    monkeypatch.setattr(
        constants,
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


def _refused_wrapper(monkeypatch: pytest.MonkeyPatch, value: str) -> str:
    """The message the wrapper's refusal gives."""
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", value)
    with pytest.raises(rac.OciValueRefused) as refused:
        rac._get_oci_wrapper_prefix()
    return str(refused.value)


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


def test_a_relative_path_from_the_environment_is_refused_and_named(
    home: Path, warnings_seen: List[Seen]
) -> None:
    with pytest.raises(rac.OciValueRefused) as refused:
        rac.oci_runner_for_this_run("bin/docker", from_environment=True)

    message = str(refused.value)
    assert "OCI_RUNNER" in message
    assert repr("bin/docker") in message
    # Refused, and not run in place of nothing: no other runtime is looked for.
    assert "another runtime" in message
    # The refusal is the report; no warning is logged beside it.
    assert warnings_seen == []


def test_a_refusal_carries_the_usage_error_exit_code(home: Path) -> None:
    with pytest.raises(rac.OciValueRefused) as refused:
        rac.oci_runner_for_this_run("bin/docker", from_environment=True)

    assert refused.value.exit_code == 3


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
    "from_environment, named",
    [(False, "--oci-runner"), (True, "OCI_RUNNER")],
    ids=["typed", "from-the-environment"],
)
def test_a_leading_tilde_with_an_empty_home_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    warnings_seen: List[Seen],
    from_environment: bool,
    named: str,
) -> None:
    monkeypatch.setenv("HOME", "")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(rac.OciValueRefused) as refused:
        rac.oci_runner_for_this_run("~/bin/docker", from_environment)

    # The refusal names the variable (or the option) and HOME, and the module
    # logs no warning about HOME or about a relative path as well.
    message = str(refused.value)
    assert named in message
    assert repr("~/bin/docker") in message
    assert "HOME is empty" in message
    assert warnings_seen == []


def test_a_relative_first_word_of_the_wrapper_is_refused_and_named(
    home: Path, monkeypatch: pytest.MonkeyPatch, warnings_seen: List[Seen]
) -> None:
    message = _refused_wrapper(monkeypatch, "bin/sudo -n")

    assert "OCI_RUNNER_WRAPPER" in message
    assert repr("bin/sudo") in message
    # Not dropped: the runtime does not start without the wrapper that was asked for.
    assert "without the wrapper" in message
    assert warnings_seen == []


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


def test_no_wrapper_is_no_prefix(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    assert rac._get_oci_wrapper_prefix() == []
    assert _wrapper_prefix(monkeypatch, " \t\n") == []


@pytest.mark.skipif(
    os.name == "nt", reason="an empty USERPROFILE falls back to HOMEDRIVE and HOMEPATH"
)
def test_a_leading_tilde_of_the_wrapper_with_an_empty_home_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, warnings_seen: List[Seen]
) -> None:
    monkeypatch.setenv("HOME", "")
    monkeypatch.chdir(tmp_path)

    message = _refused_wrapper(monkeypatch, "~/bin/sudo -n")

    assert "OCI_RUNNER_WRAPPER" in message
    assert repr("~/bin/sudo") in message
    assert "HOME is empty" in message
    assert warnings_seen == []


def test_the_early_wrapper_refusal_gives_the_exit_code_and_message(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo -n")

    refusal = rac.oci_wrapper_refusal()

    assert refusal is not None
    code, message = refusal
    assert code == 3
    assert "OCI_RUNNER_WRAPPER" in message and repr("bin/sudo") in message


@pytest.mark.parametrize("wrapper", [None, "sudo -n", "~/bin/sudo"])
def test_the_early_wrapper_refusal_is_none_for_a_wrapper_that_will_run(
    home: Path, monkeypatch: pytest.MonkeyPatch, wrapper: str | None
) -> None:
    if wrapper is None:
        monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    else:
        monkeypatch.setenv("OCI_RUNNER_WRAPPER", wrapper)

    assert rac.oci_wrapper_refusal() is None


def test_a_refused_wrapper_stops_the_container_run_before_anything_starts(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_ash_container refuses with exit 3 rather than build or run without it."""
    commands: List[List[str]] = []

    def record(cmd_list, *args, **kwargs):
        commands.append([str(item) for item in cmd_list if item is not None])
        return rac.create_completed_process(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(rac.subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(rac.subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    monkeypatch.setattr(rac, "_require_mountable_inputs", lambda *a, **k: None)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo -n")
    source = tmp_path / "project"
    source.mkdir()

    result = rac.run_ash_container(
        source_dir=str(source),
        output_dir=str(tmp_path / "out"),
        build=True,
        run=True,
    )

    assert result.returncode == 3, result.stderr
    assert "OCI_RUNNER_WRAPPER" in result.stderr
    assert not rac.container_was_started(result)
    assert commands == []


def test_the_leftover_sweep_raises_a_refused_wrapper_instead_of_warning(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep is best effort for everything but a wrapper ASH refuses: that ends
    the run, as it does in container mode, and is not one warning among others (nix
    mode runs the wrapper only here)."""
    monkeypatch.setattr(rac, "leftover_records", lambda: ["a record"])
    monkeypatch.setattr(
        rac, "_resolve_oci_runner", lambda runner, quiet=False: "/nonexistent/docker"
    )
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo")

    with pytest.raises(rac.OciValueRefused) as refused:
        rac.sweep_leftovers_before_run(None)

    assert "OCI_RUNNER_WRAPPER" in str(refused.value)


def test_the_leftover_sweep_with_no_record_starts_and_reads_nothing(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(rac, "leftover_records", list)
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo")

    assert rac.sweep_leftovers_before_run(None) == []


def test_a_nix_run_refuses_a_wrapper_before_the_log_is_opened(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """run_ash_scan asks for the wrapper ahead of the logger, which makes the output
    directory and truncates ash.log, so a refused run leaves no trace there."""
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions import run_ash_scan as scan_module

    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "bin/sudo")
    source = tmp_path / "project"
    source.mkdir()
    output = tmp_path / "out"

    with pytest.raises(SystemExit) as exited:
        scan_module.run_ash_scan(
            source_dir=str(source), output_dir=str(output), mode=RunMode.nix
        )

    assert exited.value.code == 3
    assert not output.exists()
