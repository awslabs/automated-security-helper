# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container that exits 2 without a results file is reported as a usage error.

The scan inside the container is the ASH CLI. It exits 2 for findings only after it
has written its results file, and for a usage error (Click's code) without one. An
image built from an older ASH than the host's gives that usage error for an option
the host's ASH passes it, such as ``--config-from-scanned-repository``, which the
host adds for a config elsewhere in the scanned checkout. The host then refuses with
exit 3 and says to rebuild the image from this ASH, rather than ending at "Results
file not found" with exit 1.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.sandbox_grants import in_any_checkout
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

FLAG = rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG
OTHER_FLAG = "--config-file-from-another-checkout"

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _words(output: str) -> str:
    """The console output as plain words.

    The log is written through rich, which on some hosts (a Windows runner) styles
    the text with color codes and wraps each message at the console width, with
    the log's time and level columns as padding on every wrapped line. A phrase
    that is one line on a wide console is several there, so the assertions read
    the words with the codes removed and the whitespace collapsed.
    """
    return " ".join(_ANSI.sub("", output).split())


@pytest.fixture(autouse=True)
def _no_real_runner(monkeypatch):
    def refuse(cmd_list, check=True, debug=False, shell=False, env=None):
        raise AssertionError(f"a real runner command was attempted: {cmd_list}")

    monkeypatch.setattr(rac, "run_cmd_direct", refuse)


@pytest.fixture
def container(monkeypatch, tmp_path) -> Dict[str, Any]:
    """The scan inside exits with ``seen['returncode']`` and writes nothing."""
    monkeypatch.chdir(tmp_path)
    seen: Dict[str, Any] = {"returncode": 2, "runs": []}

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )

    def fake_execute(cmd, debug=False, env=None):
        seen["runs"].append(list(cmd))
        return create_completed_process(
            args=list(cmd), returncode=seen["returncode"], stderr="Usage: ash ...\n"
        )

    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    # A caller's ASH_SCANNERS, the environment variable of the deprecated
    # --scanners, would reach the scan beside --add-scanners, and --only-scanners
    # refuses it.
    monkeypatch.delenv("ASH_SCANNERS", raising=False)
    return seen


def _scan(*args: str):
    return CliRunner().invoke(
        app, ["scan", "fs", "--mode", "container", "--no-build", "--no-progress", *args]
    )


def test_the_mark_an_older_image_does_not_know(container, tmp_path):
    checkout = tmp_path / "repo"
    mark_git_checkout(checkout)
    (checkout / "svc").mkdir()
    (checkout / "ci").mkdir()
    config = checkout / "ci" / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _scan(
        str(checkout / "svc"),
        "--output-dir",
        str(tmp_path / "out"),
        "--config",
        str(config),
    )

    [run] = container["runs"]
    assert FLAG in run
    assert result.exit_code == 3, result.output
    assert "Rebuild the image from this ASH" in _words(result.output)
    assert FLAG in _words(result.output)
    assert "Results file not found" not in _words(result.output)


def test_the_mark_for_a_config_in_another_checkout_an_older_image_does_not_know(
    container, tmp_path
):
    """The mark for a file in a checkout other than the scanned one is an option an
    older image rejects as well; the host names it and asks for a rebuild."""
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    (tmp_path / "src").mkdir()
    config = ops / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    result = _scan(
        "src",
        "--output-dir",
        str(tmp_path / "out"),
        "--config",
        str(config),
    )

    [run] = container["runs"]
    assert OTHER_FLAG in run
    assert FLAG not in run
    assert result.exit_code == 3, result.output
    assert "Rebuild the image from this ASH" in _words(result.output)
    assert OTHER_FLAG in _words(result.output)
    assert "Results file not found" not in _words(result.output)


def test_any_other_usage_error_inside(container, tmp_path):
    (tmp_path / "src").mkdir()

    result = _scan("src", "--output-dir", str(tmp_path / "out"))

    assert result.exit_code == 3, result.output
    assert "Rebuild the image from this ASH" in _words(result.output)
    assert "Results file not found" not in _words(result.output)


def test_success_without_results_is_unchanged(container, tmp_path):
    """Control: exit 0 with no results file is still the missing-results error."""
    container["returncode"] = 0
    (tmp_path / "src").mkdir()

    result = _scan("src", "--output-dir", str(tmp_path / "out"))

    assert result.exit_code == 1, result.output
    assert "Results file not found" in _words(result.output)


MARKER = "--require-scanner-selection"


def _operator_config(tmp_path, body):
    path = tmp_path.parent / f"{tmp_path.name}-operator" / "ash.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return str(path)


def _values(argv, flag):
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == flag]


def _scan_with(tmp_path, config, *args):
    (tmp_path / "src").mkdir(exist_ok=True)
    return _scan(
        "src",
        "--output-dir",
        str(tmp_path / "out"),
        *(["--config", config] if config else []),
        *args,
    )


def test_a_config_only_selection_an_older_image_cannot_enforce_is_refused(
    container, tmp_path
):
    config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

    result = _scan_with(tmp_path, config)

    [run] = container["runs"]
    assert json.loads(_values(run, MARKER)[0]) == {"add": [], "only": ["bandit"]}
    assert result.exit_code == 3, result.output
    assert MARKER in _words(result.output)
    assert "Rebuild the image from this ASH" in _words(result.output)
    assert "Results file not found" not in _words(result.output)


def test_a_replacement_flag_reaches_the_inner_scan_as_a_replacement(
    container, tmp_path
):
    config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

    _scan_with(tmp_path, config, "--only-scanners", "trivy")

    [run] = container["runs"]
    assert _values(run, "--only-scanners") == ["trivy"]
    assert _values(run, "--scanners") == []
    assert _values(run, MARKER)


def test_an_additive_flag_reaches_the_inner_scan_as_an_addition(container, tmp_path):
    config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

    _scan_with(tmp_path, config, "--add-scanners", "trivy")

    [run] = container["runs"]
    assert _values(run, "--add-scanners") == ["trivy"]
    assert _values(run, "--only-scanners") == []
    assert _values(run, MARKER)


def test_a_legacy_scanners_flag_stays_the_legacy_flag_when_the_section_matters(
    container, tmp_path
):
    config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

    _scan_with(tmp_path, config, "--scanners", "trivy")

    [run] = container["runs"]
    assert _values(run, "--scanners") == ["trivy"]
    assert _values(run, MARKER)


def test_the_marker_is_bound_to_the_normalized_lists(container, tmp_path):
    config = _operator_config(
        tmp_path, "default_scanners:\n  add: [' Trivy ', TRIVY, checkov]\n"
    )

    _scan_with(tmp_path, config)

    [run] = container["runs"]
    assert json.loads(_values(run, MARKER)[0]) == {
        "add": ["trivy", "checkov"],
        "only": [],
    }


@pytest.mark.parametrize("body", ["project_name: p\n", "default_scanners: {}\n"])
def test_without_a_selection_the_forwarding_and_the_check_are_unchanged(
    container, tmp_path, body
):
    config = _operator_config(tmp_path, body)

    _scan_with(tmp_path, config, "--only-scanners", "trivy")

    [run] = container["runs"]
    assert _values(run, "--scanners") == ["trivy"]
    assert _values(run, "--only-scanners") == []
    assert MARKER not in run


def test_with_no_config_at_all_the_forwarding_is_unchanged(container, tmp_path):
    _scan_with(tmp_path, None, "--add-scanners", "trivy")

    [run] = container["runs"]
    assert _values(run, "--scanners") == ["trivy"]
    assert MARKER not in run


def _checkout_with_config(tmp_path, body):
    checkout = tmp_path / "repo"
    mark_git_checkout(checkout)
    config = checkout / ".ash.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(body, encoding="utf-8")
    return checkout, config


_CHECKOUT_BODIES = {
    "no-section": "project_name: repo\n",
    "asks-for-trivy": "default_scanners:\n  only: [trivy]\n",
}


@pytest.mark.parametrize("body", list(_CHECKOUT_BODIES))
def test_ash_config_s_selection_under_a_named_checkout_config_is_required(
    container, tmp_path, monkeypatch, body
):
    monkeypatch.setenv(
        "ASH_CONFIG",
        _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n"),
    )
    checkout, config = _checkout_with_config(tmp_path, _CHECKOUT_BODIES[body])

    result = _scan(
        str(checkout),
        "--output-dir",
        str(tmp_path / "out"),
        "--config",
        str(config),
    )

    [run] = container["runs"]
    assert json.loads(_values(run, MARKER)[0]) == {"add": [], "only": ["bandit"]}
    assert result.exit_code == 3, result.output
    assert MARKER in _words(result.output)
    assert "Rebuild the image from this ASH" in _words(result.output)


@pytest.mark.parametrize("body", list(_CHECKOUT_BODIES))
def test_ash_config_s_selection_beside_a_discovered_checkout_config_is_required(
    container, tmp_path, monkeypatch, body
):
    from automated_security_helper.core.enums import RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    monkeypatch.setenv(
        "ASH_CONFIG",
        _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n"),
    )
    checkout, _ = _checkout_with_config(tmp_path, _CHECKOUT_BODIES[body])

    with pytest.raises(BaseException) as ended:
        run_ash_scan(
            source_dir=str(checkout),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.container,
            build=False,
            progress=False,
        )

    [run] = container["runs"]
    assert json.loads(_values(run, MARKER)[0]) == {"add": [], "only": ["bandit"]}
    assert getattr(ended.value, "code", None) == 3, ended.value


@pytest.mark.parametrize(
    "error",
    [OSError("synthetic read failure"), ValueError("synthetic resolution failure")],
    ids=["read-failure", "resolution-failure"],
)
def test_a_selection_that_cannot_be_resolved_starts_no_container(
    container, tmp_path, monkeypatch, error
):
    from automated_security_helper.core import orchestrator

    def fail(**_kwargs):
        raise error

    monkeypatch.setattr(orchestrator, "resolve_scan_config", fail)
    config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")
    out = tmp_path / "out"
    out.mkdir()
    stale = out / "stale-marker.txt"
    stale.write_text("previous run\n", encoding="utf-8")

    result = _scan_with(tmp_path, config)

    assert container["runs"] == []
    assert result.exit_code == 3, result.output
    assert "default_scanners" in _words(result.output)
    assert "Results file not found" not in _words(result.output)
    assert stale.read_text(encoding="utf-8") == "previous run\n"


_LATER_SCHEMA = "global_settings:\n  zz_option_a_later_schema_declares: true\n"


@pytest.mark.parametrize(
    ("body", "overrides"),
    [
        (_LATER_SCHEMA + "default_scanners:\n  only: [bandit]\n", []),
        (
            _LATER_SCHEMA,
            ["--config-overrides", 'default_scanners.only=["bandit"]'],
        ),
    ],
    ids=["in-ash-config", "in-an-override"],
)
def test_a_selection_left_unresolved_for_an_image_that_may_differ_is_refused(
    container, tmp_path, monkeypatch, body, overrides
):
    monkeypatch.setenv("ASH_CONFIG", _operator_config(tmp_path, body))

    result = _scan_with(tmp_path, None, *overrides)

    assert container["runs"] == []
    assert result.exit_code == 3, result.output
    assert "default_scanners" in _words(result.output)


@pytest.mark.parametrize("inherited", [False, True], ids=["direct", "inherited"])
def test_unresolved_operator_selection_is_not_lost_beside_a_checkout_config(
    container, tmp_path, monkeypatch, inherited
):
    selection = "default_scanners:\n  only: [bandit]\n"
    if inherited:
        (tmp_path / "base.yaml").write_text(selection, encoding="utf-8")
        selection = "extends: base.yaml\n"
    operator = tmp_path / "operator.yaml"
    operator.write_text(_LATER_SCHEMA + selection, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    checkout, config = _checkout_with_config(tmp_path, _CHECKOUT_BODIES["no-section"])

    result = _scan(
        str(checkout),
        "--output-dir",
        str(tmp_path / "out"),
        "--config",
        str(config),
    )

    assert container["runs"] == []
    assert result.exit_code == 3, result.output
    assert "default_scanners" in _words(result.output)


def test_without_a_selection_an_image_that_may_differ_still_judges_its_schema(
    container, tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_CONFIG", _operator_config(tmp_path, _LATER_SCHEMA))

    _scan_with(tmp_path, None)

    [run] = container["runs"]
    assert MARKER not in run
