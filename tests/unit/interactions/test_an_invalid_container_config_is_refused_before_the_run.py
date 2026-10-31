# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An invalid config refuses a container or Nix run before anything starts.

Container and nix mode hand the config to a second ASH, which refuses a file
that does not load with exit 3 -- but only once the image is built and
started, or the shell entered, and the previous run's output cleared. The
host resolves the config first, as a local scan of the same directory would
(``run_ash_scan._outer_mode_config_load``), so a chain a local scan's
confinement refuses is refused with exit 3 before the runner is invoked,
and the previous run's output stays as it was. The still-honored control
pins the fail direction: a valid operator config outside the tree reaches
the runner.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_container
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.inner_run_outcome import (
    OUTER_RUN_ID_ENV,
    completion_marker,
    record_reports_written,
)
from automated_security_helper.utils.subprocess_utils import create_completed_process
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit


def _checkout(root: Path) -> None:
    (root / ".git").mkdir(parents=True, exist_ok=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")


def _write(path: Path, doc: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _layout(name: str, w: Path):
    """(src, config, env): a scanned checkout whose config's chain leaves its root.

    The chain is refused by a local scan of the same inputs (confinement), so
    the host-side resolve has to refuse it too, before the runner.
    """
    _checkout(w / "repo")
    src = w / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    env = None
    if name == "in-src-extends-out":
        _write(w / "repo" / "shared.yaml", {"project_name": "op"})
        config = _write(src / "cfg" / "ash.yaml", {"extends": "../../shared.yaml"})
    elif name == "in-src-extends-link-out":
        _write(w / "ops" / "base.yaml", {"project_name": "op"})
        link = src / "cfg" / "lnk.yaml"
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to("../../../ops/base.yaml")
        config = _write(src / "cfg" / "ash.yaml", {"extends": "lnk.yaml"})
    elif name == "checkout-extends-out":
        _write(w / "ops" / "base.yaml", {"project_name": "op"})
        config = _write(
            w / "repo" / "ci" / "ash.yaml", {"extends": "../../ops/base.yaml"}
        )
    elif name == "env-in-src-extends-out":
        _write(w / "ops" / "base.yaml", {"project_name": "env"})
        config = env = _write(
            src / "cfg" / "child.yaml",
            {"extends": "../../../ops/base.yaml", "project_name": "child"},
        )
    elif name == "valid-out-of-tree":
        config = _write(w / "ops" / "ash.yaml", {"project_name": "op"})
    else:
        raise AssertionError(name)
    return src, config, env


@pytest.fixture
def recording_runner(monkeypatch):
    """Every runner command is recorded, none is started."""
    commands: list[list[str]] = []

    def record(cmd_list, *args, **kwargs):
        cmd = [str(item) for item in cmd_list if item is not None]
        commands.append(cmd)
        if len(cmd) > 1 and cmd[1] == "run":
            # The scan inside records that the run with the host's ID completed
            # (utils/inner_run_outcome.py); the ID reaches the runner through
            # its environment, named with -e and no value on the command line.
            run_id = (kwargs.get("env") or {}).get(OUTER_RUN_ID_ENV)
            document = {
                "sarif": None,
                "scanners": [],
                "validation_checkpoints": (
                    [completion_marker(run_id)] if run_id else []
                ),
            }
            for i, arg in enumerate(cmd[:-1]):
                if arg == "--mount":
                    fields = dict(
                        part.partition("=")[::2] for part in cmd[i + 1].split(",")
                    )
                    if fields.get("destination") == "/out":
                        Path(
                            fields["source"], "ash_aggregated_results.json"
                        ).write_text(json.dumps(document), encoding="utf-8")
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        run_ash_container, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(
        run_ash_container, "_runner_supports_buildx", lambda _runner: False
    )
    monkeypatch.setattr(run_ash_container, "run_cmd_direct", record)
    for name in (
        "ASH_CONFIG",
        "ASH_WORKSPACE",
        "ASH_WORKSPACE_CONFIG",
        "ASH_IMAGE_NAME",
    ):
        monkeypatch.delenv(name, raising=False)
    return commands


def _api_exit(src: Path, out: Path, config) -> int:
    try:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=RunMode.container,
            build=False,
            config=str(config) if config is not None else None,
            show_summary=False,
            progress=False,
            quiet=True,
        )
    except SystemExit as refusal:
        return int(refusal.code or 0)
    return 0


@pytest.mark.parametrize(
    "name",
    ["in-src-extends-out", "in-src-extends-link-out", "checkout-extends-out"],
)
def test_a_chain_leaving_the_tree_is_refused_before_the_runner(
    tmp_path, recording_runner, name
):
    src, config, _env = _layout(name, tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    previous = out / "previous.txt"
    previous.write_text("kept\n", encoding="utf-8")
    assert _api_exit(src, out, config) == 3
    assert recording_runner == [], "refused before the runner was invoked"
    assert previous.read_text(encoding="utf-8") == "kept\n", (
        "the previous run's output was left as it was"
    )


def test_an_ash_config_whose_base_leaves_the_tree_is_refused_before_the_runner(
    tmp_path, recording_runner, monkeypatch
):
    src, config, env = _layout("env-in-src-extends-out", tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(env))
    out = tmp_path / "out"
    out.mkdir()
    assert _api_exit(src, out, config) == 3
    assert recording_runner == []


def test_the_cli_route_carries_the_refusal(tmp_path, recording_runner):
    src, config, _env = _layout("in-src-extends-out", tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--source-dir",
            str(src),
            "--output-dir",
            str(out),
            "--config",
            str(config),
        ],
    )
    assert result.exit_code == 3, result.output
    assert recording_runner == []


def test_nix_mode_judges_the_config_the_same_way(
    tmp_path, recording_runner, monkeypatch
):
    src, config, _env = _layout("in-src-extends-out", tmp_path)
    out = tmp_path / "out"
    out.mkdir()

    def never(*_args, **_kwargs):
        raise AssertionError("the nix launcher was invoked")

    monkeypatch.setattr(ras, "run_ash_nix", never)
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)
    with pytest.raises(SystemExit) as refusal:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=RunMode.nix,
            config=str(config),
            show_summary=False,
            progress=False,
            quiet=True,
        )
    assert int(refusal.value.code or 0) == 3


def test_an_image_built_from_another_revision_leaves_a_model_refusal_to_the_scan_inside(
    tmp_path, recording_runner, monkeypatch
):
    """A config this tree's model refuses on SCHEMA alone is not refused when
    the image is built with an ASH from another revision
    (``_image_ash_revision_differs``): that build installs a schema this
    process cannot check against its own code, so a field this revision does
    not declare may be one the image's revision does, and the model is that
    image's own ASH's to judge. Parse and confinement stay the host's (the
    cells below), and so does a model refusal in every other image state:
    the LOCAL-build, ``--no-build`` and custom-Containerfile cells beside
    this one."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    code = _exit_of_a_scan(src, out, config, build=True, ash_revision_to_install="main")
    assert code == 0
    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner), (
        "the run went to the scan inside, whose own model judges the field"
    )


def test_a_schema_mismatch_with_a_local_image_is_still_refused(
    tmp_path, recording_runner
):
    """Control: an image built from this source tree holds this schema, so the
    host's refusal stands and the runner is never invoked."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    out = tmp_path / "out"
    out.mkdir()
    try:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=RunMode.container,
            build=True,
            ash_revision_to_install="LOCAL",
            config=str(config),
            show_summary=False,
            progress=False,
            quiet=True,
        )
    except SystemExit as refusal:
        assert int(refusal.code or 0) == 3
    else:
        raise AssertionError("a local-image schema mismatch was not refused")
    assert not any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner)


def test_an_image_built_from_this_tree_still_refuses_a_model_refusal(
    tmp_path, monkeypatch
):
    """The gate-level twin of the cell above: an image built from this source
    tree holds this schema, so the model's refusal is the host's own answer,
    worded before anything is built, started or cleared."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, ash_revision_to_install="LOCAL"
    )
    refusal = ras._outer_mode_config_load(opts).refusal
    assert refusal is not None
    assert "Configuration validation failed" in str(refusal)


def test_a_run_that_does_not_build_its_image_still_refuses_a_model_refusal(
    tmp_path, recording_runner
):
    """``--no-build`` runs whatever image is already present, which is just as
    unverifiable as another revision's build -- but this process still reads
    the config for its own decisions, the sandbox floor and its reporting
    among them, so the full refusal holds and the runner is never invoked."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    out = tmp_path / "out"
    out.mkdir()
    assert _api_exit(src, out, config) == 3
    assert recording_runner == []


def test_an_image_built_from_a_custom_containerfile_still_refuses_a_model_refusal(
    tmp_path, monkeypatch
):
    """A custom Containerfile makes the image's schema unverifiable without
    changing what this process itself reads the config for, so a model
    refusal of the selected file stands at the gate."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, custom_containerfile="Containerfile.custom"
    )
    refusal = ras._outer_mode_config_load(opts).refusal
    assert refusal is not None
    assert "Configuration validation failed" in str(refusal)


def test_a_confinement_violation_is_still_refused_when_the_image_may_differ(
    tmp_path, recording_runner
):
    """Control: the confinement judgment is the host's whatever the image
    holds -- a chain leaving its root is about which files are mounted, not
    about the model, so another revision's schema changes nothing."""
    src, config, _env = _layout("in-src-extends-out", tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    assert _api_exit(src, out, config) == 3
    assert recording_runner == []


def test_an_image_built_from_another_revision_still_refuses_a_chain_leaving_the_tree(
    tmp_path, recording_runner
):
    """Confinement is about which files are mounted, not about the model, so
    an ``extends`` chain leaving its root is refused whatever ASH the image
    holds -- another revision's build included."""
    src, config, _env = _layout("in-src-extends-out", tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    code = _exit_of_a_scan(src, out, config, build=True, ash_revision_to_install="main")
    assert code == 3
    assert recording_runner == []


def test_an_unparseable_config_is_still_refused_when_the_image_may_differ(
    tmp_path, recording_runner
):
    """Control: a file that does not parse is unreadable for every revision,
    so the host refuses it before the runner whatever image is named."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: [unclosed\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    assert _api_exit(src, out, config) == 3
    assert recording_runner == []


def test_a_file_that_does_not_parse_is_refused_as_unparsed_whatever_the_revision(
    tmp_path, monkeypatch
):
    """The gate words a parse failure as a local scan does -- an unparsed
    file, never a model refusal -- in either image state, so the model arm is
    not where an unreadable text is judged."""
    from automated_security_helper.config.resolve_config import ConfigFileRefused

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ops" / "broken.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("a: [\n", encoding="utf-8")
    for revision in ("LOCAL", "main"):
        opts = _opts_for_the_exit_fields(
            tmp_path, config, build=True, ash_revision_to_install=revision
        )
        refusal = ras._outer_mode_config_load(opts).refusal
        assert refusal is not None, revision
        assert "could not be parsed" in str(refusal), (revision, str(refusal))
        assert not isinstance(refusal, ConfigFileRefused), revision


def test_an_ash_config_schema_mismatch_is_left_to_the_scan_inside(
    tmp_path, recording_runner, monkeypatch
):
    """The base the environment names is judged the same way: schema is the
    image's when it can differ, parse and confinement stay the host's."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    env = _write(
        tmp_path / "ops" / "env.yaml",
        {
            "project_name": "env",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(env))
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    assert _api_exit(src, out, None) == 0
    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner)


def test_a_valid_operator_config_still_reaches_the_runner(
    tmp_path, recording_runner, monkeypatch
):
    """The control: the pre-run resolve only takes runs away from invalid
    configs. A config a local scan loads is not refused, and the runner is
    invoked."""
    src, config, _env = _layout("valid-out-of-tree", tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    assert _api_exit(src, out, config) == 0
    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner), (
        "the runner was invoked for a valid config"
    )


_SARIF_WITH_A_HIGH_FINDING = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "bandit"}},
            "results": [
                {
                    "ruleId": "B101",
                    "level": "error",
                    "message": {"text": "finding"},
                    "properties": {
                        "scanner_name": "bandit",
                        "issue_severity": "HIGH",
                    },
                }
            ],
        }
    ],
}


@pytest.fixture
def runner_that_reports_a_finding(recording_runner, monkeypatch):
    """The recording runner, whose run also leaves a report with one HIGH
    finding in the output directory, as a scan inside the image does."""
    record = run_ash_container.run_cmd_direct

    def record_and_report(cmd_list, *args, **kwargs):
        completed = record(cmd_list, *args, **kwargs)
        cmd = [str(item) for item in cmd_list if item is not None]
        if len(cmd) > 1 and cmd[1] == "run":
            for i, arg in enumerate(cmd[:-1]):
                if arg == "--mount":
                    fields = dict(
                        part.partition("=")[::2] for part in cmd[i + 1].split(",")
                    )
                    if fields.get("destination") == "/out":
                        _write(
                            Path(fields["source"], "reports", "ash.sarif"),
                            _SARIF_WITH_A_HIGH_FINDING,
                        )
                        # As the scan inside records it: the SARIF reporter's
                        # file is named in the results, or the host's exit code
                        # does not read it (report_file_written_as).
                        results_path = Path(
                            fields["source"], "ash_aggregated_results.json"
                        )
                        document = json.loads(results_path.read_text(encoding="utf-8"))
                        holder = SimpleNamespace(
                            validation_checkpoints=document.get(
                                "validation_checkpoints", []
                            )
                        )
                        record_reports_written(holder, [("ash.sarif", "sarif")])
                        document["validation_checkpoints"] = (
                            holder.validation_checkpoints
                        )
                        results_path.write_text(json.dumps(document), encoding="utf-8")
        return completed

    monkeypatch.setattr(run_ash_container, "run_cmd_direct", record_and_report)
    return recording_runner


def _scan_exit_code(tmp_path: Path, config: Path) -> int:
    # Build + another revision: the one state that admits a model-refused
    # selected file now that the gate refuses it for a --no-build run.
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    return _exit_of_a_scan(src, out, config, build=True, ash_revision_to_install="main")


def test_an_admitted_config_that_turns_findings_exit_off_exits_zero(
    tmp_path, runner_that_reports_a_finding
):
    """The config only the image's schema accepts still sets the operator's
    exit behavior: with ``fail_on_findings: false`` in it, a finding in the
    scan's report does not make the host exit 2, though this tree's model does
    not load the file."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "fail_on_findings": False,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    assert _scan_exit_code(tmp_path, config) == 0
    assert any(
        len(cmd) > 1 and cmd[1] == "run" for cmd in runner_that_reports_a_finding
    )


def test_an_admitted_config_that_leaves_findings_exit_alone_exits_two(
    tmp_path, runner_that_reports_a_finding
):
    """Control: the same config without ``fail_on_findings`` keeps the default,
    so the finding in the scan's report exits 2."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    assert _scan_exit_code(tmp_path, config) == 2


def _opts_for_the_exit_fields(tmp_path: Path, config: Path, **overrides):
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True, exist_ok=True)
    # The surviving admission state: a model-refused selected file rides to
    # the scan inside only for an image built with an ASH from another
    # revision, so these cells pin that state (a --no-build run is refused
    # at the gate before the exit fields matter).
    overrides.setdefault("build", True)
    overrides.setdefault("ash_revision_to_install", "main")
    return ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        config=str(config),
        **overrides,
    )


def test_the_exit_fields_of_a_run_with_no_config_do_not_ask_for_the_image_revision(
    tmp_path, monkeypatch
):
    """Reading the exit fields of a run that has no config file asks nothing
    of the image's revision: asking logs which source the image is built
    from, which belongs to the run's own output, not to this read."""
    asked = []
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setattr(
        run_ash_container,
        "get_ash_revision",
        lambda quiet=False: asked.append(1) or "LOCAL",
    )
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        build=True,
    )

    assert ras._resolve_config_fail_on_findings(opts) is None
    assert ras._resolve_config_fail_on_incomplete_scanners(opts) is None
    assert asked == []


def test_the_exit_fields_of_an_admitted_config_are_read_from_its_document(tmp_path):
    """Both exit-code fields come from the file's resolved document when this
    tree's model does not load it and the image may differ."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": False,
            "fail_on_incomplete_scanners": False,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)
    # The fallback to the document's fields lives in the exit-fields loader; the
    # resolvers read the field off what it loaded, as the scan's callers do.
    loaded = ras._load_config_file_or_its_exit_fields(opts)
    assert ras._resolve_config_fail_on_findings(opts, loaded=loaded) is False
    assert ras._resolve_config_fail_on_incomplete_scanners(opts, loaded=loaded) is False


def test_an_exit_field_that_is_missing_keeps_its_default(tmp_path):
    """A field the document does not write reads as unset (None), the answer
    the caller replaces with the field's default."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {"global_settings": {"zz_option_a_later_schema_declares": True}},
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)
    assert ras._resolve_config_fail_on_findings(opts) is None
    assert ras._resolve_config_fail_on_incomplete_scanners(opts) is None


@pytest.mark.parametrize("value", ["no", "false", "off", 0, 1, None])
def test_an_exit_field_the_model_refuses_reads_as_unset(tmp_path, value):
    """A config file is validated strictly, so the model refuses a text or a
    number at a boolean field: ``"no"`` and ``0`` are not False there, and
    ``1`` is not True. The fallback reads the value the way the model reads a
    file's, so it neither turns an exit code off for text the image's own ASH
    refuses the file over, nor keeps one the model would not."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": value,
            "fail_on_incomplete_scanners": value,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)
    assert ras._resolve_config_fail_on_findings(opts) is None
    assert ras._resolve_config_fail_on_incomplete_scanners(opts) is None


@pytest.mark.parametrize("value", [True, False])
def test_an_exit_field_name_the_model_does_not_declare_reads_as_unset(value):
    """A name the model no longer declares is a value it refuses: it reads as
    unset, like any other refused value, and does not raise."""
    assert ras._exit_field_as_the_model_reads_it("an_exit_field_renamed", value) is None


def test_a_stale_exit_field_name_does_not_stop_the_other_field_being_read(
    tmp_path, monkeypatch
):
    """With a name in the list that the model does not declare, the fallback
    still reads the field that is declared, and the stale one reads as unset."""
    monkeypatch.setattr(
        ras, "_EXIT_FIELDS", ("fail_on_findings", "an_exit_field_renamed")
    )
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": False,
            "an_exit_field_renamed": True,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)

    fields = ras._load_config_file_or_its_exit_fields(opts)

    assert fields.fail_on_findings is False
    assert not hasattr(fields, "an_exit_field_renamed")


def test_every_exit_field_the_fallback_reads_is_a_field_of_the_model():
    """The list the fallback reads and the model are one vocabulary: a rename
    of either side alone fails here instead of unsetting an exit field."""
    from automated_security_helper.config.ash_config import AshConfig

    assert set(ras._EXIT_FIELDS) <= set(AshConfig.model_fields)


def test_an_exit_field_is_read_with_the_constraints_its_annotation_carries(
    monkeypatch,
):
    """pydantic moves an ``Annotated`` field's constraints out of the
    annotation into the field's metadata. Read through the annotation alone, a
    field that comes to carry one would accept a value the model refuses, and
    turn an exit code off the image's own ASH keeps."""
    from typing import Annotated

    from annotated_types import Gt
    from pydantic.fields import FieldInfo

    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.setitem(
        AshConfig.model_fields,
        "fail_on_findings",
        FieldInfo.from_annotation(Annotated[int, Gt(5)]),
    )

    assert ras._exit_field_as_the_model_reads_it("fail_on_findings", 3) is None
    assert ras._exit_field_as_the_model_reads_it("fail_on_findings", 9) == 9


#: The field validators every section inherits that reach an exit field and are
#: pinned below to only refuse: the section base's before-validator on every
#: field (``RedactedSection``), which refuses text resolved from an environment
#: reference at a boolean field, bare or held in a container, by a named
#: refusal that keeps the reference marker on the error's input, and hands every
#: value that holds no such text on as it is.
_VALIDATORS_THAT_ONLY_REFUSE_AN_EXIT_FIELD_REFERENCE = frozenset(
    {"_env_resolved_text_reads_as_the_field_type"}
)


@pytest.mark.parametrize("name", ras._EXIT_FIELDS)
def test_no_field_validator_reaches_an_exit_field(name):
    """The exit-field read applies the field's annotation and constraints, not
    the model's validators. A validator added for either field must be read
    through before the fallback can keep agreeing with the model, so this
    fails when one is added. The one every section carries is named above and
    pinned by the next cell to only refuse."""
    from automated_security_helper.config.ash_config import AshConfig

    validators = AshConfig.__pydantic_decorators__.field_validators
    reaching = sorted(
        key
        for key, decorator in validators.items()
        if (name in decorator.info.fields or "*" in decorator.info.fields)
        and key not in _VALIDATORS_THAT_ONLY_REFUSE_AN_EXIT_FIELD_REFERENCE
    )

    assert reaching == [], reaching


@pytest.mark.parametrize("name", ras._EXIT_FIELDS)
def test_the_validator_every_section_carries_only_refuses_an_exit_field_reference(
    name,
):
    """The validator the cell above leaves out takes a value that is not text
    resolved from an environment reference as it is, and refuses that text at a
    boolean field. The exit-field read refuses the same text (a boolean is not
    a string under strict typing), so the read and the model agree on it.

    The refusal is the validator's own, not the strict typing that would refuse
    the text anyway: it is a value error that names the variable, and the error
    keeps the reference marker as its input. A validator that handed the text on
    as a plain str would still end in a validation error here, so the cell reads
    the error's type, message and input."""
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.redacted_model import (
        EnvResolvedScalar,
        env_resolved_scalar,
    )

    AshConfig.model_rebuild()
    reference = env_resolved_scalar(_RESOLVED_TEXT, _EXIT_FIELD_VARIABLE)
    context = {"strict_file_load": True}

    with pytest.raises(ValidationError) as refused:
        AshConfig.model_validate({name: reference}, strict=True, context=context)
    problem = _the_one_named_refusal(refused.value)
    assert isinstance(problem["input"], EnvResolvedScalar), problem
    assert ras._exit_field_as_the_model_reads_it(name, reference) is None

    loaded = AshConfig.model_validate({name: False}, strict=True, context=context)
    assert getattr(loaded, name) is False
    assert ras._exit_field_as_the_model_reads_it(name, False) is False


_EXIT_FIELD_VARIABLE = "ASH_AN_EXIT_FIELD_VARIABLE"
_RESOLVED_TEXT = "resolved-text-the-refusal-must-not-repeat"


def _the_one_named_refusal(error):
    """The single error pydantic holds for a reference the section base's
    validator refused: a value error whose message names the variable and
    carries none of the resolved text."""
    problems = error.errors(include_url=False)
    assert len(problems) == 1, problems
    problem = problems[0]
    assert problem["type"] == "value_error", problem
    assert _EXIT_FIELD_VARIABLE in problem["msg"], problem
    assert "Input should be a valid boolean" in problem["msg"], problem
    assert _RESOLVED_TEXT not in problem["msg"], problem
    return problem


_CONTAINERS_HOLDING_A_REFERENCE = {
    "list": lambda reference: [reference],
    "tuple": lambda reference: (reference,),
    "set": lambda reference: {reference},
    "dict": lambda reference: {"key": reference},
    "nested": lambda reference: [{"key": (reference,)}],
}


@pytest.mark.parametrize("route", ["file", "plugin"])
@pytest.mark.parametrize("shape", _CONTAINERS_HOLDING_A_REFERENCE)
@pytest.mark.parametrize("name", ras._EXIT_FIELDS)
def test_a_container_holding_a_reference_at_an_exit_field_is_refused_by_name(
    name, shape, route
):
    """A list, tuple, set or dict that holds text resolved from an environment
    reference draws the refusal a bare reference draws at the field: a value
    error that names the variable, with the reference marker still on the
    error's input. It is not handed on as a copy with the marker downcast to
    plain text, which strict typing then refuses with an error that names no
    variable and whose input is a plain list of the resolved text. A container
    with no reference in it is not the validator's to refuse: pydantic's own
    boolean error stands."""
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.utils.redacted_model import (
        env_resolved_scalar,
        first_env_scalar,
    )

    AshConfig.model_rebuild()
    reference = env_resolved_scalar(_RESOLVED_TEXT, _EXIT_FIELD_VARIABLE)
    container = _CONTAINERS_HOLDING_A_REFERENCE[shape](reference)
    if route == "file":
        arguments = {"strict": True, "context": {"strict_file_load": True}}
    else:
        arguments = {}

    with pytest.raises(ValidationError) as refused:
        AshConfig.model_validate({name: container}, **arguments)
    problem = _the_one_named_refusal(refused.value)
    assert first_env_scalar(problem["input"]) is reference, problem
    assert ras._exit_field_as_the_model_reads_it(name, container) is None

    with pytest.raises(ValidationError) as plain:
        AshConfig.model_validate({name: _plain_copy_of(container)}, **arguments)
    assert [item["type"] for item in plain.value.errors()] == ["bool_type"]


def _plain_copy_of(container):
    """*container* with its reference written as the plain text it resolved
    to, which holds no marker."""
    if isinstance(container, dict):
        return {key: _plain_copy_of(item) for key, item in container.items()}
    if isinstance(container, (list, tuple, set)):
        return type(container)(_plain_copy_of(item) for item in container)
    return str(container)


def test_a_refused_exit_field_does_not_hide_the_one_beside_it(tmp_path):
    """Each field is read on its own: one the model refuses reads as unset
    and the other keeps what the file wrote."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": False,
            "fail_on_incomplete_scanners": "off",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)
    loaded = ras._load_config_file_or_its_exit_fields(opts)
    assert ras._resolve_config_fail_on_findings(opts, loaded=loaded) is False
    assert ras._resolve_config_fail_on_incomplete_scanners(opts, loaded=loaded) is None


class _StoppedBeforeTheRun(Exception):
    """Raised in place of the container run, after the exit fields are read."""


def test_the_gate_and_the_exit_fields_resolve_the_selected_document_once(
    tmp_path, recording_runner, monkeypatch
):
    """The pre-run gate resolves the selected file, and the exit-field read
    that follows takes that document: the host resolves the file once, so the
    two cannot judge two versions of a file that changes between them.

    The model load (``AshConfig.from_file``) resolves the chain through the name
    ``resolve_config`` imported, so the walks made by the exit-field read are
    counted there as well as the gate's at ``config_sources``: counting the one
    name alone cannot see that load. The watcher must have been entered: if the
    exit-field read stopped going through the name it wraps, the gate's walk
    alone would still make the count one and the cell would pass without
    having looked at the read.

    The sandbox-mode probe (``_refuse_symlinked_output_dir``) is not counted
    here either: it returns at once for a container run, which every scan of
    this cell is, and it is not the exit-field read. For a local scan it
    resolves the selected file a second time through ``resolve_config`` and
    takes no document from the gate; the cell below asks what it takes from
    the scan."""
    from automated_security_helper.config import config_sources, resolve_config

    resolved = []
    in_the_exit_field_read = []
    entered = []
    real = config_sources.resolve_config_document
    real_exit_field_read = ras._load_config_file_or_its_exit_fields

    def counting(*args, **kwargs):
        # Only the host's own reader passes the repository hooks.
        if "repository_file" in kwargs:
            resolved.append(args[0])
        return real(*args, **kwargs)

    def counting_the_model_load(*args, **kwargs):
        if in_the_exit_field_read and "repository_file" in kwargs:
            resolved.append(args[0])
        return real(*args, **kwargs)

    def watching_the_exit_field_read(*args, **kwargs):
        entered.append(True)
        in_the_exit_field_read.append(True)
        try:
            return real_exit_field_read(*args, **kwargs)
        finally:
            in_the_exit_field_read.pop()

    monkeypatch.setattr(config_sources, "resolve_config_document", counting)
    monkeypatch.setattr(
        resolve_config, "resolve_config_document", counting_the_model_load
    )
    monkeypatch.setattr(
        ras, "_load_config_file_or_its_exit_fields", watching_the_exit_field_read
    )
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": False,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    assert _scan_exit_code(tmp_path, config) == 0
    assert entered, "the exit-field read never went through the watched name"
    assert len(resolved) == 1, resolved


def test_the_sandbox_mode_probe_asks_for_the_selected_file_with_the_scans_base_gate(
    tmp_path, monkeypatch
):
    """What a local scan's sandbox-mode probe takes from the scan. A scan whose
    output directory is reached through a link asks the sandbox mode of the
    configuration (``_refuse_symlinked_output_dir``), and it resolves the
    selected file again through ``resolve_config`` with the scan's own
    arguments: no document of the gate's is handed to it, so a file that
    changes between the gate and the probe is read in two versions. The probe
    only decides whether the sandbox is on (an unresolvable file counts as on),
    and the scan's own load judges the file. This cell pins the two things the
    probe must take from the scan, one resolve of the selected path and the
    scan's base gate; it does not pin the rest of the call."""
    from automated_security_helper.config import resolve_config as resolving
    from automated_security_helper.utils.sandbox import policy

    def unavailable(*_args, **_kwargs):
        raise policy.SandboxUnavailable("the output directory is a symlink")

    asked = []

    def resolve_the_sandbox_mode(**kwargs):
        asked.append(kwargs)
        return SimpleNamespace(sandbox=SimpleNamespace(mode="off"))

    monkeypatch.setattr(policy, "refuse_symlinked_output_dir", unavailable)
    monkeypatch.setattr(resolving, "resolve_config", resolve_the_sandbox_mode)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    gate = object()
    opts = SimpleNamespace(
        mode=RunMode.local,
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=str(config),
        config_overrides=["project_name=other"],
        config_base_gate=gate,
        workspace_plan=None,
    )

    ras._refuse_symlinked_output_dir(opts)

    assert len(asked) == 1, asked
    assert asked[0]["config_path"] == str(config), asked
    assert asked[0]["permit_base"] is gate, asked


def test_the_exit_field_read_takes_the_gates_answer_about_the_image(
    tmp_path, recording_runner, monkeypatch
):
    """Asking for the image's revision logs which source the image is built
    from. The gate asks with its records dropped; the exit-field read, which
    runs after the logger is set up, takes that answer and asks nothing."""
    asked = []
    monkeypatch.setattr(
        run_ash_container,
        "get_ash_revision",
        lambda: asked.append(1) or "0123456789abcdef",
    )
    asked_by_the_exit_field_read = []
    real = ras._load_config_file_or_its_exit_fields

    def watching(*args, **kwargs):
        before = len(asked)
        try:
            return real(*args, **kwargs)
        finally:
            asked_by_the_exit_field_read.append(len(asked) - before)

    def stop(*_args, **_kwargs):
        raise _StoppedBeforeTheRun

    monkeypatch.setattr(ras, "_load_config_file_or_its_exit_fields", watching)
    monkeypatch.setattr(ras, "_run_container_mode", stop)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(_StoppedBeforeTheRun):
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=RunMode.container,
            build=True,
            config=str(config),
            show_summary=False,
            progress=False,
            quiet=True,
        )
    assert asked == [1], "the revision was asked for once for the whole scan"
    assert asked_by_the_exit_field_read == [0]


def test_a_local_image_does_not_read_the_exit_fields_from_a_refused_config(tmp_path):
    """Control: for an image built from this tree the model's refusal stands
    and the exit fields read as unset, as they always did."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": False,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, ash_revision_to_install="LOCAL"
    )
    assert ras._resolve_config_fail_on_findings(opts) is None


def _in_tree_ash_config(tmp_path: Path, monkeypatch, extends: str, base_at: str):
    """(src, out, named): an ASH_CONFIG file at ``app/cfg/child.yaml`` that
    extends *extends*, with the base written at *base_at* under the source
    directory, and a valid ``--config`` outside the tree beside it."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    _write(src / base_at, {"project_name": "base"})
    env = _write(src / "cfg" / "child.yaml", {"extends": extends})
    named = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    monkeypatch.setenv("ASH_CONFIG", str(env))
    out = tmp_path / "out"
    out.mkdir()
    return src, out, named


def test_an_ash_config_base_outside_its_directory_is_refused_when_the_image_may_differ(
    tmp_path, recording_runner, monkeypatch
):
    """The file ASH_CONFIG names is judged the way the scan loads it
    (``default_config_for_tree``): its bases stay in its own directory, so a
    base elsewhere in the scanned tree, which ``--config`` would allow, is
    refused whatever image is named."""
    src, out, named = _in_tree_ash_config(
        tmp_path, monkeypatch, extends="../base.yaml", base_at="base.yaml"
    )
    assert _api_exit(src, out, named) == 3
    assert recording_runner == []


def test_an_ash_config_base_outside_its_directory_is_refused_for_a_local_image(
    tmp_path, recording_runner, monkeypatch
):
    """Control: an image built from this source tree refuses the same layout,
    so the two judgments agree."""
    src, out, named = _in_tree_ash_config(
        tmp_path, monkeypatch, extends="../base.yaml", base_at="base.yaml"
    )
    try:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=RunMode.container,
            build=True,
            ash_revision_to_install="LOCAL",
            config=str(named),
            show_summary=False,
            progress=False,
            quiet=True,
        )
    except SystemExit as refusal:
        assert int(refusal.code or 0) == 3
    else:
        raise AssertionError("an ASH_CONFIG base outside its directory was admitted")
    assert recording_runner == []


def test_an_ash_config_base_in_its_own_directory_is_admitted_when_the_image_may_differ(
    tmp_path, recording_runner, monkeypatch
):
    """Control: a base beside the ASH_CONFIG file is inside its directory, so
    the run reaches the scan inside."""
    src, out, named = _in_tree_ash_config(
        tmp_path, monkeypatch, extends="base.yaml", base_at="cfg/base.yaml"
    )
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    assert _api_exit(src, out, named) == 0
    assert any(len(cmd) > 1 and cmd[1] == "run" for cmd in recording_runner)


@pytest.mark.parametrize("error", [MemoryError])
def test_a_failure_that_is_not_a_file_read_propagates_from_the_gate(
    tmp_path, monkeypatch, error
):
    """The gate answers only the read errors it names (a missing or unreadable
    file, a file that does not parse or is nested past the recursion limit).
    A failure that is none of those is not hidden as "no refusal"."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, ash_revision_to_install="LOCAL"
    )

    def fail(*_args, **_kwargs):
        raise error("not a file read")

    monkeypatch.setattr(ras, "_loaded_config_file", fail)
    with pytest.raises(error):
        ras._outer_mode_config_load(opts)


def test_a_recursion_error_outside_any_file_read_still_propagates_from_the_gate(
    tmp_path, monkeypatch
):
    """A RecursionError is refused as an over-nested file only where a file's
    text is parsed. One raised after the load, where no file is under way, is a
    bug in the host and is not worded as a config refusal."""
    from automated_security_helper.config import resolve_config

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, ash_revision_to_install="LOCAL"
    )

    def fail(*_args, **_kwargs):
        raise RecursionError("after the load")

    monkeypatch.setattr(resolve_config, "apply_config_overrides", fail)
    with pytest.raises(RecursionError):
        ras._outer_mode_config_load(opts)


def test_a_recursion_error_inside_the_load_but_not_in_a_parse_propagates_from_the_gate(
    tmp_path, monkeypatch
):
    """The load of the selected config file raises RecursionError without any
    file's text failing to parse, so the gate does not word it as an unparsed
    file. Only the parse site classifies a file nested too deep."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, ash_revision_to_install="LOCAL"
    )

    def fail(*_args, **_kwargs):
        raise RecursionError("in the load, not in a parse")

    monkeypatch.setattr(ras, "_loaded_config_file", fail)
    with pytest.raises(RecursionError):
        ras._outer_mode_config_load(opts)


def test_an_unparsable_config_for_a_local_image_is_refused_at_the_gate(
    tmp_path, recording_runner, monkeypatch
):
    """The this-tree branch loads the model, and the load raises the parser's
    own error for a file that does not parse. The gate words it as a local
    scan does: exit 3 naming the file, with no image built, no container
    started and the previous run's output left alone."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: [unclosed\n", encoding="utf-8")
    opts = _opts_for_the_exit_fields(
        tmp_path, config, build=True, ash_revision_to_install="LOCAL"
    )
    refusal = ras._outer_mode_config_load(opts).refusal

    assert isinstance(refusal, ras.ASHConfigValidationError)
    assert "ash.yaml could not be parsed" in str(refusal)

    out = tmp_path / "out"
    previous = out / "reports" / "ash.sarif"
    previous.parent.mkdir(parents=True)
    previous.write_text('{"runs": []}\n', encoding="utf-8")
    src = tmp_path / "repo" / "app"
    assert (
        _exit_of_a_scan(src, out, config, build=True, ash_revision_to_install="LOCAL")
        == 3
    )
    assert recording_runner == [], "no image was built and no container started"
    assert previous.exists(), "the previous run's output was cleared"


def test_an_unreadable_config_file_is_refused_not_raised(
    tmp_path, recording_runner, capsys
):
    """A permission failure on the named file is a read error the gate defers
    to the checks that own it, so it lands in the same refusal as a missing
    file (exit 3, the file named, no runner) rather than escaping as a
    traceback. In container mode the handover check owns it and says ASH does
    not hand the container runner a file it cannot read itself."""
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("needs POSIX permission bits, which root reads past")
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = tmp_path / "ops" / "unreadable.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: op\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    config.chmod(0)
    try:
        code = _api_exit(src, out, config)
    finally:
        config.chmod(0o600)

    assert code == 3
    assert recording_runner == [], "refused before the runner was invoked"
    captured = capsys.readouterr()
    shown = captured.out + captured.err
    assert "unreadable.yaml" in shown, shown
    assert "cannot be read" in shown, shown


def _nix_opts(tmp_path: Path, config: Path):
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    return ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
        config=str(config),
    )


def test_nix_mode_refuses_a_missing_config_at_the_gate(tmp_path, monkeypatch):
    """Records nix mode: a ``--config`` naming no file is refused by the gate
    itself (``_unusable_nix_config``), naming the file."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    missing = tmp_path / "ops" / "never-written.yaml"

    refusal = ras._outer_mode_config_load(_nix_opts(tmp_path, missing)).refusal

    assert refusal is not None
    assert "Configuration file not found" in str(refusal)
    assert "never-written.yaml" in str(refusal)


def test_nix_mode_refuses_an_unparsable_config_before_clearing_output(
    tmp_path, monkeypatch
):
    """Nix mode on the this-tree branch: a file that exists but does not parse
    is refused by the gate as a local scan refuses it (exit 3, the file
    named), before the shell is entered and before the previous run's output
    is cleared."""
    from unittest.mock import MagicMock

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text("project_name: [unclosed\n", encoding="utf-8")
    opts = _nix_opts(tmp_path, config)
    out = tmp_path / "out"
    previous = out / "reports" / "ash.sarif"
    previous.parent.mkdir(parents=True)
    previous.write_text('{"runs": []}\n', encoding="utf-8")

    refusal = ras._outer_mode_config_load(opts).refusal
    assert isinstance(refusal, ras.ASHConfigValidationError)
    assert "ash.yaml could not be parsed" in str(refusal)

    launcher = MagicMock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(ras, "run_ash_nix", launcher)
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)
    with pytest.raises(SystemExit) as finished:
        ras.run_ash_scan(
            source_dir=str(opts.source_dir),
            output_dir=str(out),
            mode=RunMode.nix,
            config=str(config),
            show_summary=False,
            progress=False,
            quiet=True,
        )

    assert finished.value.code == 3
    assert launcher.call_count == 0, "the shell was entered"
    assert previous.exists(), "the previous run's output was cleared"


def test_a_scan_with_no_config_asks_no_image_revision_question(monkeypatch):
    """With no config file selected there is nothing whose schema could
    differ, so the exit-field load answers None without probing the image
    revision, a probe that can print to stdout."""
    probes: list[int] = []
    monkeypatch.setattr(ras, "_load_config_file", lambda opts: None)
    monkeypatch.setattr(ras, "_selected_config_path", lambda opts: None)
    monkeypatch.setattr(
        ras, "_image_schema_may_differ", lambda opts: probes.append(1) or True
    )

    opts = SimpleNamespace(mode=RunMode.container)
    assert ras._load_config_file_or_its_exit_fields(opts) is None
    assert probes == [], probes


@pytest.mark.parametrize("mode", [RunMode.local, RunMode.nix])
def test_a_scan_outside_container_mode_runs_no_second_config_discovery(
    monkeypatch, mode
):
    """Only a container scan has an image whose schema can differ. A local or
    nix scan with no loadable config answers None without searching for the
    config file again, which is the common no-config case."""
    discoveries: list[int] = []
    monkeypatch.setattr(ras, "_load_config_file", lambda opts: None)
    monkeypatch.setattr(
        ras, "_selected_config_path", lambda opts: discoveries.append(1)
    )

    assert ras._load_config_file_or_its_exit_fields(SimpleNamespace(mode=mode)) is None
    assert discoveries == [], discoveries


def test_the_loaded_exit_fields_file_is_keyword_only(tmp_path):
    """``None`` is a loaded answer (no config file found), so a caller that
    still hands the second parameter positionally must fail loudly instead of
    reading the argument as an already-loaded file."""
    config = _write(tmp_path / "ops" / "ash.yaml", {"fail_on_findings": False})
    opts = _opts_for_the_exit_fields(tmp_path, config)

    with pytest.raises(TypeError):
        ras._resolve_config_fail_on_findings(opts, None)
    with pytest.raises(TypeError):
        ras._resolve_config_fail_on_incomplete_scanners(opts, None)
    assert ras._resolve_config_fail_on_findings(opts, loaded=None) is None
    assert ras._resolve_config_fail_on_incomplete_scanners(opts, loaded=None) is None


def test_handed_in_answers_are_not_asked_for_again(tmp_path, monkeypatch):
    """The gate's resolved document and image answer, handed to the exit-field
    read, replace its own selection, resolution and image question."""
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "fail_on_findings": False,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)
    document = ras._parse_and_confine_config(str(config), opts)

    asked: list[str] = []

    def recording(name, answer):
        def stub(*_args, **_kwargs):
            asked.append(name)
            return answer

        return stub

    for name, answer in {
        "_load_config_file": None,
        "_loaded_config_file": None,
        "_load_with_confinement": None,
        "_selected_config_path": str(config),
        "_parse_and_confine_config": document,
        "_image_schema_may_differ": True,
    }.items():
        monkeypatch.setattr(ras, name, recording(name, answer))

    handed = ras._load_config_file_or_its_exit_fields(
        opts, document=document, image_may_differ=True, model=None
    )
    assert handed.fail_on_findings is False
    assert (
        ras._load_config_file_or_its_exit_fields(
            opts, document=None, image_may_differ=True, model=None
        )
        is None
    )
    assert asked == [], asked


def test_a_handed_in_document_the_model_accepts_gives_the_model_without_a_reload(
    tmp_path, monkeypatch
):
    """With the gate's document in hand the model is built from it, not from
    the file again; the answer is the model's, defaults included, as the
    load of the file gave it."""
    from automated_security_helper.config.ash_config import AshConfig

    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {"project_name": "op", "fail_on_findings": False},
    )
    opts = _opts_for_the_exit_fields(tmp_path, config)
    document = ras._parse_and_confine_config(str(config), opts)

    def never(*_args, **_kwargs):
        raise AssertionError("loaded again")

    monkeypatch.setattr(ras, "_load_config_file", never)
    loaded = ras._load_config_file_or_its_exit_fields(
        opts, document=document, image_may_differ=True
    )

    assert isinstance(loaded, AshConfig), type(loaded)
    assert loaded.fail_on_findings is False
    assert loaded.fail_on_incomplete_scanners is True


def test_a_selected_file_the_model_cannot_load_still_asks_the_image_question(
    monkeypatch, tmp_path
):
    """The must-not twin: with a config file selected and not loadable, the
    image-schema question is still asked, so a differing image keeps its
    exit-field fallback."""
    probes: list[int] = []
    monkeypatch.setattr(ras, "_load_config_file", lambda opts: None)
    monkeypatch.setattr(
        ras, "_selected_config_path", lambda opts: tmp_path / "ash.yaml"
    )
    monkeypatch.setattr(
        ras, "_image_schema_may_differ", lambda opts: probes.append(1) or False
    )

    opts = SimpleNamespace(mode=RunMode.container)
    assert ras._load_config_file_or_its_exit_fields(opts) is None
    assert probes == [1], probes


@pytest.fixture
def unreadable():
    """``unreadable(path)`` takes every permission off *path* for the test and
    gives them back after it. Skipped where the mode does not keep this
    process out of the file (a process running as root reads it anyway)."""
    taken = []

    def take_away(path: Path) -> Path:
        path.chmod(0o000)
        taken.append(path)
        if os.access(path, os.R_OK):
            pytest.skip("the permission bits do not keep this process out of a file")
        return path

    yield take_away
    for path in taken:
        path.chmod(0o600)


_BUILDS = {
    "image-built-from-this-tree": {"build": True, "ash_revision_to_install": "LOCAL"},
    "image-that-may-differ": {"build": False},
}


def _scan_options_for_the_gate(src: Path, out: Path, config, **options):
    return ras.ScanOptions(
        source_dir=src,
        output_dir=out,
        mode=RunMode.container,
        config=str(config) if config is not None else None,
        **options,
    )


def _exit_of_a_scan(src: Path, out: Path, config, **options) -> int:
    try:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=RunMode.container,
            config=str(config) if config is not None else None,
            show_summary=False,
            progress=False,
            quiet=True,
            **options,
        )
    except SystemExit as refusal:
        return int(refusal.code or 0)
    return 0


@pytest.mark.parametrize("build", sorted(_BUILDS))
def test_an_ash_config_file_that_cannot_be_read_is_refused_at_the_gate(
    tmp_path, recording_runner, monkeypatch, unreadable, build
):
    """The environment's config is read at the gate, not handed over unread, so
    a file ``ASH_CONFIG`` names that exists but cannot be read is refused there
    with exit 3 whichever image is named, and the runner is never invoked."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    env = unreadable(_write(tmp_path / "ops" / "env.yaml", {"project_name": "env"}))
    monkeypatch.setenv("ASH_CONFIG", str(env))
    out = tmp_path / "out"
    out.mkdir()
    opts = _scan_options_for_the_gate(src, out, None, **_BUILDS[build])
    assert isinstance(
        ras._outer_mode_config_load(opts).refusal, ras.ASHConfigValidationError
    )
    assert _exit_of_a_scan(src, out, None, **_BUILDS[build]) == 3
    assert recording_runner == []


@pytest.mark.parametrize("build", sorted(_BUILDS))
def test_a_config_file_that_cannot_be_read_is_left_to_the_handover_check(
    tmp_path, recording_runner, unreadable, build
):
    """A ``--config`` the host cannot read is not refused by the gate, which
    returns None for it; the check that hands the config to the container
    refuses it with exit 3 before the runner is invoked."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = unreadable(_write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"}))
    out = tmp_path / "out"
    out.mkdir()
    opts = _scan_options_for_the_gate(src, out, config, **_BUILDS[build])
    assert ras._outer_mode_config_load(opts).refusal is None
    assert _exit_of_a_scan(src, out, config, **_BUILDS[build]) == 3
    assert recording_runner == []


_REFERENCE = "${ASH_PROBE_SEV:LOW}"


def _results_with_an_unreadable_reference():
    """Results whose record holds an environment reference in a field that
    cannot hold one, so the record repair has work to do."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    data = json.loads(model.model_dump_json(by_alias=True))
    data["ash_config"]["global_settings"]["severity_threshold"] = _REFERENCE
    return json.dumps(data)


class _ImageQuestionSpy:
    """Stands in for ``get_ash_revision`` and records every ask: whether the
    asking thread had its log records dropped (the pre-run gate does), and
    which of the scan's functions were on the stack."""

    def __init__(self) -> None:
        self.asks: list[tuple[bool, set[str]]] = []

    def __call__(self, quiet: bool = False) -> str:
        import inspect

        silenced = any(
            isinstance(f, ras._DropThisThreadsRecords) for f in ras.ASH_LOGGER.filters
        )
        frames = {frame.function for frame in inspect.stack()}
        self.asks.append((silenced, frames))
        return "0123456789abcdef"

    def summary(self) -> list[str]:
        """One word per ask: where it came from and whether it was logged."""
        origins = (
            "_outer_mode_config_load",
            "run_ash_container",
            "_take_own_values_for_record",
            "_load_config_file_or_its_exit_fields",
        )
        return [
            f"{next((o for o in origins if o in frames), 'other')}"
            f" ({'dropped' if silenced else 'logged'})"
            for silenced, frames in self.asks
        ]

    def logged_from(self, function: str) -> int:
        """How many asks that were not silenced came from *function*."""
        return sum(1 for s, frames in self.asks if not s and function in frames)

    @property
    def logged(self) -> int:
        return sum(1 for silenced, _ in self.asks if not silenced)


@pytest.fixture
def image_question(monkeypatch) -> _ImageQuestionSpy:
    spy = _ImageQuestionSpy()
    monkeypatch.setattr(run_ash_container, "get_ash_revision", spy)
    return spy


def _a_record_repair_that_has_work(tmp_path: Path, monkeypatch):
    """(opts, results): a container scan with a build and no revision named,
    whose selected file this tree's model refuses, over results whose record
    holds an unreadable reference."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    opts = _scan_options_for_the_gate(src, tmp_path / "out", config, build=True)
    results = AshAggregatedResults.model_validate_json(
        _results_with_an_unreadable_reference()
    )
    return opts, results


def test_the_record_repair_takes_the_gates_answer_and_asks_nothing(
    tmp_path, monkeypatch, image_question
):
    """The pre-run gate holds the answer about the image. The repair, which
    runs after the inner scan, takes it by keyword instead of naming the
    image's source in the log again."""
    opts, results = _a_record_repair_that_has_work(tmp_path, monkeypatch)
    ras._take_own_values_for_record(results, opts, image_may_differ=True)
    assert image_question.asks == []


def test_the_record_repair_without_a_gate_asks_for_itself(
    tmp_path, monkeypatch, image_question
):
    """Control: with no answer handed in, the repair asks once, as it did."""
    opts, results = _a_record_repair_that_has_work(tmp_path, monkeypatch)
    ras._take_own_values_for_record(results, opts)
    assert len(image_question.asks) == 1


def test_the_pre_run_gate_with_no_config_selected_asks_no_image_revision_question(
    tmp_path, monkeypatch, image_question
):
    """A container run that builds its image from this tree (build set, no
    custom Containerfile, no revision to install) but selects no config file,
    names no ASH_CONFIG and gives no --config-overrides judges only the
    defaults, so the pre-run gate answers without reading the image's
    revision."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (tmp_path / "out").mkdir()
    opts = _scan_options_for_the_gate(src, tmp_path / "out", None, build=True, run=True)
    assert opts.ash_revision_to_install is None
    assert opts.custom_containerfile is None

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None
    assert loaded.image_may_differ is False
    assert image_question.asks == [], image_question.summary()


def test_the_pre_run_gate_with_a_config_selected_asks_the_image_question_once(
    tmp_path, monkeypatch, image_question
):
    """Control for the test above: the same run with a config file selected
    does read the image's revision, once, so the no-config test above cannot
    pass because the spy is not on the path."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (tmp_path / "out").mkdir()
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", config, build=True, run=True
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None
    assert loaded.image_may_differ is True
    assert len(image_question.asks) == 1, image_question.summary()


#: Every image state the gate cannot check against this tree's schema.
_IMAGES_THAT_MAY_DIFFER = {
    "no-build": {"build": False},
    "custom-containerfile": {
        "build": True,
        "custom_containerfile": "Containerfile.custom",
    },
    "another-revision": {"build": True, "ash_revision_to_install": "main"},
}

#: An override whose key only a later schema declares: this tree's apply
#: refuses it, and an image holding that schema accepts it.
_OVERRIDE_OF_A_LATER_SCHEMA_KEY = (
    "global_settings.zz_option_a_later_schema_declares=true"
)


def _a_source_with_no_config(tmp_path: Path) -> Path:
    """A scanned directory in a checkout where discovery finds no config file;
    the output directory exists."""
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (tmp_path / "out").mkdir()
    return src


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_leaves_an_override_of_a_later_schema_key_to_the_image(
    tmp_path, monkeypatch, image
):
    """A scan with no config file whose ``--config-overrides`` name a key only
    the image's schema declares is not refused at the gate when the image may
    hold another schema: this tree's apply would refuse the key, which the
    image's own apply accepts, so the overrides are the scan inside's to
    judge, as they are for a scan that selects a file."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        config_overrides=[_OVERRIDE_OF_A_LATER_SCHEMA_KEY],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.image_may_differ is True


def test_the_pre_run_gate_still_refuses_an_override_this_tree_cannot_apply_to_a_local_image(
    tmp_path, monkeypatch
):
    """Control for the cells above: an image built from this source tree holds
    this schema, so the same override is refused at the gate, before anything
    is built, started or cleared. The cells above cannot pass because the
    override applies."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        build=True,
        ash_revision_to_install="LOCAL",
        config_overrides=[_OVERRIDE_OF_A_LATER_SCHEMA_KEY],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is not None
    assert "requested overrides" in str(loaded.refusal), str(loaded.refusal)
    assert loaded.image_may_differ is False


#: Overrides no revision applies: not an assignment at all, and a part of the key
#: with a space in it. The apply cannot be made, so its refusal carries no
#: validation error that another schema could judge differently.
_OVERRIDES_NO_REVISION_APPLIES = [
    pytest.param("no-equals-sign", id="not-an-assignment"),
    pytest.param("global_settings .severity_threshold=HIGH", id="a-space-in-the-key"),
]

#: Overrides that leave a field this tree declares with a value this tree's model
#: refuses: a value of the wrong kind, a section given a scalar, and a value
#: outside the choices this tree allows. Whether the image refuses it too is the
#: image's schema's answer, which this tree can read only when the image is built
#: from it (or when no image is built and the host's own schema is the one that
#: matters); an image built with another revision's ASH may accept the value.
_OVERRIDES_OF_A_VALUE_THIS_TREE_REFUSES = [
    pytest.param("fail_on_findings=maybe", id="wrong-kind-of-value"),
    pytest.param("global_settings=7", id="a-section-given-a-scalar"),
    pytest.param(
        "global_settings.severity_threshold=ZZ_A_LATER_SEVERITY",
        id="a-value-only-a-later-schema-accepts",
    ),
]

#: The may-differ images in which the host's own schema stays the judge of a
#: value, as it is of the selected file: no image is built, or the image is built
#: from a custom Containerfile.
_IMAGES_WHERE_THE_HOSTS_SCHEMA_JUDGES_A_VALUE = ["custom-containerfile", "no-build"]

#: A plugin option only a later schema declares: the plugin's section refuses it
#: in words (a ``value_error``), where a section that forbids extras refuses
#: with ``extra_forbidden``.
_OVERRIDE_OF_A_LATER_PLUGIN_OPTION = (
    "scanners.bandit.options.zz_option_a_later_schema_declares=true"
)


@pytest.mark.parametrize("override", _OVERRIDES_NO_REVISION_APPLIES)
@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_refuses_an_override_no_revision_applies_whatever_the_image(
    tmp_path, monkeypatch, image, override
):
    """An override that does not parse, or one the apply cannot make, is
    refused at the gate for an image that may hold another schema: no
    revision applies it, and the scan inside would refuse it only after the
    image is built, started and the previous output cleared. A key another
    schema may declare is the image's to judge (the cells above), and so is a
    value, for an image built with another revision (the cells below)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        config_overrides=[override],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert isinstance(loaded.refusal, ras.ASHConfigValidationError), loaded.refusal
    assert loaded.image_may_differ is True


@pytest.mark.parametrize("override", _OVERRIDES_NO_REVISION_APPLIES)
@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_refuses_such_an_override_beside_a_selected_file_too(
    tmp_path, monkeypatch, image, override
):
    """The same refusal when a config file is selected: the overrides are
    applied to this tree's model of that file, as a local scan applies them."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[override],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert isinstance(loaded.refusal, ras.ASHConfigValidationError), loaded.refusal
    assert loaded.image_may_differ is True


def test_the_pre_run_gate_does_not_waive_a_refusal_that_also_holds_a_wrong_value(
    tmp_path, monkeypatch
):
    """The waiver is for a refusal whose every error names a key this tree
    does not declare. A later-schema key beside a value of the wrong kind is
    one refusal with an error every revision shares, and it stands."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        build=False,
        config_overrides=[_OVERRIDE_OF_A_LATER_SCHEMA_KEY, "fail_on_findings=maybe"],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert isinstance(loaded.refusal, ras.ASHConfigValidationError), loaded.refusal


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_leaves_an_override_of_a_later_plugin_option_to_the_image(
    tmp_path, monkeypatch, image
):
    """A plugin option only the image's schema declares is refused by this
    tree's plugin section in words, not by a section that forbids extras. It
    is still a key this tree does not declare, so it is the image's to judge."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        config_overrides=[_OVERRIDE_OF_A_LATER_PLUGIN_OPTION],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.image_may_differ is True


def test_the_pre_run_gate_still_refuses_a_plugin_option_this_tree_cannot_apply_to_a_local_image(
    tmp_path, monkeypatch
):
    """Control for the cell above: an image built from this tree holds this
    schema, so the same override is refused at the gate."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        build=True,
        ash_revision_to_install="LOCAL",
        config_overrides=[_OVERRIDE_OF_A_LATER_PLUGIN_OPTION],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is not None
    assert "requested overrides" in str(loaded.refusal), str(loaded.refusal)


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_does_not_refuse_an_override_every_revision_applies(
    tmp_path, monkeypatch, image
):
    """Control for the refusals above: overrides this tree applies pass the
    gate for an image that may differ, with a file selected or not."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    for selected in (None, config):
        opts = _scan_options_for_the_gate(
            src,
            tmp_path / "out",
            selected,
            run=True,
            config_overrides=["fail_on_findings=false", "project_name=other"],
            **_IMAGES_THAT_MAY_DIFFER[image],
        )

        loaded = ras._outer_mode_config_load(opts)

        assert loaded.refusal is None, (selected, loaded.refusal)
        assert loaded.image_may_differ is True


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_hands_the_exit_code_readers_the_overrides_applied_values(
    tmp_path, monkeypatch, image
):
    """A ``--config-overrides`` value for either exit-code field decides the
    exit code in a container run as it does in a local scan, which reads the
    configuration with the overrides applied. The readers take the exit-code
    fields from the gate, and the host forwards what they read as a command-line
    flag, which the scan inside ranks above its own overrides; so the gate hands
    them the applied values, not the file's. The check applies the overrides to
    a copy, so the file's model the gate also returns keeps the file's values."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "fail_on_findings": False,
            "fail_on_incomplete_scanners": False,
        },
    )
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[
            "fail_on_findings=true",
            "fail_on_incomplete_scanners=true",
        ],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.loaded is True
    assert loaded.selected.fail_on_findings is True
    assert loaded.selected.fail_on_incomplete_scanners is True
    assert ras._resolve_config_fail_on_findings(opts, loaded=loaded.selected) is True
    assert (
        ras._resolve_config_fail_on_incomplete_scanners(opts, loaded=loaded.selected)
        is True
    )
    assert loaded.model is not None
    assert loaded.model.fail_on_findings is False


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_an_override_of_another_key_leaves_the_files_exit_code_fields(
    tmp_path, monkeypatch, image
):
    """Control for the cell above: overrides that do not name an exit-code
    field leave the file's values, so the readers report them whichever
    object the gate hands over."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {"project_name": "op", "fail_on_findings": False},
    )
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=["project_name=other"],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    shared = (
        loaded.selected
        if loaded.loaded
        else ras._load_config_file_or_its_exit_fields(
            opts,
            document=loaded.document,
            image_may_differ=loaded.image_may_differ,
            model=loaded.model,
        )
    )
    assert ras._resolve_config_fail_on_findings(opts, loaded=shared) is False


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_overrides_the_gate_leaves_to_the_image_do_not_change_the_files_exit_fields(
    tmp_path, monkeypatch, image
):
    """The overrides are the scan inside's to judge when one of them names a
    key only a later schema declares, so there is no applied model to take
    values from, and the readers keep reporting the file's. The limit is
    pinned here: an override of ``fail_on_findings`` beside such a key does not
    reach the exit code the host forwards."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {"project_name": "op", "fail_on_findings": False},
    )
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[_OVERRIDE_OF_A_LATER_SCHEMA_KEY, "fail_on_findings=true"],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    shared = (
        loaded.selected
        if loaded.loaded
        else ras._load_config_file_or_its_exit_fields(
            opts,
            document=loaded.document,
            image_may_differ=loaded.image_may_differ,
            model=loaded.model,
        )
    )
    assert ras._resolve_config_fail_on_findings(opts, loaded=shared) is False


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_a_run_with_no_config_file_forwards_no_exit_code_field_from_its_overrides(
    tmp_path, monkeypatch, image
):
    """With no file selected there is no file value to override: the readers
    answer None, no flag is forwarded, and the scan inside applies the
    overrides itself."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        config_overrides=["fail_on_findings=true"],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    shared = (
        loaded.selected
        if loaded.loaded
        else ras._load_config_file_or_its_exit_fields(
            opts,
            document=loaded.document,
            image_may_differ=loaded.image_may_differ,
            model=loaded.model,
        )
    )
    assert ras._resolve_config_fail_on_findings(opts, loaded=shared) is None


@pytest.mark.parametrize("selected", [False, True], ids=["no-file", "a-file"])
@pytest.mark.parametrize("override", _OVERRIDES_OF_A_VALUE_THIS_TREE_REFUSES)
@pytest.mark.parametrize("image", _IMAGES_WHERE_THE_HOSTS_SCHEMA_JUDGES_A_VALUE)
def test_the_pre_run_gate_refuses_an_override_value_this_tree_refuses_when_its_schema_judges_it(
    tmp_path, monkeypatch, image, override, selected
):
    """Control for the cell below: when no image is built, or the image is built
    from a custom Containerfile, this tree's model stays the judge of a value,
    as it is of the selected file, and a value it refuses is refused at the
    gate."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = (
        _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
        if selected
        else None
    )
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[override],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert isinstance(loaded.refusal, ras.ASHConfigValidationError), loaded.refusal


@pytest.mark.parametrize("selected", [False, True], ids=["no-file", "a-file"])
@pytest.mark.parametrize("override", _OVERRIDES_OF_A_VALUE_THIS_TREE_REFUSES)
def test_the_pre_run_gate_leaves_an_override_value_this_tree_refuses_to_an_image_of_another_revision(
    tmp_path, monkeypatch, override, selected
):
    """An image built with another revision's ASH may hold a schema that
    accepts the value, as it may accept a file this tree's model refuses (the
    gate raises that refusal only for the other images). The same override of
    the same value is therefore the scan inside's to judge, whether it is given
    beside a file or in the file's place."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = (
        _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
        if selected
        else None
    )
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[override],
        **_IMAGES_THAT_MAY_DIFFER["another-revision"],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.image_may_differ is True


#: A file this tree's model refuses for a field only a later schema declares,
#: and that holds a tool's install scripts: the section the overrides below
#: reach into.
_A_FILE_ONLY_A_LATER_SCHEMA_LOADS = {
    "project_name": "op",
    "global_settings": {"zz_option_a_later_schema_declares": True},
    "build": {"tool_install_scripts": {"mytool": ["install-a"]}},
}

#: An override into a list only the file holds. Applied to the file it appends;
#: applied to the defaults, which have no such key, it sets a string where the
#: model wants a list.
_OVERRIDE_INTO_A_LIST_ONLY_THE_FILE_HOLDS = (
    "build.tool_install_scripts.mytool+=install-b"
)


def test_the_pre_run_gate_leaves_an_override_into_a_section_only_the_file_holds_to_the_image(
    tmp_path, monkeypatch
):
    """When this tree's model refuses the selected file (an image built with
    another revision), there is no model of the file to apply the overrides to,
    and applying them to the defaults refuses a path that exists only in the
    file: ``build.tool_install_scripts.mytool+=...`` sets a string where the
    model wants a list. The image applies the override to the file, where it
    appends, so the host does not refuse a validation failure it cannot tell
    from a file it cannot read."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(tmp_path / "ops" / "ash.yaml", _A_FILE_ONLY_A_LATER_SCHEMA_LOADS)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[_OVERRIDE_INTO_A_LIST_ONLY_THE_FILE_HOLDS],
        **_IMAGES_THAT_MAY_DIFFER["another-revision"],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.model is None
    assert loaded.image_may_differ is True


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_an_override_into_a_list_the_file_holds_applies_when_this_trees_model_loads_the_file(
    tmp_path, monkeypatch, image
):
    """Control for the cell above: the same override beside a file this tree's
    model loads is applied to that model, where it appends, so nothing is
    refused. The cell above cannot pass because the override is invalid."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    document = {
        key: value
        for key, value in _A_FILE_ONLY_A_LATER_SCHEMA_LOADS.items()
        if key != "global_settings"
    }
    config = _write(tmp_path / "ops" / "ash.yaml", document)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[_OVERRIDE_INTO_A_LIST_ONLY_THE_FILE_HOLDS],
        **_IMAGES_THAT_MAY_DIFFER[image],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.model is not None


@pytest.mark.parametrize(
    "override",
    ["no-equals-sign", "global_settings .severity_threshold=HIGH"],
    ids=["not-an-assignment", "a-space-in-the-key"],
)
def test_the_pre_run_gate_still_refuses_an_override_that_does_not_parse_beside_a_file_it_cannot_load(
    tmp_path, monkeypatch, override
):
    """Control for the cell above: an override that does not parse, or one the
    apply cannot make, is refused whatever the file, because no revision
    applies it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(tmp_path / "ops" / "ash.yaml", _A_FILE_ONLY_A_LATER_SCHEMA_LOADS)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        config,
        run=True,
        config_overrides=[override],
        **_IMAGES_THAT_MAY_DIFFER["another-revision"],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert isinstance(loaded.refusal, ras.ASHConfigValidationError), loaded.refusal


#: An unknown key beside a wrong value in one section. The section's validator
#: runs before its fields and raises only the unknown-key error, so the refusal
#: holds no error about the value and the waiver for an undeclared key applies.
_AN_UNKNOWN_KEY_BESIDE_A_WRONG_VALUE = [
    pytest.param(
        [
            "scanners.bandit.options.zz_option_a_later_schema_declares=1",
            "scanners.bandit.options.confidence_level=BOGUS",
        ],
        id="in-a-plugins-options",
    ),
    pytest.param(
        [
            "scanners.bandit.zz_option_a_later_schema_declares=1",
            "scanners.bandit.enabled=maybe",
        ],
        id="in-a-plugins-section",
    ),
]


@pytest.mark.parametrize("overrides", _AN_UNKNOWN_KEY_BESIDE_A_WRONG_VALUE)
def test_the_pre_run_gate_waives_an_unknown_key_that_hides_a_wrong_value_beside_it(
    tmp_path, monkeypatch, overrides
):
    """The waiver is for a refusal whose every error names an undeclared key.
    A section that forbids an unknown key says so before it validates its
    fields, so a wrong value in the same section does not appear in the
    refusal and the overrides are waived whole: the scan inside refuses the
    value if its schema does not accept it. The refusal of a wrong value in
    another section, which does appear, stands (the cell above this block)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        build=False,
        config_overrides=overrides,
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal


@pytest.mark.parametrize("overrides", _AN_UNKNOWN_KEY_BESIDE_A_WRONG_VALUE)
def test_the_wrong_value_beside_an_unknown_key_is_refused_on_its_own(
    tmp_path, monkeypatch, overrides
):
    """Control for the cell above: the value, the last override of each pair,
    is wrong on its own, so the cell above waives it only because of the key
    beside it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        build=False,
        config_overrides=overrides[-1:],
    )

    loaded = ras._outer_mode_config_load(opts)

    assert isinstance(loaded.refusal, ras.ASHConfigValidationError), loaded.refusal


@pytest.mark.parametrize("image", sorted(_IMAGES_THAT_MAY_DIFFER))
def test_the_pre_run_gate_leaves_an_ash_config_base_of_a_later_schema_to_the_image(
    tmp_path, monkeypatch, image
):
    """With no config file selected, the file ``ASH_CONFIG`` names is the only
    config the gate judges. When the image may hold another schema, a field
    only that schema declares in it is the scan inside's to judge, as it is
    when the same file is also the scan's ``--config``."""
    env = _write(
        tmp_path / "ops" / "env.yaml",
        {
            "project_name": "env",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(env))
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", None, run=True, **_IMAGES_THAT_MAY_DIFFER[image]
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.image_may_differ is True


def test_the_pre_run_gate_still_refuses_an_ash_config_base_this_tree_cannot_load_for_a_local_image(
    tmp_path, monkeypatch
):
    """Control for the cells above: an image built from this source tree holds
    this schema, so a base this tree's model refuses is refused at the gate."""
    env = _write(
        tmp_path / "ops" / "env.yaml",
        {
            "project_name": "env",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    monkeypatch.setenv("ASH_CONFIG", str(env))
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        run=True,
        build=True,
        ash_revision_to_install="LOCAL",
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is not None
    assert loaded.image_may_differ is False


@pytest.mark.parametrize("input_kind", ["overrides", "ash_config"])
def test_the_pre_run_gate_with_no_config_asks_the_image_question_once_when_it_judges_something(
    tmp_path, monkeypatch, image_question, input_kind
):
    """A run that selects no config file but gives ``--config-overrides`` or
    names an ``ASH_CONFIG`` base has a schema to judge, so the gate asks the
    image question for it, once, where it asks nothing of a run that judges
    nothing (the cell above)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    options = {}
    if input_kind == "overrides":
        options["config_overrides"] = ["project_name=op"]
    else:
        env = _write(tmp_path / "ops" / "env.yaml", {"project_name": "env"})
        monkeypatch.setenv("ASH_CONFIG", str(env))
    src = _a_source_with_no_config(tmp_path)
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", None, build=True, run=True, **options
    )
    assert opts.ash_revision_to_install is None

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.image_may_differ is True
    assert len(image_question.asks) == 1, image_question.summary()


@pytest.mark.parametrize("image", ["local", *sorted(_IMAGES_THAT_MAY_DIFFER)])
def test_the_pre_run_gate_with_nothing_to_judge_asks_nothing_of_any_image(
    tmp_path, monkeypatch, image_question, image
):
    """No config file, no ``ASH_CONFIG`` and no ``--config-overrides``: the gate
    judges only the defaults, so it neither refuses nor asks about the image,
    whatever the image is."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    image_options = (
        {"build": True, "ash_revision_to_install": "LOCAL"}
        if image == "local"
        else _IMAGES_THAT_MAY_DIFFER[image]
    )
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", None, run=True, **image_options
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.image_may_differ is False
    assert image_question.asks == [], image_question.summary()


class _ImageQuestionThatRaisesOnce:
    """Stands in for ``get_ash_revision``: the first ask raises the ``OSError``
    a revision read can raise (the checkout or the install receipt cannot be
    read), and every later ask answers with a revision that is not LOCAL."""

    def __init__(self) -> None:
        self.asks = 0

    def __call__(self) -> str:
        self.asks += 1
        if self.asks == 1:
            raise OSError("the install receipt cannot be read")
        return "0123456789abcdef"


def test_an_image_question_that_raises_leaves_the_gates_answer_unset(
    tmp_path, monkeypatch
):
    """``image_may_differ`` is None when the gate never got an answer about the
    image and False only when it learned the image holds this schema. A
    question that raises is the first, so the readers that follow the gate ask
    for themselves; reading it as the second would have them trust "same
    schema" for an image nobody inspected."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    question = _ImageQuestionThatRaisesOnce()
    monkeypatch.setattr(run_ash_container, "get_ash_revision", question)
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", config, build=True, run=True
    )
    assert opts.ash_revision_to_install is None

    loaded = ras._outer_mode_config_load(opts)

    assert question.asks == 1
    assert loaded.refusal is None, loaded.refusal
    assert loaded.loaded is False
    assert loaded.document is ras._NOT_LOADED
    assert loaded.image_may_differ is None


def test_a_gate_that_got_no_answer_about_the_image_keeps_the_exit_fields_fallback(
    tmp_path, monkeypatch
):
    """The consequence of the cell above: a file this tree's model refuses
    because a later schema declares a key in it, with ``fail_on_findings:
    false``. The gate's question raised, so the exit-field read asks for
    itself, learns the image may differ and reads the file's own False. Handed
    a False in place of the missing answer it would return None, and the
    host's exit code would use the default (True) against the file."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "fail_on_findings": False,
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    question = _ImageQuestionThatRaisesOnce()
    monkeypatch.setattr(run_ash_container, "get_ash_revision", question)
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", config, build=True, run=True
    )

    loaded = ras._outer_mode_config_load(opts)
    fields = ras._load_config_file_or_its_exit_fields(
        opts,
        document=loaded.document,
        image_may_differ=loaded.image_may_differ,
        model=loaded.model,
    )

    assert loaded.image_may_differ is None
    assert question.asks == 2
    assert fields is not None, "the fallback was skipped for an image nobody inspected"
    assert fields.fail_on_findings is False


def test_an_image_question_that_answers_is_the_gates_answer(tmp_path, monkeypatch):
    """Control for the two cells above: the same run with a question that does
    not raise leaves the gate holding its answer, so those cells cannot pass
    because the gate never keeps one."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    config = _write(tmp_path / "ops" / "ash.yaml", {"project_name": "op"})
    monkeypatch.setattr(
        run_ash_container, "get_ash_revision", lambda quiet=False: "main"
    )
    opts = _scan_options_for_the_gate(
        src, tmp_path / "out", config, build=True, run=True
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.image_may_differ is True
    assert loaded.document is not ras._NOT_LOADED, "the gate stopped at the question"


def test_the_pre_run_gate_discovers_the_config_file_once(tmp_path, monkeypatch):
    """The gate selects the config file once and loads that file. A second
    discovery for the load could answer differently if the directory changed
    between the two, and would load a file the gate never judged the image
    question for."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    (src / ".ash").mkdir()
    (src / ".ash" / ".ash.yaml").write_text("project_name: found\n", encoding="utf-8")
    discoveries: list[object] = []
    real = ras._discovered_config_path

    def counting(*args, **kwargs):
        found = real(*args, **kwargs)
        discoveries.append(found)
        return found

    monkeypatch.setattr(ras, "_discovered_config_path", counting)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        build=True,
        ash_revision_to_install="LOCAL",
        run=True,
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.loaded is True
    assert loaded.selected is not None, "the discovered file was not loaded"
    assert len(discoveries) == 1, discoveries


def test_a_selection_of_no_file_is_not_a_request_to_discover_one(tmp_path, monkeypatch):
    """``_loaded_config_file(selected_path=None)`` says the caller selected no
    file, so it loads none and does not discover a second time; a call that
    leaves the argument out selects here. Before the sentinel None meant "select
    here" too, and "I selected nothing" could not be said: a natural call
    passing the gate's own answer on would have discovered, and loaded, a file
    the gate never judged."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    (src / ".ash").mkdir()
    (src / ".ash" / ".ash.yaml").write_text("project_name: found\n", encoding="utf-8")
    discoveries: list[int] = []
    real = ras._discovered_config_path

    def counting(*args, **kwargs):
        discoveries.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(ras, "_discovered_config_path", counting)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        build=True,
        ash_revision_to_install="LOCAL",
        run=True,
    )

    assert ras._loaded_config_file(opts, selected_path=None) is None
    assert discoveries == [], "a selection of no file discovered one"

    # Control: with the argument left out the call selects here, so the cell
    # above cannot pass because there is no file to find.
    assert ras._loaded_config_file(opts) is not None
    assert discoveries == [1], discoveries


def test_the_pre_run_gate_does_not_load_a_file_that_appears_after_it_selected_none(
    tmp_path, monkeypatch
):
    """A file that appears after the gate found no config is not loaded by it:
    the gate judged nothing (no file, no ``ASH_CONFIG``, no overrides), so it
    did not ask the image question, and a load of a file found later would
    check that file against this tree's schema for an image that may differ."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    src = _a_source_with_no_config(tmp_path)
    late = _write(
        tmp_path / "ops" / "late.yaml",
        {
            "project_name": "late",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    discoveries: list[int] = []

    def found_late(*_args, **_kwargs):
        discoveries.append(1)
        return None if len(discoveries) == 1 else str(late)

    monkeypatch.setattr(ras, "_discovered_config_path", found_late)
    opts = _scan_options_for_the_gate(
        src,
        tmp_path / "out",
        None,
        build=True,
        ash_revision_to_install="LOCAL",
        run=True,
    )

    loaded = ras._outer_mode_config_load(opts)

    assert loaded.refusal is None, loaded.refusal
    assert loaded.selected is None
    assert discoveries == [1], discoveries


@pytest.mark.parametrize(("answer", "warned"), [(True, True), (False, False)])
def test_the_record_repair_warns_only_for_an_image_that_may_differ(
    tmp_path, monkeypatch, image_question, answer, warned
):
    """A handed-in answer decides the repair's warning without asking: True
    says the image may hold another schema, so the repair names the base
    configuration it fell back on; False says it does not, so it stays
    silent."""
    from unittest.mock import patch

    opts, results = _a_record_repair_that_has_work(tmp_path, monkeypatch)
    with patch.object(ras, "ASH_LOGGER") as log:
        ras._take_own_values_for_record(results, opts, image_may_differ=answer)
    repairs = [
        call
        for call in log.warning.call_args_list
        if "repaired from the operator's base configuration" in str(call)
    ]
    assert bool(repairs) is warned, log.warning.call_args_list
    assert image_question.asks == []


@pytest.mark.parametrize("answer", [True, False, None])
def test_the_record_repair_gives_the_record_the_operators_own_value(
    tmp_path, monkeypatch, image_question, answer
):
    """The record cannot hold an environment reference in a fixed-choice field,
    so it is read with that field's default and the field is listed as
    unreadable. The repair takes the operator's own value for it: here the
    selected file loads, and reads severity_threshold from the environment as
    CRITICAL, which is not the default the record was read with."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    monkeypatch.setenv("ASH_PROBE_SEV", "CRITICAL")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    # Plain scalar text: a quoted "${...}" is a literal string, not a reference.
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        f"project_name: op\nglobal_settings:\n  severity_threshold: {_REFERENCE}\n",
        encoding="utf-8",
    )
    opts = _scan_options_for_the_gate(src, tmp_path / "out", config, build=False)
    results = AshAggregatedResults.model_validate_json(
        _results_with_an_unreadable_reference()
    )
    before = str(results.ash_config.global_settings.severity_threshold)
    assert before != "CRITICAL", "the record was read with the field's default"

    ras._take_own_values_for_record(results, opts, image_may_differ=answer)

    assert results.ash_config.global_settings.severity_threshold == "CRITICAL"
    assert image_question.asks == []


def test_the_record_repair_takes_the_image_answer_by_keyword_only(
    tmp_path, monkeypatch, image_question
):
    import inspect

    opts, results = _a_record_repair_that_has_work(tmp_path, monkeypatch)
    with pytest.raises(TypeError):
        ras._take_own_values_for_record(results, opts, True)
    # The container runner takes the same answer the same way.
    kind = (
        inspect.signature(ras._run_container_mode).parameters["image_may_differ"].kind
    )
    assert kind is inspect.Parameter.KEYWORD_ONLY


@pytest.mark.parametrize("answer", [True, False, None])
@pytest.mark.parametrize("mode", ["container", "nix"])
def test_each_outer_mode_hands_the_gates_answer_to_the_record_repair(
    tmp_path, monkeypatch, mode, answer
):
    """Both runners read the inner scan's results back and repair the record;
    each passes on the answer it was given, by keyword."""
    from unittest.mock import MagicMock, patch

    src = tmp_path / "src"
    src.mkdir()
    opts = ras.ScanOptions(source_dir=src, output_dir=tmp_path / "out")

    def inner(*_args, **kwargs):
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        # As the inner run writes it: with the record that the run the outer
        # process gave this ID completed, or the read-back refuses the file.
        document = json.loads(_results_with_an_unreadable_reference())
        document["validation_checkpoints"] = [completion_marker(kwargs["outer_run_id"])]
        (opts.output_dir / "ash_aggregated_results.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    seen: list[dict] = []
    monkeypatch.setattr(
        ras,
        "_take_own_values_for_record",
        lambda results, opts, **handed: seen.append(handed),
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    runner = ras._run_container_mode if mode == "container" else ras._run_nix_mode
    target = "run_ash_container" if mode == "container" else "run_ash_nix"
    with (
        patch.object(ras, target, side_effect=inner),
        patch.object(ras, "nix_preflight", lambda: None),
    ):
        runner(opts, MagicMock(), image_may_differ=answer)
    assert seen == [{"image_may_differ": answer}]


@pytest.mark.parametrize(
    ("mode", "runner", "options", "expected"),
    [
        (
            RunMode.container,
            "_run_container_mode",
            {"build": False, "config_overrides": ["project_name=op"]},
            True,
        ),
        (
            RunMode.container,
            "_run_container_mode",
            {"build": False},
            False,
        ),
        (
            RunMode.container,
            "_run_container_mode",
            {"build": True, "ash_revision_to_install": "LOCAL"},
            False,
        ),
        (
            RunMode.container,
            "_run_container_mode",
            {"build": False, "run": False},
            None,
        ),
        (RunMode.nix, "_run_nix_mode", {"build": False}, False),
    ],
    ids=["may-differ", "nothing-to-judge", "built-from-this-tree", "no-gate", "nix"],
)
def test_a_scan_hands_the_gates_answer_to_its_mode_runner(
    tmp_path, recording_runner, monkeypatch, mode, runner, options, expected
):
    """``run_ash_scan`` holds the gate's answer about the image and passes it
    to the runner of its mode by keyword: an image that is not built from this
    tree may differ (True), an image built from it does not (False), a Nix
    shell re-executes this checkout's own ASH (False), and a scan whose gate
    did not run has no answer to hand over (None). The gate asks about the
    image only when it judges something against this tree's schema, so the
    first case gives it an override to judge; a run that judges nothing is
    answered False without a question."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    seen: list[dict] = []

    def stop(*_args, **kwargs):
        seen.append(kwargs)
        raise _StoppedBeforeTheRun

    monkeypatch.setattr(ras, runner, stop)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    with pytest.raises(_StoppedBeforeTheRun):
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            mode=mode,
            show_summary=False,
            progress=False,
            quiet=True,
            **options,
        )
    assert [kwargs["image_may_differ"] for kwargs in seen] == [expected]


@pytest.fixture
def runner_that_records_a_reference(recording_runner, monkeypatch):
    """The recording runner, whose run also leaves results holding an
    unreadable reference, as an inner scan whose config read one does."""
    record = run_ash_container.run_cmd_direct

    def record_and_write(cmd_list, *args, **kwargs):
        completed = record(cmd_list, *args, **kwargs)
        cmd = [str(item) for item in cmd_list if item is not None]
        if len(cmd) > 1 and cmd[1] == "run":
            for i, arg in enumerate(cmd[:-1]):
                if arg == "--mount":
                    fields = dict(
                        part.partition("=")[::2] for part in cmd[i + 1].split(",")
                    )
                    if fields.get("destination") == "/out":
                        # With the record that the run the host gave this ID
                        # completed, as the scan inside writes it; the file
                        # replaces the recorder's, so the marker is written here.
                        run_id = (kwargs.get("env") or {}).get(OUTER_RUN_ID_ENV)
                        document = json.loads(_results_with_an_unreadable_reference())
                        document["validation_checkpoints"] = (
                            [completion_marker(run_id)] if run_id else []
                        )
                        Path(
                            fields["source"], "ash_aggregated_results.json"
                        ).write_text(json.dumps(document), encoding="utf-8")
        return completed

    monkeypatch.setattr(run_ash_container, "run_cmd_direct", record_and_write)
    return recording_runner


def test_one_container_scan_names_the_image_source_once(
    tmp_path, runner_that_records_a_reference, image_question, monkeypatch
):
    """A container scan with a build, no revision named and a selected file
    this tree's model refuses asks about the image from three places: the
    pre-run gate (its records dropped), the build (the read the scan keeps)
    and the record repair after the inner scan. Only the build's read is
    logged, so the image's source is named once."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setattr(ras, "_compute_exit_code", lambda *a, **k: 0)
    _checkout(tmp_path / "repo")
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    config = _write(
        tmp_path / "ops" / "ash.yaml",
        {
            "project_name": "op",
            "global_settings": {"zz_option_a_later_schema_declares": True},
        },
    )
    out = tmp_path / "out"
    out.mkdir()
    assert _exit_of_a_scan(src, out, config, build=True) == 0
    assert any(
        len(cmd) > 1 and cmd[1] == "run" for cmd in runner_that_records_a_reference
    ), "the scan ran, so the record repair had results to repair"
    assert image_question.logged == 1, image_question.summary()
    assert image_question.logged_from("run_ash_container") == 1
    assert image_question.logged_from("_take_own_values_for_record") == 0


_GATE_MODES = ["nix", *sorted(_BUILDS)]

#: Deep enough that every parser this project reads a config with runs out of
#: recursion on it, whatever the interpreter's limit.
_NESTING = 100_000


def _nested_past_the_recursion_limit(path: Path) -> Path:
    """A real config file whose document is nested ``_NESTING`` levels, as the
    format its name says (the same text is a JSON array and a YAML flow
    sequence)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[" * _NESTING + "]" * _NESTING, encoding="utf-8")
    return path


def _scan_through_the_gate(
    tmp_path: Path, monkeypatch, capsys, mode: str, config, ash_config=None
):
    """Run a scan of *mode* (one of ``_GATE_MODES``) through ``run_ash_scan``
    with the Nix launcher replaced and the container runner recorded by the
    caller's ``recording_runner``. Returns the exit code, what the run
    printed with every blank removed (a long path wraps), how many times the
    Nix shell was entered, and whether the previous run's output is still
    there."""
    from unittest.mock import MagicMock

    if ash_config is None:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    else:
        monkeypatch.setenv("ASH_CONFIG", str(ash_config))
    src = tmp_path / "repo" / "app"
    src.mkdir(parents=True, exist_ok=True)
    (src / "a.py").write_text("x = 1\n", encoding="utf-8")
    out = tmp_path / "out"
    previous = out / "reports" / "ash.sarif"
    previous.parent.mkdir(parents=True, exist_ok=True)
    previous.write_text('{"runs": []}\n', encoding="utf-8")
    launcher = MagicMock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(ras, "run_ash_nix", launcher)
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)
    options = (
        {"mode": RunMode.nix}
        if mode == "nix"
        else {"mode": RunMode.container, **_BUILDS[mode]}
    )
    try:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(out),
            config=str(config) if config is not None else None,
            show_summary=False,
            progress=False,
            quiet=True,
            **options,
        )
        code = 0
    except SystemExit as refusal:
        code = int(refusal.code or 0)
    shown = capsys.readouterr()
    # The console may write color escapes into a captured stream on one OS;
    # the compare reads the words, not the styling.
    plain = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", shown.out + shown.err)
    squeezed = re.sub(r"\s+", "", plain)
    return code, squeezed, launcher.call_count, previous.exists()


@pytest.mark.parametrize("suffix", ["json", "yaml"])
@pytest.mark.parametrize("mode", _GATE_MODES)
def test_a_config_nested_past_the_recursion_limit_is_refused_not_raised(
    tmp_path, recording_runner, monkeypatch, capsys, mode, suffix
):
    """A repository can write a config nested past the interpreter's
    recursion limit. The gate refuses it with exit 3, naming the file, in
    every mode and before anything is built, started or cleared; the
    traceback of a RecursionError never reaches the caller."""
    config = _nested_past_the_recursion_limit(tmp_path / "ops" / f"deep.{suffix}")

    code, shown, shell_entered, kept = _scan_through_the_gate(
        tmp_path, monkeypatch, capsys, mode, config
    )

    assert code == 3, shown
    assert f"deep.{suffix}couldnotbeparsed" in shown, shown
    assert recording_runner == [], "a container command was run"
    assert shell_entered == 0, "the Nix shell was entered"
    assert kept, "the previous run's output was cleared"


@pytest.mark.parametrize("mode", _GATE_MODES)
def test_a_discovered_config_nested_past_the_recursion_limit_is_refused(
    tmp_path, recording_runner, monkeypatch, capsys, mode
):
    """With no ``--config`` the scan reads the file the scanned repository
    keeps at ``.ash/.ash.yaml``, which the repository controls."""
    _nested_past_the_recursion_limit(tmp_path / "repo" / "app" / ".ash" / ".ash.yaml")

    code, shown, shell_entered, kept = _scan_through_the_gate(
        tmp_path, monkeypatch, capsys, mode, None
    )

    assert code == 3, shown
    assert ".ash.yamlcouldnotbeparsed" in shown, shown
    assert recording_runner == []
    assert shell_entered == 0
    assert kept


@pytest.mark.parametrize("mode", _GATE_MODES)
def test_the_refusal_names_the_file_the_failing_read_was_of(
    tmp_path, recording_runner, monkeypatch, capsys, mode
):
    """The file ASH_CONFIG names and the config the scan selects are loaded
    one after the other, and each can be the one that is nested too deep. The
    refusal names that one, never the other."""
    deep = _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    fine = _write(tmp_path / "ops" / "fine.yaml", {"project_name": "op"})

    code, shown, _entered, kept = _scan_through_the_gate(
        tmp_path / "environment-deep", monkeypatch, capsys, mode, fine, ash_config=deep
    )
    assert code == 3, shown
    assert "deep.jsoncouldnotbeparsed" in shown, shown
    assert "fine.yaml" not in shown, shown
    assert kept

    code, shown, _entered, kept = _scan_through_the_gate(
        tmp_path / "selected-deep", monkeypatch, capsys, mode, deep, ash_config=fine
    )
    assert code == 3, shown
    assert "deep.jsoncouldnotbeparsed" in shown, shown
    assert "fine.yaml" not in shown, shown
    assert kept
    assert recording_runner == []


@pytest.mark.parametrize("mode", _GATE_MODES)
def test_the_refusal_names_an_extended_base_that_is_nested_too_deep(
    tmp_path, recording_runner, monkeypatch, capsys, mode
):
    """A config that parses can extend a base nested past the recursion limit.
    The RecursionError carries no file name, so the refusal names the file the
    chain walk was reading when it was raised: the base, never the top-level
    file, which parses."""
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    top = _write(tmp_path / "ops" / "top.yaml", {"extends": "deep.json"})

    code, shown, shell_entered, kept = _scan_through_the_gate(
        tmp_path, monkeypatch, capsys, mode, top
    )

    assert code == 3, shown
    assert "deep.jsoncouldnotbeparsed" in shown, shown
    assert "top.yamlcouldnotbeparsed" not in shown, shown
    assert recording_runner == [], "a container command was run"
    assert shell_entered == 0, "the Nix shell was entered"
    assert kept, "the previous run's output was cleared"


@pytest.mark.parametrize("mode", _GATE_MODES)
def test_the_refusal_names_an_extended_base_of_the_environment_config(
    tmp_path, recording_runner, monkeypatch, capsys, mode
):
    """The same for the file ASH_CONFIG names: it parses, its base does not."""
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    named = _write(tmp_path / "ops" / "env.yaml", {"extends": "deep.json"})
    fine = _write(tmp_path / "ops" / "fine.yaml", {"project_name": "op"})

    code, shown, _entered, kept = _scan_through_the_gate(
        tmp_path, monkeypatch, capsys, mode, fine, ash_config=named
    )

    assert code == 3, shown
    assert "deep.jsoncouldnotbeparsed" in shown, shown
    assert "env.yamlcouldnotbeparsed" not in shown, shown
    assert "fine.yaml" not in shown, shown
    assert recording_runner == []
    assert kept


@pytest.mark.parametrize("mode", _GATE_MODES)
def test_the_refusal_names_no_extended_base_the_environment_chose(
    tmp_path, recording_runner, monkeypatch, capsys, mode
):
    """A base named through an environment reference is named ``<value>`` in
    every message about it, so the refusal for a base nested too deep does not
    name that file either; it is still refused with exit 3 before anything
    runs."""
    _nested_past_the_recursion_limit(tmp_path / "ops" / "deep.json")
    monkeypatch.setenv("ASH_BASE_CHOSEN_BY_THE_ENVIRONMENT", "deep.json")
    top = tmp_path / "ops" / "top.yaml"
    top.write_text(
        "extends: ${ASH_BASE_CHOSEN_BY_THE_ENVIRONMENT}\nproject_name: op\n",
        encoding="utf-8",
    )

    code, shown, shell_entered, kept = _scan_through_the_gate(
        tmp_path, monkeypatch, capsys, mode, top
    )

    assert code == 3, shown
    assert "deep.json" not in shown, shown
    assert recording_runner == [], "a container command was run"
    assert shell_entered == 0, "the Nix shell was entered"
    assert kept, "the previous run's output was cleared"


@pytest.mark.parametrize(
    "content",
    [b"project_name: [unclosed\n", b"\xff\xfeproject_name: op\n"],
    ids=["not-yaml", "not-utf8"],
)
@pytest.mark.parametrize("mode", _GATE_MODES)
def test_an_unparsable_config_is_refused_the_same_way_in_every_mode(
    tmp_path, recording_runner, monkeypatch, capsys, mode, content
):
    """Exit 3, the file named, no container command, no shell and the previous
    run's output kept, whichever image the run would use and in nix mode."""
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_bytes(content)

    code, shown, shell_entered, kept = _scan_through_the_gate(
        tmp_path, monkeypatch, capsys, mode, config
    )

    assert code == 3, shown
    assert "ash.yamlcouldnotbeparsed" in shown, shown
    assert recording_runner == []
    assert shell_entered == 0
    assert kept


def _one_project_workspace_plan(root: Path) -> WorkspacePlan:
    """A one-project workspace plan rooted at *root*, the shape the CLI builds."""
    project = root / "api"
    project.mkdir(parents=True, exist_ok=True)
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    return WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=project.as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
            )
        ],
    )


def _workspace_container_scan(tmp_path: Path, monkeypatch, capsys, build: str, config):
    """A container run of a workspace plan rooted at ``tmp_path / "ws"``, with
    the runner recorded by the caller's ``recording_runner``. Returns the exit
    code, what the run printed with every blank removed, and whether the
    previous run's output is still there."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root = tmp_path / "ws"
    plan = _one_project_workspace_plan(root)
    out = tmp_path / "out"
    previous = out / "reports" / "ash.sarif"
    previous.parent.mkdir(parents=True, exist_ok=True)
    previous.write_text('{"runs": []}\n', encoding="utf-8")
    try:
        ras.run_ash_scan(
            source_dir=str(root),
            output_dir=str(out),
            mode=RunMode.container,
            workspace_plan=plan,
            config=str(config) if config is not None else None,
            show_summary=False,
            progress=False,
            quiet=True,
            **_BUILDS[build],
        )
        code = 0
    except SystemExit as refusal:
        code = int(refusal.code or 0)
    shown = capsys.readouterr()
    # The console may write color escapes into a captured stream on one OS;
    # the compare reads the words, not the styling.
    plain = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", shown.out + shown.err)
    squeezed = re.sub(r"\s+", "", plain)
    return code, squeezed, previous.exists()


@pytest.mark.parametrize("suffix", ["json", "yaml"])
@pytest.mark.parametrize("build", sorted(_BUILDS))
def test_a_workspace_plan_container_run_refuses_a_config_nested_past_the_recursion_limit(
    tmp_path, recording_runner, monkeypatch, capsys, build, suffix
):
    """A container run of a workspace plan skips the pre-run gate (the plan was
    resolved on the host), so the parse check inside ``_run_container_mode`` is
    the one layer that reads the config before the runner. It refuses a file
    nested past the interpreter's recursion limit with exit 3, naming the file;
    the traceback of a RecursionError never reaches the caller, and nothing is
    built, started or cleared."""
    config = _nested_past_the_recursion_limit(tmp_path / "ops" / f"deep.{suffix}")

    code, shown, kept = _workspace_container_scan(
        tmp_path, monkeypatch, capsys, build, config
    )

    assert code == 3, shown
    assert f"deep.{suffix}couldnotbeparsed" in shown, shown
    assert recording_runner == [], "a container command was run"
    assert kept, "the previous run's output was cleared"


@pytest.mark.parametrize("build", sorted(_BUILDS))
def test_a_workspace_plan_container_run_refuses_a_discovered_config_nested_too_deep(
    tmp_path, recording_runner, monkeypatch, capsys, build
):
    """With no ``--config`` the parse check reads the file discovery finds at
    the workspace root, which the scanned repository controls."""
    _nested_past_the_recursion_limit(tmp_path / "ws" / ".ash" / ".ash.yaml")

    code, shown, kept = _workspace_container_scan(
        tmp_path, monkeypatch, capsys, build, None
    )

    assert code == 3, shown
    assert ".ash.yamlcouldnotbeparsed" in shown, shown
    assert recording_runner == []
    assert kept
