# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The exit-code fields the scan entry reads come from one load of the config.

Container and nix mode load the operator's config before the run
(``_outer_mode_config_load``), to refuse what a local scan would refuse. The
two exit-code readers (``fail_on_findings`` and ``fail_on_incomplete_scanners``)
need the same file, so the gate hands them the two values it read, and a mode
that has no completed gate load (a local scan, an image whose ASH may declare a
different schema, a load that failed some other way) loads the file once for
both.

``apply_config_overrides`` is the one step of the gate that could make the
shared object differ from a fresh read. It returns a new model, but a caller
that mutated its input, or raised half way through, must not change what the
readers report, so the values are read before the apply.

The cells run the production entry (``run_ash_scan``) with the container runner
replaced by a recorder.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan
from tests.utils.helpers import stand_in_host_ids

AshConfig.model_rebuild()


class Stopped(Exception):
    pass


def _tree(tmp_path, fail_on_findings=True, fail_on_incomplete_scanners=False):
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = tmp_path / "ops" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "project_name: t\n"
        f"fail_on_findings: {str(fail_on_findings).lower()}\n"
        f"fail_on_incomplete_scanners: {str(fail_on_incomplete_scanners).lower()}\n",
        encoding="utf-8",
    )
    return src, config


def _counting_loads(monkeypatch):
    calls = {"reader_loads": 0, "gate_loads": 0}
    real_reader_load = ras._load_config_file
    real_gate_load = ras._loaded_config_file

    def reader_load(opts, for_run=False):
        calls["reader_loads"] += 1
        return real_reader_load(opts, for_run=for_run)

    def gate_load(opts, for_run=False, **kwargs):
        calls["gate_loads"] += 1
        return real_gate_load(opts, for_run=for_run, **kwargs)

    # _load_config_file calls _loaded_config_file itself, so gate_loads counts
    # every load of the file, the readers' included. A cell that expects the
    # gate not to load asserts gate_loads == reader_loads.
    monkeypatch.setattr(ras, "_load_config_file", reader_load)
    monkeypatch.setattr(ras, "_loaded_config_file", gate_load)
    return calls


def _container(tmp_path, monkeypatch, config, src, **extra):
    """Run the entry in container mode up to the runner; the kwargs the runner
    is handed come back."""
    stand_in_host_ids(monkeypatch)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    seen: Dict[str, Any] = {}

    def record(opts, logger, **kwargs):
        # ``reads`` is the run's OperatorConfigReads, handed to every
        # container-mode check; these cells are about the two resolved flags.
        kwargs.pop("reads", None)
        seen.update(kwargs)
        raise Stopped

    monkeypatch.setattr(ras, "_run_container_mode", record)
    with pytest.raises(Stopped):
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(tmp_path / "out"),
            config=str(config),
            mode=RunMode.container,
            progress=False,
            show_summary=False,
            **extra,
        )
    return seen


def test_a_container_run_loads_the_config_once_for_the_gate_and_both_readers(
    tmp_path, monkeypatch
):
    src, config = _tree(tmp_path, True, False)
    calls = _counting_loads(monkeypatch)

    seen = _container(
        tmp_path, monkeypatch, config, src, ash_revision_to_install="LOCAL"
    )

    assert seen == {
        "resolved_fail_on_findings": True,
        "resolved_fail_on_incomplete_scanners": False,
        "image_may_differ": False,
    }
    assert calls["reader_loads"] == 0, "a reader loaded what the gate had loaded"
    assert calls["gate_loads"] == 1, calls


def test_an_image_that_may_differ_builds_the_model_from_the_gates_document(
    tmp_path, monkeypatch
):
    """The gate parses without loading when the image's ASH can hold another
    schema, and hands its resolved document on. The readers build the model
    from that document and do not load the file, so it is not read a second
    time.

    The runner is also handed the gate's answer about the image
    (``image_may_differ``), which the record repair after the run takes
    instead of asking again, so it is part of what this run hands over."""
    src, config = _tree(tmp_path, False, True)
    calls = _counting_loads(monkeypatch)

    seen = _container(
        tmp_path, monkeypatch, config, src, ash_revision_to_install="v9.9.9"
    )

    assert seen == {
        "resolved_fail_on_findings": False,
        "resolved_fail_on_incomplete_scanners": True,
        "image_may_differ": True,
    }
    assert calls["reader_loads"] == 0, calls
    assert calls["gate_loads"] == 0, calls


def test_a_gate_load_that_failed_some_other_way_is_read_again_once(
    tmp_path, monkeypatch
):
    src, config = _tree(tmp_path, False, True)
    real = ras._loaded_config_file
    attempts = {"n": 0}

    def fails_the_first_time(opts, for_run=False, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise OSError("the gate's load failed some other way")
        return real(opts, for_run=for_run, **kwargs)

    monkeypatch.setattr(ras, "_loaded_config_file", fails_the_first_time)
    calls = _counting_loads(monkeypatch)

    seen = _container(
        tmp_path, monkeypatch, config, src, ash_revision_to_install="LOCAL"
    )

    assert seen == {
        "resolved_fail_on_findings": False,
        "resolved_fail_on_incomplete_scanners": True,
        "image_may_differ": False,
    }
    assert calls["reader_loads"] == 1, calls


def test_a_local_scan_loads_the_config_once_for_both_readers(tmp_path, monkeypatch):
    src, config = _tree(tmp_path, True, False)
    calls = _counting_loads(monkeypatch)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def stop(opts, logger):
        raise Stopped

    monkeypatch.setattr(ras, "_run_local_mode", stop)

    with pytest.raises(Stopped):
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(tmp_path / "out"),
            config=str(config),
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert calls["reader_loads"] == 1, calls


def test_a_config_override_is_the_value_the_container_run_is_handed(
    tmp_path, monkeypatch
):
    """The exit code follows the overridden value, as in a local scan; the
    end-to-end exit codes are pinned in
    test_config_overrides_fail_on_findings_reaches_the_exit_code_in_every_mode.py."""
    src, config = _tree(tmp_path, True, False)

    seen = _container(
        tmp_path,
        monkeypatch,
        config,
        src,
        ash_revision_to_install="LOCAL",
        config_overrides=["fail_on_findings=false"],
    )

    assert seen == {
        "resolved_fail_on_findings": False,
        "resolved_fail_on_incomplete_scanners": False,
        "image_may_differ": False,
    }


@pytest.mark.parametrize("mutator_raises", [False, True])
def test_an_apply_that_changes_its_input_does_not_change_the_reported_values(
    tmp_path, monkeypatch, mutator_raises
):
    """A non-validation failure half way through the apply (or an apply that
    writes into the object it was given) used to leave the shared object
    changed with ``loaded`` true: the readers then reported the half-applied
    value, not the file's. The values come from the model a successful apply
    returns, never from its input."""
    src, config = _tree(tmp_path, True, False)

    def apply_that_writes_into_its_input(model, overrides):
        returned = model.model_copy(deep=True)
        model.__dict__["fail_on_findings"] = not model.fail_on_findings
        model.__dict__[
            "fail_on_incomplete_scanners"
        ] = not model.fail_on_incomplete_scanners
        if mutator_raises:
            raise OSError("the apply failed half way")
        return returned

    monkeypatch.setattr(
        "automated_security_helper.config.resolve_config.apply_config_overrides",
        apply_that_writes_into_its_input,
    )

    seen = _container(
        tmp_path,
        monkeypatch,
        config,
        src,
        ash_revision_to_install="LOCAL",
        config_overrides=["fail_on_findings=false"],
    )

    assert seen == {
        "resolved_fail_on_findings": True,
        "resolved_fail_on_incomplete_scanners": False,
        "image_may_differ": False,
    }


def test_a_gate_refusal_from_the_apply_still_exits_3(tmp_path, monkeypatch):
    src, config = _tree(tmp_path)
    stand_in_host_ids(monkeypatch)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    def runner(*_a, **_k):
        raise AssertionError("the run started on a refused override")

    monkeypatch.setattr(ras, "_run_container_mode", runner)

    with pytest.raises(ras.ScanRefusedExit) as refused:
        ras.run_ash_scan(
            source_dir=str(src),
            output_dir=str(tmp_path / "out"),
            config=str(config),
            mode=RunMode.container,
            ash_revision_to_install="LOCAL",
            config_overrides=["fail_on_findings=not-a-boolean"],
            progress=False,
            show_summary=False,
        )

    assert refused.value.code == 3


def _plan(root: Path) -> WorkspacePlan:
    (root / "app").mkdir(parents=True, exist_ok=True)
    return WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="app",
                relative_path="app",
                path=(root / "app").as_posix(),
                label="app",
                display_label="app",
                severity_threshold="MEDIUM",
            )
        ],
    )


@pytest.mark.parametrize(
    "mode, plan, expected, absent",
    [
        (RunMode.container, False, "second ASH", None),
        (RunMode.nix, False, "second ASH", None),
        (RunMode.local, True, "workspace", "the ASH that mode runs"),
    ],
    ids=["container", "nix", "local-workspace"],
)
def test_a_config_base_gate_is_refused_where_it_would_be_dropped_in_words_for_the_case(
    tmp_path, monkeypatch, mode, plan, expected, absent
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    with pytest.raises(ValueError) as refused:
        ras.run_ash_scan(
            source_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            mode=mode,
            workspace_plan=_plan(tmp_path) if plan else None,
            config_base_gate=lambda _path: True,
            progress=False,
            show_summary=False,
        )

    text = str(refused.value)
    assert "config_base_gate" in text and expected in text, text
    if absent is not None:
        assert absent not in text, text


def test_a_config_base_gate_is_accepted_for_a_single_directory_local_scan(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    def stop(opts, logger):
        assert opts.config_base_gate is not None
        raise Stopped

    monkeypatch.setattr(ras, "_run_local_mode", stop)

    with pytest.raises(Stopped):
        ras.run_ash_scan(
            source_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.local,
            config_base_gate=lambda _path: True,
            progress=False,
            show_summary=False,
        )


def test_the_mcp_workspace_tool_never_hands_run_ash_scan_a_config_base_gate(tmp_path):
    """The new ValueError is for callers that pass a gate with a mode or a plan
    that would drop it. The MCP workspace tool builds its ScanOptions without
    one and scans through the workspace executor, not through run_ash_scan's
    keyword form, so it cannot reach the raise."""
    from automated_security_helper.cli.mcp.workspace import _scan_options

    opts = _scan_options(
        _plan(tmp_path),
        output_dir=None,
        config_overrides=None,
        scanners=None,
        excluded_scanners=None,
        offline=False,
        allow_missing_projects=False,
    )

    assert opts.config_base_gate is None
    assert opts.workspace_plan is not None
