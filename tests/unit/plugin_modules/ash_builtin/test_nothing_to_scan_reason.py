# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``nothing_to_scan_reason`` for cfn-lint, cfn-guard, actionlint, zizmor, gitleaks, trivy.

The hook says why a scanner has nothing to scan in this run, or None when it
cannot tell. A reason is given only from the selection the scanner's own scan()
makes, over every tree the scan hands it, and only when that selection is empty.
The scan phase and the scanner executor ask it
(core/phases/scan_phase.py, core/phases/scanner_executor.py), so its answers
decide scanner statuses.

Each selection-based hook is held to its scan() by an agreement test: on the same
tree, scan() with the tool standing in attempts a target exactly when the hook
returns None. The fixtures include files the selection refuses (a link that leads
out of the tree, a file that is not CloudFormation), which a check by file name
alone would count as input.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    NO_WORKFLOW_FILE,
    ActionlintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    CfnGuardScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    NO_ZIZMOR_INPUT,
    ZizmorScanner,
)
from automated_security_helper.utils.cfn_template_discovery import (
    NO_CLOUDFORMATION_TEMPLATE,
)
from automated_security_helper.utils.scan_targets import scan_targets

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

CFN_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\n"
    "Resources:\n"
    "  Queue:\n"
    "    Type: AWS::SQS::Queue\n"
)
#: A Resources mapping the template model rejects: cfn-lint and cfn-guard count it
#: as a target that failed.
UNMODELABLE_TEMPLATE = "Resources:\n  X:\n    Type: 'Not A Valid Type!'\n"
NOT_CLOUDFORMATION = "service:\n  name: app\n"


def _write(root: Path, files: Dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _context(
    tmp_path: Path,
    source: Dict[str, str],
    converted: Optional[Dict[str, str]] = None,
    links: Optional[Dict[str, str]] = None,
) -> PluginContext:
    """A source tree, an output directory beside it, and its converted files.

    ``links`` maps a name in the source tree to a file of the same content kept
    outside it, so the name is a symbolic link that leads out of the tree.
    """
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    _write(source_dir, source)
    output_dir = tmp_path / "out"
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir(parents=True)
    _write(work_dir, converted or {})
    for name, text in (links or {}).items():
        outside = tmp_path / "elsewhere" / name
        outside.parent.mkdir(parents=True, exist_ok=True)
        outside.write_text(text, encoding="utf-8")
        link = source_dir / name
        link.parent.mkdir(parents=True, exist_ok=True)
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
            pytest.skip(f"symlink creation unavailable on this platform: {exc}")
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=get_default_config(),
    )


class _ToolStarted(Exception):
    """Raised by the stand-in for the tool: scan() got as far as running it."""


def _scan_attempts_a_target(scanner, context, monkeypatch) -> bool:
    """Whether scan(), over every tree a scan hands the scanner, attempts a target.

    The dependency check passes and the tool is a stand-in that raises, so a
    target scan() selects is attempted and then fails; nothing real runs.
    """
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )

    def tool(command, *args, **kwargs):
        raise _ToolStarted(command)

    monkeypatch.setattr(scanner, "_run_subprocess", tool)
    attempted = False
    for target_type, target in scan_targets(context):
        try:
            scanner.scan(target=target, target_type=target_type)
        except ScannerError:
            pass
        attempted = attempted or scanner.targets_attempted > 0
    return attempted


# --------------------------------------------------------------------------- #
# The trees a scan hands a scanner
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("converted", "expected"),
    [
        pytest.param({}, ["source"], id="no-converted-files"),
        pytest.param({"a/b.yaml": "x: 1\n"}, ["source", "converted"], id="converted"),
    ],
)
def test_scan_targets_are_the_trees_scan_phase_queues(tmp_path, converted, expected):
    context = _context(tmp_path, {"app.py": "x = 1\n"}, converted)
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[CfnLintScanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    phase.validation_manager = MagicMock()
    with (
        patch.object(CfnLintScanner, "validate_plugin_dependencies", return_value=True),
        patch(
            "automated_security_helper.core.phases.scan_phase.ScannerExecutor"
        ) as executor,
    ):
        double = MagicMock()
        double.completed_scanners = []
        double.run_parallel.return_value = aggregated
        double.run_sequential.return_value = aggregated
        executor.return_value = double
        phase._execute_phase(aggregated_results=aggregated)
    ((_, _, tasks),) = executor.call_args.kwargs["scanner_tasks"]

    queued = [(task["type"], Path(task["path"])) for task in tasks]
    assert queued == scan_targets(context)
    assert [target_type for target_type, _ in queued] == expected


# --------------------------------------------------------------------------- #
# cfn-lint and cfn-guard: the CloudFormation templates discover_templates selects
# --------------------------------------------------------------------------- #

CFN_SCANNERS = [
    pytest.param(CfnLintScanner, id="cfn-lint"),
    pytest.param(CfnGuardScanner, id="cfn-guard"),
]


@pytest.fixture
def no_rules_bundle(monkeypatch):
    """cfn-guard selects its rules before its templates; no bundle is installed here."""
    monkeypatch.setattr(CfnGuardScanner, "_selected_rules", lambda self: [])


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_template_in_the_source_tree_is_something_to_scan(tmp_path, scanner_class):
    context = _context(tmp_path, {"stack.yaml": CFN_TEMPLATE})

    assert scanner_class(context=context).nothing_to_scan_reason() is None


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_tree_without_a_template_has_nothing_to_scan(tmp_path, scanner_class):
    context = _context(
        tmp_path,
        {"README.md": "# app\n", "config.yaml": NOT_CLOUDFORMATION},
        {"archive/config.yaml": NOT_CLOUDFORMATION},
    )

    assert (
        scanner_class(context=context).nothing_to_scan_reason()
        == NO_CLOUDFORMATION_TEMPLATE
    )


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_template_only_in_the_converted_tree_is_something_to_scan(
    tmp_path, scanner_class
):
    context = _context(
        tmp_path, {"README.md": "# app\n"}, {"archive/stack.yaml": CFN_TEMPLATE}
    )

    assert scanner_class(context=context).nothing_to_scan_reason() is None


@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
def test_a_template_the_model_rejects_is_something_to_scan(tmp_path, scanner_class):
    """scan() counts it as a target that failed, which an absent tool cannot excuse."""
    context = _context(tmp_path, {"custom.yaml": UNMODELABLE_TEMPLATE})

    assert scanner_class(context=context).nothing_to_scan_reason() is None


CFN_TREES = [
    pytest.param({"source": {"stack.yaml": CFN_TEMPLATE}}, id="template"),
    pytest.param(
        {"source": {"README.md": "# app\n", "config.yaml": NOT_CLOUDFORMATION}},
        id="no-template",
    ),
    pytest.param(
        {"source": {"README.md": "# app\n"}, "converted": {"a/s.json": "{}"}},
        id="converted-without-template",
    ),
    pytest.param(
        {"source": {"README.md": "# app\n"}, "converted": {"a/s.yaml": CFN_TEMPLATE}},
        id="template-only-converted",
    ),
    pytest.param({"source": {"custom.yaml": UNMODELABLE_TEMPLATE}}, id="unmodelable"),
    pytest.param({"source": {"broken.json": '{"Resources": '}}, id="does-not-parse"),
    pytest.param(
        {"source": {"README.md": "# app\n"}, "links": {"linked.yaml": CFN_TEMPLATE}},
        id="template-through-a-link-out-of-the-tree",
    ),
]


@pytest.mark.usefixtures("no_rules_bundle")
@pytest.mark.parametrize("scanner_class", CFN_SCANNERS)
@pytest.mark.parametrize("tree", CFN_TREES)
def test_cfn_scan_and_hook_agree(tmp_path, monkeypatch, scanner_class, tree):
    context = _context(
        tmp_path, tree["source"], tree.get("converted"), tree.get("links")
    )
    reason = scanner_class(context=context).nothing_to_scan_reason()

    attempted = _scan_attempts_a_target(
        scanner_class(context=context), context, monkeypatch
    )

    assert (reason is None) == attempted, (reason, attempted)


# --------------------------------------------------------------------------- #
# actionlint: the workflow files _workflow_files selects
# --------------------------------------------------------------------------- #

WORKFLOW = (
    "on: push\n"
    "jobs:\n"
    "  build:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: echo hi\n"
)
#: A workflow whose local reference resolves outside the scanned tree (the
#: scan root's parent, which exists). actionlint would read and quote what it
#: names, so _workflow_files leaves it out.
WORKFLOW_USING_A_PATH_OUTSIDE = WORKFLOW + "      - uses: ./..\n"
COMPOSITE_ACTION = "name: a\nruns:\n  using: composite\n  steps: []\n"

WORKFLOW_TREES = [
    pytest.param({"source": {".github/workflows/ci.yml": WORKFLOW}}, id="workflow"),
    pytest.param(
        {"source": {"README.md": "# app\n", "ci.yml": WORKFLOW}},
        id="no-workflow",
    ),
    pytest.param(
        {"source": {".github/workflows/nested/ci.yml": WORKFLOW}},
        id="below-the-workflows-directory",
    ),
    pytest.param(
        {"source": {"node_modules/pkg/.github/workflows/ci.yml": WORKFLOW}},
        id="vendored",
    ),
    pytest.param(
        {"source": {"action.yml": COMPOSITE_ACTION}},
        id="composite-action-only",
    ),
    pytest.param(
        {
            "source": {"README.md": "# app\n"},
            "converted": {"archive/.github/workflows/ci.yml": WORKFLOW},
        },
        id="workflow-only-converted",
    ),
    pytest.param(
        {
            "source": {"README.md": "# app\n"},
            "links": {".github/workflows/ci.yml": WORKFLOW},
        },
        id="workflow-through-a-link-out-of-the-tree",
    ),
    pytest.param(
        {"source": {".github/workflows/ci.yml": WORKFLOW_USING_A_PATH_OUTSIDE}},
        id="workflow-referencing-a-path-outside",
    ),
]


def test_actionlint_a_workflow_in_the_source_tree_is_something_to_scan(tmp_path):
    context = _context(tmp_path, {".github/workflows/ci.yml": WORKFLOW})

    assert ActionlintScanner(context=context).nothing_to_scan_reason() is None


def test_actionlint_a_tree_without_a_workflow_has_nothing_to_scan(tmp_path):
    context = _context(
        tmp_path,
        {"README.md": "# app\n", "action.yml": COMPOSITE_ACTION},
        {"archive/ci.yml": WORKFLOW},
    )

    assert ActionlintScanner(context=context).nothing_to_scan_reason() == (
        NO_WORKFLOW_FILE
    )


def test_actionlint_a_workflow_only_in_the_converted_tree_is_something_to_scan(
    tmp_path,
):
    context = _context(
        tmp_path,
        {"README.md": "# app\n"},
        {"archive/.github/workflows/ci.yml": WORKFLOW},
    )

    assert ActionlintScanner(context=context).nothing_to_scan_reason() is None


def test_actionlint_the_hook_does_not_repeat_the_scans_warnings(tmp_path, caplog):
    """scan() warns about the workflows it skips; the hook does not warn again."""
    context = _context(
        tmp_path,
        {"README.md": "# app\n"},
        links={".github/workflows/ci.yml": WORKFLOW},
    )

    with caplog.at_level(logging.DEBUG):
        reason = ActionlintScanner(context=context).nothing_to_scan_reason()

    # There is a workflow file, left out of the lint: the reason names it
    # rather than saying the tree holds none.
    assert reason != NO_WORKFLOW_FILE
    assert "left out of the lint" in reason
    assert ".github/workflows/ci.yml" in reason
    assert "Not linting" not in caplog.text


@pytest.mark.parametrize("tree", WORKFLOW_TREES)
def test_actionlint_scan_and_hook_agree(tmp_path, monkeypatch, tree):
    context = _context(
        tmp_path, tree["source"], tree.get("converted"), tree.get("links")
    )
    reason = ActionlintScanner(context=context).nothing_to_scan_reason()

    attempted = _scan_attempts_a_target(
        ActionlintScanner(context=context), context, monkeypatch
    )

    assert (reason is None) == attempted, (reason, attempted)


# --------------------------------------------------------------------------- #
# zizmor: the workflows and composite actions _collect_inputs selects
# --------------------------------------------------------------------------- #

ZIZMOR_TREES = [
    pytest.param({"source": {".github/workflows/ci.yml": WORKFLOW}}, id="workflow"),
    pytest.param(
        {"source": {"tools/setup/action.yaml": COMPOSITE_ACTION}},
        id="composite-action",
    ),
    pytest.param(
        {"source": {"README.md": "# app\n", "ci.yml": WORKFLOW}},
        id="no-input",
    ),
    pytest.param(
        {"source": {".github/workflows/nested/ci.yml": WORKFLOW}},
        id="below-the-workflows-directory",
    ),
    pytest.param(
        {"source": {"node_modules/pkg/action.yml": COMPOSITE_ACTION}},
        id="vendored",
    ),
    pytest.param(
        {
            "source": {"README.md": "# app\n"},
            "converted": {"archive/.github/workflows/ci.yml": WORKFLOW},
        },
        id="workflow-only-converted",
    ),
    pytest.param(
        {
            "source": {"README.md": "# app\n"},
            "links": {".github/workflows/ci.yml": WORKFLOW},
        },
        id="workflow-through-a-link-out-of-the-tree",
    ),
    pytest.param(
        {"source": {"README.md": "# app\n"}, "links": {"action.yml": COMPOSITE_ACTION}},
        id="action-through-a-link-out-of-the-tree",
    ),
]


@pytest.mark.parametrize(
    "files",
    [
        pytest.param({".github/workflows/ci.yml": WORKFLOW}, id="workflow"),
        pytest.param({"action.yml": COMPOSITE_ACTION}, id="composite-action"),
    ],
)
def test_zizmor_a_workflow_or_action_in_the_source_tree_is_something_to_scan(
    tmp_path, files
):
    context = _context(tmp_path, files)

    assert ZizmorScanner(context=context).nothing_to_scan_reason() is None


def test_zizmor_a_tree_without_a_workflow_or_action_has_nothing_to_scan(tmp_path):
    context = _context(
        tmp_path,
        {"README.md": "# app\n", "ci.yml": WORKFLOW},
        {"archive/ci.yml": WORKFLOW},
    )

    assert ZizmorScanner(context=context).nothing_to_scan_reason() == (NO_ZIZMOR_INPUT)


def test_zizmor_a_workflow_only_in_the_converted_tree_is_something_to_scan(
    tmp_path,
):
    context = _context(
        tmp_path,
        {"README.md": "# app\n"},
        {"archive/.github/workflows/ci.yml": WORKFLOW},
    )

    assert ZizmorScanner(context=context).nothing_to_scan_reason() is None


def test_zizmor_the_hook_does_not_repeat_the_scans_warnings(tmp_path, caplog):
    context = _context(
        tmp_path,
        {"README.md": "# app\n"},
        links={".github/workflows/ci.yml": WORKFLOW},
    )

    with caplog.at_level(logging.DEBUG):
        reason = ZizmorScanner(context=context).nothing_to_scan_reason()

    assert reason == NO_ZIZMOR_INPUT
    assert "Not auditing" not in caplog.text


@pytest.mark.parametrize("tree", ZIZMOR_TREES)
def test_zizmor_scan_and_hook_agree(tmp_path, monkeypatch, tree):
    context = _context(
        tmp_path, tree["source"], tree.get("converted"), tree.get("links")
    )
    reason = ZizmorScanner(context=context).nothing_to_scan_reason()

    attempted = _scan_attempts_a_target(
        ZizmorScanner(context=context), context, monkeypatch
    )

    assert (reason is None) == attempted, (reason, attempted)


# --------------------------------------------------------------------------- #
# gitleaks and trivy: their tool walks the whole target, so they cannot tell
# --------------------------------------------------------------------------- #

WHOLE_TREE_SCANNERS = [
    pytest.param(GitleaksScanner, id="gitleaks"),
    pytest.param(TrivyScanner, id="trivy"),
]


@pytest.mark.parametrize("scanner_class", WHOLE_TREE_SCANNERS)
def test_a_whole_tree_scanner_states_its_hook(scanner_class):
    """Stated on the class, so the answer is this scanner's and not a default."""
    assert "nothing_to_scan_reason" in vars(scanner_class)


@pytest.mark.parametrize("scanner_class", WHOLE_TREE_SCANNERS)
@pytest.mark.parametrize(
    ("source", "converted"),
    [
        pytest.param({"README.md": "# app\n"}, {}, id="readme-only"),
        pytest.param({}, {}, id="empty"),
        pytest.param(
            {"README.md": "# app\n"}, {"archive/notes.txt": "x\n"}, id="converted"
        ),
    ],
)
def test_a_whole_tree_scanner_cannot_tell_there_is_nothing_to_scan(
    tmp_path, scanner_class, source, converted
):
    context = _context(tmp_path, source, converted)

    assert scanner_class(context=context).nothing_to_scan_reason() is None
