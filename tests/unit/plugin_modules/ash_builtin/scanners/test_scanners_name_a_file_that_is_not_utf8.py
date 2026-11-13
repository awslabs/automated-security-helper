# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each tool-backed scanner names a file whose name is not UTF-8, or says it did not scan it.

A file name that is not valid UTF-8 reaches each scanner's tool, and each tool does its
own thing with it, measured with the real tools:

- cfn_nag_scan, given such a template, writes nothing to stdout. The template's
  findings are unknown, and the other templates of the same run have theirs.
- bandit reports the file under its absolute file URI, the byte percent-encoded
  (``pathlib``'s ``as_uri``, which bandit's SARIF writer uses for an absolute path).
- grype, a Go tool, reports the path with the byte replaced by U+FFFD.
- checkov crashes in its own SARIF writer: exit 2, no SARIF file.

Each cell runs the real scanner through the scan executor, with its tool replaced by a
stand-in that answers as that tool did (``_run_subprocess``), merges the result as the
scan phase does, saves the results and reads them back. Whatever a tool did with the
name, the results must keep the other files' findings, must name the file in the
record form (the surrogate as the six characters ``\\udcNN``) wherever they name it,
and must never call a scanner that did not finish PASSED.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scan_result_processor import (
    ScanResultProcessor,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scan_results_container import (
    ScanResultsContainer,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
)
from tests.utils import undecodable_names as names

pytestmark = pytest.mark.unit

# Every test here plants a file whose name is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

_TEMPLATE = (
    b'AWSTemplateFormatVersion: "2010-09-09"\n'
    b"Resources:\n"
    b"  Bucket:\n"
    b"    Type: AWS::S3::Bucket\n"
)

_LOCK = json.dumps(
    {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "dependencies": {"lodash": "4.17.15"}},
            "node_modules/lodash": {"version": "4.17.15"},
        },
    }
).encode("utf-8")


def _sarif(tool: str, results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": tool}}, "results": results}],
    }


def _result(rule: str, uri: str, message: str = "finding", line: int = 1) -> dict:
    return {
        "ruleId": rule,
        "level": "warning",
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def _argument_after(command: List[str], flag: str) -> str:
    return command[command.index(flag) + 1]


def _results_path(command: List[str], suffix: str) -> Path:
    """The results file the scanner told its tool to write."""
    for argument in command:
        if str(argument).endswith(suffix):
            return Path(argument)
    raise AssertionError(f"no argument ends with {suffix}: {command}")


def _run(
    tmp_path: Path,
    scanner_class: type,
    files: Dict[object, bytes],
    respond: Callable[..., Dict[str, Any]],
) -> Tuple[ScanResultsContainer, AshAggregatedResults, dict]:
    """*scanner_class* over a tree of *files*, its tool answering with *respond*:
    its container, the results read back, and the saved JSON."""
    source = names.make_tree(tmp_path / "src", files)
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )

    def answered(scanner, command, *args, **kwargs):
        response = respond([str(part) for part in command], source)
        scanner.exit_code = response["returncode"]
        return response

    # The tool-version probe and the content-database age check ask the tool itself
    # (bandit --version, grype db status); neither is what these cells measure, so
    # the version is left unprobed and the scanners declare no database here.
    with (
        patch.object(scanner_class, "validate_plugin_dependencies", return_value=True),
        patch.object(
            scanner_class, "_run_subprocess", autospec=True, side_effect=answered
        ),
        patch.object(scanner_class, "content_databases_in_use", return_value=[]),
        patch.object(scanner_class, "resolve_deferred_tool_version", return_value=None),
    ):
        scanner = scanner_class(context=context)
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        (container,) = executor._execute_scanner(
            scanner.config.name, scanner, [{"path": source, "type": "source"}]
        )
    model = ScanResultProcessor(context).process_container(
        container, AshAggregatedResults()
    )
    model.save_model(output)
    saved = names.results_file(output).read_bytes().decode("utf-8")
    return container, AshAggregatedResults.model_validate_json(saved), json.loads(saved)


def _uris(model: AshAggregatedResults) -> List[str]:
    return sorted(
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for result in model.sarif.get_all_results()
        if result.locations
    )


def _row(saved: dict, scanner: str) -> List[str]:
    """Every string the results record about *scanner*'s run but its findings.

    Searched decoded, as a reader of the record gets them: a dump of the row
    re-escapes the record form's backslash, so a record-form name appears in a
    dump only with a doubled backslash, never as the name itself.
    """

    def strings(value):
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            for key, item in value.items():
                yield from strings(key)
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)

    return [
        text
        for part in ("additional_reports", "scanner_results")
        for text in strings(saved.get(part, {}).get(scanner))
    ]


# --- cfn-nag

_ODD_TEMPLATE = b"templ\xe9.yaml"
_ODD_TEMPLATE_RECORDED = "templ\\udce9.yaml"
#: The findings cfn_nag reports for the template it can read.
_CONTROL_FINDINGS = 7


def _cfn_nag(command: List[str], source: Path) -> Dict[str, Any]:
    staged = _argument_after(command, "--input-path")
    try:
        os.fsencode(staged).decode("utf-8")
    except UnicodeDecodeError:
        return {"returncode": 1, "stdout": "", "stderr": ""}
    results = [
        _result(f"W{number}", staged, line=number)
        for number in range(1, _CONTROL_FINDINGS + 1)
    ]
    return {
        "returncode": 2,
        "stdout": json.dumps(_sarif("cfn_nag", results)),
        "stderr": "",
    }


def test_cfn_nag_keeps_the_other_templates_findings(tmp_path):
    container, model, saved = _run(
        tmp_path,
        CfnNagScanner,
        {_ODD_TEMPLATE: _TEMPLATE, b"control.yaml": _TEMPLATE},
        _cfn_nag,
    )

    uris = _uris(model)
    assert uris.count("control.yaml") == _CONTROL_FINDINGS, (container.status, uris)
    odd = [uri for uri in uris if uri != "control.yaml"]
    # The template cfn_nag wrote nothing for is named, in the record form, as not
    # scanned; any finding of it is under that name too.
    assert set(odd) <= {_ODD_TEMPLATE_RECORDED}, odd
    if not odd:
        row = _row(saved, "cfn-nag")
        assert any(_ODD_TEMPLATE_RECORDED in text for text in row), row
        assert container.status != ScannerStatus.PASSED, container.status


# --- bandit

_ODD_PY = names.ODD_BYTES


def _bandit(command: List[str], source: Path) -> Dict[str, Any]:
    results_file = _results_path(command, "bandit.sarif")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results = [
        _result(
            "B602", Path(os.fsdecode(os.path.join(os.fsencode(source), name))).as_uri()
        )
        for name in (_ODD_PY, b"control.py")
    ]
    results_file.write_text(json.dumps(_sarif("Bandit", results)), encoding="utf-8")
    return {"returncode": 1, "stdout": "", "stderr": ""}


def test_bandit_names_the_file_in_the_record_form(tmp_path):
    container, model, _ = _run(
        tmp_path,
        BanditScanner,
        {_ODD_PY: b"import subprocess\n", b"control.py": b"import subprocess\n"},
        _bandit,
    )

    # ascii(): a report holding a lone surrogate cannot be sent between workers.
    assert ascii(_uris(model)) == ascii(sorted(["control.py", names.RECORDED])), (
        container.status
    )


# --- grype

_ODD_DIR = b"dir\xe9"


def _grype(command: List[str], source: Path) -> Dict[str, Any]:
    results_file = _results_path(command, "results_sarif.sarif")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results = []
    # grype writes the odd directory's byte as U+FFFD, the replacement character.
    for directory in ("dir" + chr(0xFFFD), "dir"):
        path = f"/{directory}/package-lock.json"
        message = (
            "A medium vulnerability in npm package: lodash, version 4.17.15 was "
            f"found at: {path}"
        )
        results.append(_result("GHSA-35jh-r3h4-6jhm-lodash", path, message))
    results_file.write_text(json.dumps(_sarif("grype", results)), encoding="utf-8")
    return {"returncode": 0, "stdout": "", "stderr": ""}


def test_grype_names_the_file_in_the_record_form(tmp_path):
    container, model, _ = _run(
        tmp_path,
        GrypeScanner,
        {_ODD_DIR + b"/package-lock.json": _LOCK, b"dir/package-lock.json": _LOCK},
        _grype,
    )

    expected = sorted(["dir/package-lock.json", "dir\\udce9/package-lock.json"])
    assert ascii(_uris(model)) == ascii(expected), container.status


def _grype_reporting(paths: List[str], prepare=None):
    """A grype stand-in whose SARIF names each of *paths* as grype wrote it,
    after *prepare* (a callable of the source tree) has run."""

    def respond(command: List[str], source: Path) -> Dict[str, Any]:
        if prepare is not None:
            prepare(source)
        results_file = _results_path(command, "results_sarif.sarif")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        results = [
            _result(
                "GHSA-35jh-r3h4-6jhm-lodash",
                path,
                "A medium vulnerability in npm package: lodash, version 4.17.15 "
                f"was found at: {path}",
            )
            for path in paths
        ]
        results_file.write_text(json.dumps(_sarif("grype", results)), encoding="utf-8")
        return {"returncode": 0, "stdout": "", "stderr": ""}

    return respond


# The three ways a replacement character is left as grype wrote it. Each cell
# scans a tree that also holds dir\xe9, whose reported name must come back in
# the record form: the control that distinguishes reading the name back from
# never rewriting anything.


def test_an_entry_literally_named_with_the_replacement_character_is_left_alone(
    tmp_path,
):
    """A directory entry really named with U+FFFD keeps its own name, even with
    a sibling whose undecodable name would match it."""
    replaced = "lit" + chr(0xFFFD)
    container, model, _ = _run(
        tmp_path,
        GrypeScanner,
        {
            _ODD_DIR + b"/package-lock.json": _LOCK,
            replaced.encode("utf-8") + b"/package-lock.json": _LOCK,
            b"lit\xe9/package-lock.json": _LOCK,
        },
        _grype_reporting(
            [
                f"/dir{chr(0xFFFD)}/package-lock.json",
                # One finding per lockfile, as grype reports them: the literal
                # entry's own, and lit\xe9's, whose garbled path is the same text.
                f"/{replaced}/package-lock.json",
                f"/{replaced}/package-lock.json",
            ]
        ),
    )

    expected = sorted(
        [
            "dir\\udce9/package-lock.json",
            f"{replaced}/package-lock.json",
            f"{replaced}/package-lock.json",
        ]
    )
    assert ascii(_uris(model)) == ascii(expected), container.status


def test_a_name_two_entries_could_be_is_left_as_grype_wrote_it(tmp_path):
    """Two undecodable entries match the garbled component, so the output does
    not say which file it means, and the name stays as written."""
    container, model, _ = _run(
        tmp_path,
        GrypeScanner,
        {
            _ODD_DIR + b"/package-lock.json": _LOCK,
            b"two\xe9/package-lock.json": _LOCK,
            b"two\xe8/package-lock.json": _LOCK,
        },
        _grype_reporting(
            [
                f"/dir{chr(0xFFFD)}/package-lock.json",
                # One finding per lockfile: two\xe9's and two\xe8's garbled
                # paths are the same text, and both stay as written.
                f"/two{chr(0xFFFD)}/package-lock.json",
                f"/two{chr(0xFFFD)}/package-lock.json",
            ]
        ),
    )

    expected = sorted(
        [
            "dir\\udce9/package-lock.json",
            f"two{chr(0xFFFD)}/package-lock.json",
            f"two{chr(0xFFFD)}/package-lock.json",
        ]
    )
    assert ascii(_uris(model)) == ascii(expected), container.status


def test_a_directory_that_cannot_be_listed_keeps_the_name_as_grype_wrote_it(
    tmp_path,
):
    """With the holding directory unlistable there is no listing to match the
    garbled component against, and the name stays as written."""
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip(
            "root (and Windows, with no mode bits) lists an unreadable directory"
        )
    sub = tmp_path / "src" / "sub"
    try:
        container, model, _ = _run(
            tmp_path,
            GrypeScanner,
            {
                _ODD_DIR + b"/package-lock.json": _LOCK,
                b"sub/q\xe9/package-lock.json": _LOCK,
            },
            _grype_reporting(
                [
                    f"/dir{chr(0xFFFD)}/package-lock.json",
                    f"/sub/q{chr(0xFFFD)}/package-lock.json",
                ],
                prepare=lambda source: os.chmod(source / "sub", 0o000),
            ),
        )
    finally:
        if sub.exists():
            os.chmod(sub, 0o755)

    expected = sorted(
        ["dir\\udce9/package-lock.json", f"sub/q{chr(0xFFFD)}/package-lock.json"]
    )
    assert ascii(_uris(model)) == ascii(expected), container.status


# --- checkov


def _checkov(command: List[str], source: Path) -> Dict[str, Any]:
    return {
        "returncode": 2,
        "stdout": "",
        "stderr": (
            "Traceback (most recent call last):\n"
            "UnicodeEncodeError: 'utf-8' codec can't encode character '\\udce9' in "
            "position 4: surrogates not allowed\n"
        ),
    }


def test_checkov_that_wrote_no_sarif_is_an_error_and_costs_no_other_scanner(
    tmp_path,
):
    container, _, _ = _run(
        tmp_path,
        CheckovScanner,
        {_ODD_TEMPLATE: _TEMPLATE, b"control.yaml": _TEMPLATE},
        _checkov,
    )
    _, bandit_model, _ = _run(
        tmp_path / "other",
        BanditScanner,
        {_ODD_PY: b"import subprocess\n", b"control.py": b"import subprocess\n"},
        _bandit,
    )

    assert container.status == ScannerStatus.ERROR, container.status
    merged = ScanResultProcessor(
        PluginContext(
            source_dir=tmp_path / "other" / "src",
            output_dir=tmp_path / "merged",
            config=AshConfig(),
        )
    ).process_container(container, bandit_model)
    assert "control.py" in _uris(merged)


@pytest.mark.parametrize(
    "scanner_class", [CfnNagScanner, BanditScanner, GrypeScanner, CheckovScanner]
)
def test_the_stand_ins_answer_for_the_tool(tmp_path, scanner_class):
    """Each cell above reaches its tool only through _run_subprocess, so the stand-in
    is what answered: the scanner asked for its tool once or more."""
    calls: List[List[str]] = []
    respond = {
        CfnNagScanner: _cfn_nag,
        BanditScanner: _bandit,
        GrypeScanner: _grype,
        CheckovScanner: _checkov,
    }[scanner_class]

    def recorded(command, source):
        calls.append(command)
        return respond(command, source)

    files = {
        CfnNagScanner: {b"control.yaml": _TEMPLATE},
        BanditScanner: {b"control.py": b"import subprocess\n"},
        GrypeScanner: {b"dir/package-lock.json": _LOCK},
        CheckovScanner: {b"control.yaml": _TEMPLATE},
    }[scanner_class]
    _run(tmp_path, scanner_class, files, recorded)

    assert calls, scanner_class.__name__
