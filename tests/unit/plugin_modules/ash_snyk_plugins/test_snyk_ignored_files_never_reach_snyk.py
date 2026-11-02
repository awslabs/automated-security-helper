# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ignored file, or ASH's own output, never reaches the snyk program.

``snyk code test`` uploads the files it reads, and has no option that leaves out a
path. So snyk-code refuses a target holding a file the operator's
``global_settings.ignore_paths`` match: the row is ERROR, the message names the first
such file and the pattern that matched it, and snyk is not started. The files are
every file snyk is given: the source directory for the source target, and the work
directory, wherever it is, for the converted one. Each is matched as ASH's findings
step matches the location snyk reports in it, its path below the directory snyk
tests, by the one function both call; so a file is refused exactly when ASH would
drop its finding.

ASH's own output directory is never in what snyk is given either: a source target
that holds it is refused, whatever .gitignore it has, since snyk honoring one is read
from its sources and not measured.

These tests run the scanner through the executor with a stand-in ``snyk`` first on
PATH. The stand-in records its arguments and the text of every file below the
directory it is given, which is what the real program would read and upload. A canary
sits in the file that must not be sent. When the target is refused, the stand-in never
runs and the canary is in nothing it recorded. The controls show the stand-in does
receive the canary when nothing refuses it, so its absence means something.

snyk-code has no exclusion option of its own, so the operator's ignore paths are the
only rule the refusal checks; the last test fails if the scanner gains one.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.client_scanner_exclusions import (
    SCANNER_EXCLUSION_OPTIONS,
)
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
    SnykCodeScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import Run, SarifReport
from automated_security_helper.utils.output_dir_links import ignore_output_dir_in_git
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

CANARY = "snyk-canary-4b1f0e9d7c"

#: The stand-in snyk. It reads every file below the directory it is given, as the
#: real program reads what it uploads, honoring no ignore file, and writes its
#: arguments and each file's path and text to ``received.json`` in the record
#: directory.
_STAND_IN = """#!{python} -I
import json, os, sys

args = sys.argv[1:]
output = next(a for a in args if a.startswith("--sarif-file-output="))
target = args[args.index(output) - 1]
files = {{}}
for directory, _subdirectories, names in os.walk(target):
    for name in names:
        path = os.path.join(directory, name)
        with open(path, encoding="utf-8", errors="replace") as handle:
            files[os.path.relpath(path, target).replace(os.sep, "/")] = handle.read()
os.makedirs({record!r}, exist_ok=True)
with open(os.path.join({record!r}, "received.json"), "w", encoding="utf-8") as handle:
    json.dump({{"argv": args, "files": files}}, handle)
sarif = {{"version": "2.1.0", "runs": [
    {{"tool": {{"driver": {{"name": "SnykCode", "rules": []}}}}, "results": []}}
]}}
with open(output.split("=", 1)[1], "w", encoding="utf-8") as handle:
    json.dump(sarif, handle)
"""

#: An archive member below a vendored directory, as the archive converter names it
#: in the work directory.
VENDORED_MEMBER = "archive/src__bundle__zip/vendor/m.js"


@pytest.fixture
def record(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Where the stand-in snyk, first on PATH, records what it was given."""
    record = tmp_path / "snyk-record"
    binary = tmp_path / "bin" / "snyk"
    binary.parent.mkdir()
    stand_in = _STAND_IN.format(python=sys.executable, record=str(record))
    if sys.platform == "win32":
        # CreateProcess starts no shebang script. ASH looks for snyk.exe, snyk.bat
        # and snyk.cmd before the bare name, so the program is a .cmd that runs the
        # same script (its shebang line is only a comment to Python).
        script = binary.parent / "snyk_stand_in.py"
        script.write_text(stand_in, encoding="utf-8")
        binary.parent.joinpath("snyk.cmd").write_text(
            f'@"{sys.executable}" -I "{script}" %*\r\n', encoding="utf-8"
        )
    else:
        binary.write_text(stand_in, encoding="utf-8")
        binary.chmod(0o755)
    monkeypatch.setenv("PATH", f"{binary.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    return record


def _context(
    tmp_path: Path, ignore_paths: List[str], output_inside: bool = False
) -> PluginContext:
    """A source tree with a canary under thirdparty/, and an output directory
    outside it unless ``output_inside``, with the work directory below that."""
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output" if output_inside else tmp_path / "out"
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=path, reason="vendored") for path in ignore_paths
    ]
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )
    (source / "thirdparty").mkdir(parents=True)
    Path(context.work_dir).mkdir(parents=True)
    (source / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    (source / "thirdparty" / "lib.js").write_text("const b = 2;\n", encoding="utf-8")
    (source / "thirdparty" / "zz-canary.js").write_text(
        f"const canary = '{CANARY}';\n", encoding="utf-8"
    )
    return context


def _converted(context: PluginContext) -> Path:
    """The work directory with an ordinary member and the vendored one (the canary)."""
    work = Path(context.work_dir)
    member = work / VENDORED_MEMBER
    member.parent.mkdir(parents=True)
    (member.parent.parent / "ok.js").write_text("const ok = 1;\n", encoding="utf-8")
    member.write_text(f"const canary = '{CANARY}';\n", encoding="utf-8")
    return work


def _run(context: PluginContext, target: Path, target_type: str):
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    # As the scan phase sets it: the operator's ignore paths.
    executor._global_ignore_paths = ignore_paths_that_skip_scanning(
        context.config.global_settings.ignore_paths, ignore_suppressions=False
    )
    (container,) = executor._execute_scanner(
        "snyk-code", scanner, [{"path": target, "type": target_type}]
    )
    return container


def _errors(container) -> str:
    return "\n".join(str(error) for error in container.errors)


def _received(record: Path) -> Optional[Dict[str, Any]]:
    """What the stand-in snyk was given, or None when it never ran."""
    path = record / "received.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _canary_in(received: Optional[Dict[str, Any]]) -> List[str]:
    """Where the canary reached the stand-in: ``argv``, or each file holding it."""
    if received is None:
        return []
    found = ["argv"] if CANARY in json.dumps(received["argv"]) else []
    return found + sorted(
        name for name, text in received["files"].items() if CANARY in text
    )


def _findings_step_drops(context: PluginContext, uri: str) -> bool:
    """Whether ASH's findings step drops a snyk finding reported at ``uri``."""
    sarif = SarifReport(
        runs=[
            Run(
                tool={"driver": {"name": "SnykCode"}},
                results=[
                    {
                        "ruleId": "probe",
                        "message": {"text": "probe"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        ],
                    }
                ],
            )
        ]
    )
    kept = apply_suppressions_to_sarif(sarif, context).runs[0].results or []
    return not kept


class TestTheSourceTarget:
    # The refusal tests are integration like the tests that run snyk: each drives
    # the scanner's scan(), which starts the stand-in snyk on any path the refusal
    # does not take, so a regression in the refusal would start a process here.
    @pytest.mark.integration
    def test_a_source_target_holding_an_ignored_file_never_starts_snyk(
        self, tmp_path, record
    ):
        context = _context(tmp_path, ["thirdparty/**"])

        container = _run(context, Path(context.source_dir), "source")

        received = _received(record)
        assert _canary_in(received) == []
        assert received is None, "the stand-in snyk ran"
        assert container.status == ScannerStatus.ERROR
        errors = _errors(container)
        assert "the first 'thirdparty/lib.js', which 'thirdparty/**' matches" in errors
        assert "2 files there are in global_settings.ignore_paths" in errors
        assert "--exclude-scanners snyk-code" in errors
        assert "snyk code test was not started" in errors
        assert CANARY not in errors

    @pytest.mark.integration
    def test_without_an_ignored_file_snyk_runs_and_receives_every_file(
        self, tmp_path, record
    ):
        """The control: the stand-in reads the canary when nothing ignores it."""
        context = _context(tmp_path, ["docs/**"])

        container = _run(context, Path(context.source_dir), "source")

        assert container.status != ScannerStatus.ERROR, _errors(container)
        received = _received(record)
        assert received is not None, "the stand-in snyk did not run"
        assert received["argv"][:2] == ["code", "test"]
        # The source directory is tested as a copy of the scan set, made outside the
        # tree, so the directory snyk is given is not the source directory itself.
        # It is the argument before --sarif-file-output, as the stand-in reads it.
        argv = received["argv"]
        output = next(arg for arg in argv if arg.startswith("--sarif-file-output="))
        assert argv[argv.index(output) - 1] != Path(context.source_dir).as_posix()
        assert sorted(received["files"]) == [
            "app.js",
            "thirdparty/lib.js",
            "thirdparty/zz-canary.js",
        ]
        assert _canary_in(received) == ["thirdparty/zz-canary.js"]

    @pytest.mark.parametrize("gitignored", [True, False])
    @pytest.mark.integration
    def test_a_source_target_holding_the_output_dir_is_refused(
        self, tmp_path, record, gitignored
    ):
        """Whatever .gitignore the output directory has: that snyk honors one is
        read, not measured, so it is not relied on."""
        context = _context(tmp_path, [], output_inside=True)
        output = Path(context.output_dir)
        (output / "reports").mkdir(parents=True)
        (output / "reports" / "ash.html").write_text(
            f"<p>{CANARY}</p>\n", encoding="utf-8"
        )
        if gitignored:
            assert ignore_output_dir_in_git(context.source_dir, output) is True

        container = _run(context, Path(context.source_dir), "source")

        assert _received(record) is None, "the stand-in snyk ran"
        assert container.status == ScannerStatus.ERROR
        errors = _errors(container)
        assert "ASH's output directory '.ash/ash_output' is inside it" in errors
        assert "--output-dir" in errors
        assert "snyk code test was not started" in errors

    @pytest.mark.parametrize(
        "spelled, refused",
        [
            pytest.param("../out", False, id="dotdot-leaving-the-tree"),
            pytest.param("sub/../.ash/ash_output", True, id="dotdot-staying-inside"),
        ],
    )
    @pytest.mark.integration
    def test_an_output_dir_spelled_with_dotdot_is_judged_by_where_it_points(
        self, tmp_path, record, spelled, refused
    ):
        """``--output-dir ../ash_output`` is the remedy the refusal itself gives, and
        the path reaches the scanner as ``<source>/../ash_output``. Compared as
        written that is inside the source; it is outside it."""
        base = _context(tmp_path, [])
        source = Path(base.source_dir)
        output = source / spelled
        (source / "sub").mkdir()
        output.mkdir(parents=True, exist_ok=True)
        context = PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=base.config,
        )

        container = _run(context, source, "source")

        if refused:
            assert container.status == ScannerStatus.ERROR
            assert "ASH's output directory '.ash/ash_output' is inside it" in _errors(
                container
            )
            assert _received(record) is None, "the stand-in snyk ran"
        else:
            assert container.status != ScannerStatus.ERROR, _errors(container)
            assert _received(record) is not None, "the stand-in snyk did not run"

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows file names cannot hold a newline or an escape character",
    )
    @pytest.mark.integration
    def test_the_first_path_is_shown_with_its_controls_escaped(self, tmp_path, record):
        context = _context(tmp_path, ["thirdparty/**"])
        name = "a\nb\x1b[31m.js"
        (Path(context.source_dir) / "thirdparty" / name).write_text(
            "const e = 5;\n", encoding="utf-8"
        )

        container = _run(context, Path(context.source_dir), "source")

        errors = _errors(container)
        assert "the first 'thirdparty/a\\nb\\x1b[31m.js'" in errors, errors
        assert name not in errors
        assert _received(record) is None, "the stand-in snyk ran"


class TestTheConvertedTarget:
    @pytest.mark.integration
    def test_an_ignored_member_of_a_work_dir_outside_the_source_is_refused(
        self, tmp_path, record
    ):
        """The output directory outside the source, and a converted member under
        ``**/vendor/**``: ASH drops its finding, so snyk must not be given it."""
        context = _context(tmp_path, ["**/vendor/**"])
        work = _converted(context)

        container = _run(context, work, "converted")

        received = _received(record)
        assert _canary_in(received) == []
        assert received is None, "the stand-in snyk ran"
        assert container.status == ScannerStatus.ERROR
        errors = _errors(container)
        assert f"the first '{VENDORED_MEMBER}', which '**/vendor/**' matches" in errors
        assert "1 file there is in global_settings.ignore_paths" in errors
        assert "so it would upload it." in errors

    @pytest.mark.integration
    def test_a_work_dir_with_nothing_ignored_runs(self, tmp_path, record):
        """The control: the stand-in receives the member when nothing ignores it."""
        context = _context(tmp_path, ["docs/**"])
        work = _converted(context)

        container = _run(context, work, "converted")

        assert container.status != ScannerStatus.ERROR, _errors(container)
        assert _canary_in(_received(record)) == [VENDORED_MEMBER]

    @pytest.mark.parametrize(
        "pattern, output_inside, dropped",
        [
            ("**/vendor/**", False, True),
            ("**/vendor/**", True, True),
            ("archive/src__bundle__zip/**", False, True),
            ("**/ash_output/converted/archive/**", True, False),
            (".ash/ash_output/converted/**", True, False),
            ("vendor/**", False, False),
        ],
    )
    @pytest.mark.integration
    def test_refused_exactly_when_the_findings_step_drops_the_finding(
        self, tmp_path, record, pattern, output_inside, dropped
    ):
        """Both directions: a converted file whose finding ASH would drop is refused,
        and one whose finding ASH would keep is given to snyk, wherever the work
        directory is. snyk reports each location below the directory it tests, so
        the findings step matches a converted file by its path below the work
        directory, not the source directory."""
        context = _context(tmp_path, [pattern], output_inside=output_inside)
        work = _converted(context)
        drops = _findings_step_drops(context, VENDORED_MEMBER)
        assert drops is dropped

        container = _run(context, work, "converted")

        refused = container.status == ScannerStatus.ERROR
        assert refused is drops, _errors(container)
        assert (_received(record) is None) is drops


@pytest.mark.parametrize(
    "spelled, inside",
    [
        ("../out", None),
        ("../src/.ash/ash_output", Path(".ash/ash_output")),
        ("sub/../.ash/ash_output", Path(".ash/ash_output")),
        (".ash/ash_output", Path(".ash/ash_output")),
        (".", None),
    ],
)
@pytest.mark.unit
def test_the_output_dir_inside_the_target_is_read_through_dotdot(
    tmp_path, spelled, inside
):
    """The scanner base reports where ASH's output directory sits in the target
    after ``..`` and ``.`` are removed, without following a link, so a spelling
    like ``<source>/../out`` is outside and ``<source>/sub/../.ash/ash_output`` is
    inside."""
    source = tmp_path / "src"
    (source / "sub").mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=source / spelled,
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    scanner = SnykCodeScanner(context=context, config=SnykCodeScannerConfig())

    assert scanner._output_dir_inside(source) == inside


@pytest.mark.unit
def test_an_exact_source_path_is_kept_from_snyk_by_the_converter_skip(
    test_plugin_context,
):
    """A converted file's name is flattened, so an ignore path naming the source
    archive exactly matches nothing in the work directory; the archive converter
    does not extract the archive in the first place."""
    from automated_security_helper.plugin_modules.ash_builtin.converters.archive_converter import (
        ArchiveConverter,
        ArchiveConverterConfig,
    )

    test_plugin_context.config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="vendor/a.zip", reason="third-party code")
    ]
    converter = ArchiveConverter(
        context=test_plugin_context, config=ArchiveConverterConfig()
    )
    source = Path(test_plugin_context.source_dir)

    assert converter._skipped(str(source / "vendor" / "a.zip")) is True
    assert converter._skipped(str(source / "vendor" / "b.zip")) is False


@pytest.mark.unit
def test_snyk_code_has_no_exclusion_option_the_refusal_does_not_check():
    """A tripwire. The refusal checks the operator's ignore paths only, because
    snyk-code has no exclusion option of its own. If it gains one, an entry in
    SCANNER_EXCLUSION_OPTIONS or an options field that leaves files out, snyk would
    still read and upload those files: check them in
    ``SnykCodeScanner._refuse_ignored_files`` and update this test.
    """
    assert [
        option for option in SCANNER_EXCLUSION_OPTIONS if option.scanner == "snyk-code"
    ] == []
    # severity_threshold, scan_timeout and offline are every scanner's
    # (base/options.py ScannerOptionsBase); none of them leaves a file out.
    # honor_tree_exclusions is the operator's consent to snyk applying the tree's own
    # exclusion files, which narrows the analysis; it adds no path to the upload.
    assert set(SnykCodeScannerConfigOptions.model_fields) == {
        "severity_threshold",
        "scan_timeout",
        "offline",
        "honor_tree_exclusions",
    }
