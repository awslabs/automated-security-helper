# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shipped example plugin package has to pass a real scan.

The defect
----------
``examples/ash_plugins_example`` failed every scan it was configured for. Its
converter declared ``convert(self, target)``, as ``ConverterPluginBase`` did, while
``ConvertPhase`` calls ``convert()`` with no argument, so the converter raised
``TypeError`` and the completeness gate exited 1. Its scanner returned a dict, which
ASH records as PASSED with 0 findings, so its finding never reached a report. Its
reporter wrote ``example_report.txt`` itself and returned that path, so ASH wrote the
path string into ``reports/ash.None``. Nothing ran the example, so none of this was
seen.

What the test does
------------------
It runs ``ash scan`` in local mode, in a child interpreter, on a small tree that
carries a copy of the example's own ``.ash/.ash.yaml``. The child puts a copy of the
example package on ``sys.path``, which is what installing the package does, and
nothing else: the plugins are loaded by ASH's own loader from ``ash_plugin_modules``.
The copy is outside every git checkout, where an installed package is: a config in
the scanned tree may only name modules installed outside it, and the loader may
count a module inside this repository's checkout as the scanned repository's own.
A child process because the plugin decorators register into the process-wide plugin
manager, and the example's classes must not appear in the rest of the suite's
registry.

The assertions follow each plugin's output to where a user would look for it: the
converter's file, the scanner's results in ``ash.sarif``, the reporter's file, and
the event handlers' lines on stdout.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.stand_in_uv import (
    UV_PROBED_TOOLS,
    assert_reached_the_stand_in,
    calls_naming,
    install_stand_in_uv,
    probe_bandit_in_a_child,
    reaching_the_stand_in,
    recorded_calls,
    stand_in_env,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
EXAMPLE_DIR = REPO_ROOT / "examples" / "ash_plugins_example"
MARKER = "TODO(security)"

DRIVER = reaching_the_stand_in(
    """
    import sys

    # Stands in for installing the package into ASH's environment.
    sys.path.insert(0, sys.argv[1])

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", "scan", *sys.argv[2:]]
    app()
    """
)


def _inside_a_checkout(directory: Path) -> bool:
    return any(os.path.lexists(d / ".git") for d in (directory, *directory.parents))


@pytest.fixture(scope="module")
def installed_example(tmp_path_factory):
    """A copy of the example package, in a directory outside every git checkout.

    Under pytest's temporary directory, unless --basetemp put that inside a
    checkout; then under the system temporary directory.
    """
    site = tmp_path_factory.mktemp("example-site")
    made = None
    if _inside_a_checkout(site):
        made = site = Path(tempfile.mkdtemp(prefix="ash-example-site-"))
    try:
        if _inside_a_checkout(site):
            pytest.fail(
                f"{site} is inside a git checkout, so the example package cannot be "
                "installed outside one; run with --basetemp outside every checkout"
            )
        shutil.copytree(
            EXAMPLE_DIR / "my_ash_plugins",
            site / "my_ash_plugins",
            ignore=shutil.ignore_patterns("__pycache__"),
        )
        yield site
    finally:
        if made is not None:
            shutil.rmtree(made, ignore_errors=True)


def _scan_env(base: Path) -> dict:
    """The scan's environment; the stand-in uv records its calls in base/uv.log."""
    # Offline keeps uv and the selected tools off the network. That is the whole
    # child only because no unselected scanner asks uv about its tool, which
    # test_the_scan_asks_uv_about_no_tool checks through the stand-in uv (first on
    # PATH, and reached through DRIVER). The example plugins need no tool.
    bin_dir, log = install_stand_in_uv(base)
    env = stand_in_env(bin_dir, log, dict(os.environ))
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "200"})
    return env


@pytest.fixture(scope="module")
def scan(tmp_path_factory, installed_example):
    base = tmp_path_factory.mktemp("example-plugins")
    tree = base / "repo"
    (tree / ".ash").mkdir(parents=True)
    shutil.copyfile(EXAMPLE_DIR / ".ash" / ".ash.yaml", tree / ".ash" / ".ash.yaml")
    (tree / "app.py").write_text(
        f"def main():\n    # {MARKER} validate the input\n    return 1\n",
        encoding="utf-8",
    )
    (tree / "settings.py.tmpl").write_text(
        f'NAME = "{{{{ name }}}}"  # {MARKER} render from a vault\n',
        encoding="utf-8",
    )
    # Not a template: its name ends in a space. A converter that strips the
    # scan-set names reads it as settings.py.tmpl and converts that file twice.
    (tree / "settings.py.tmpl ").write_text("NAME = 'other'\n", encoding="utf-8")
    output = base / "out"

    env = _scan_env(base)
    # `-I` keeps the child's imports to the interpreter's own site-packages, which is
    # the ASH under test, plus the one directory the driver adds.
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(DRIVER),
            str(installed_example),
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--scanners",
            "my-example-scanner",
            "--no-progress",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        cwd=base,
    )
    return tree, output, completed


@pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in uv is a POSIX shell script"
)
def test_the_scan_asks_uv_about_no_tool(scan):
    """No unselected scanner probes its tool; the example scanner has none."""
    _, output, _ = scan
    calls = recorded_calls(output.parent / "uv.log")

    assert_reached_the_stand_in(calls)
    assert calls_naming(calls, UV_PROBED_TOOLS) == [], calls


@pytest.mark.skipif(
    sys.platform == "win32", reason="the stand-in uv is a POSIX shell script"
)
def test_the_stand_in_uv_records_a_probe_under_the_scan_environment(tmp_path):
    """Control: a probing scanner, in the scan's environment, lands in the log.

    So the empty log above means no scanner asked, not that ASH found some other uv.
    """
    completed = probe_bandit_in_a_child(_scan_env(tmp_path), tmp_path)

    assert completed.returncode == 0, completed.stderr[-4000:]
    calls = recorded_calls(tmp_path / "uv.log")
    assert calls_naming(calls, ["bandit"]), calls


def _sarif_results(output: Path) -> list:
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    return [result for run in sarif["runs"] for result in run.get("results") or []]


def test_the_scan_exits_0(scan):
    """The example's findings are LOW, under the default threshold, so nothing fails."""
    _, output, completed = scan
    assert completed.returncode == 0, (
        completed.stdout[-6000:] + "\n--- stderr ---\n" + completed.stderr[-4000:]
    )
    log = (output / "ash.log").read_text(encoding="utf-8")
    assert "required positional argument" not in log


def test_the_converter_runs_and_writes_its_output(scan):
    _, output, _ = scan
    results = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    row = results["converter_results"]["my-example-converter"]
    assert row["failure"] is None, row
    converted = output / "converted" / "my-example-converter" / "settings.py"
    assert [Path(p).resolve() for p in row["converted_paths"]] == [converted.resolve()]
    assert MARKER in converted.read_text(encoding="utf-8")


def test_the_scanner_findings_reach_the_sarif_report(scan):
    """Source findings by relative path, plus the one in the converted file."""
    _, output, _ = scan
    found = sorted(
        (
            result["ruleId"],
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for result in _sarif_results(output)
    )
    uris = [uri for _, uri in found]
    assert {rule for rule, _ in found} == {"EXAMPLE-001"}, found
    assert "app.py" in uris and "settings.py.tmpl" in uris, found
    assert any(uri.endswith("my-example-converter/settings.py") for uri in uris), found
    assert len(found) == 3, found


def test_the_reporter_writes_its_report_where_the_config_says(scan):
    _, output, _ = scan
    report = (output / "reports" / "ash.example.md").read_text(encoding="utf-8")
    assert report.startswith("# ASH example report\n"), report
    assert "3 findings" in report, report
    assert "- EXAMPLE-001 at app.py:2:" in report, report
    assert not (output / "reports" / "ash.None").exists()
    assert not (output / "example_report.txt").exists()


def test_the_event_handlers_run(scan):
    _, _, completed = scan
    assert "Example plugin: scanner 'my-example-scanner' started" in completed.stdout
    assert "Example plugin: scanner 'my-example-scanner' completed" in completed.stdout


# ---------------------------------------------------------------------------
# The example plugins' own rules, run without a scan
# ---------------------------------------------------------------------------
#
# Loaded by file location, with the plugin manager's registration stubbed, so the
# example classes never enter this process's plugin registry (the same approach as
# tests/unit/base/test_plugin_context_shared_state.py).


@pytest.fixture
def example_module():
    import importlib.util
    from unittest.mock import patch

    from automated_security_helper.plugins import ash_plugin_manager

    loaded: list[str] = []

    def _load(stem: str):
        name = f"_ash_example_package_{stem}"
        spec = importlib.util.spec_from_file_location(
            name, EXAMPLE_DIR / "my_ash_plugins" / f"{stem}.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        loaded.append(name)
        with patch.object(ash_plugin_manager, "register_plugin_module"):
            spec.loader.exec_module(module)
        return module

    try:
        yield _load
    finally:
        for name in loaded:
            sys.modules.pop(name, None)


def _context(tmp_path, **global_settings):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    source = tmp_path / "src"
    source.mkdir()
    config = AshConfig(project_name="example-plugins", global_settings=global_settings)
    return PluginContext(source_dir=source, output_dir=tmp_path / "out", config=config)


def test_the_converter_skips_a_template_under_an_ignore_path(tmp_path, example_module):
    context = _context(
        tmp_path, ignore_paths=[{"path": "vendor/**", "reason": "third-party"}]
    )
    (context.source_dir / "keep.py.tmpl").write_text("A = 1\n", encoding="utf-8")
    (context.source_dir / "vendor").mkdir()
    (context.source_dir / "vendor" / "skip.py.tmpl").write_text(
        "B = 2\n", encoding="utf-8"
    )

    converter = example_module("converter").ExampleConverter(context=context)
    written = converter.convert()

    assert sorted(Path(p).relative_to(converter.results_dir) for p in written) == [
        Path("keep.py")
    ]


# Skipped on Windows as the other symlink tests are, for example
# tests/unit/converters/test_converter_scanned_tree.py.
@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
@pytest.mark.parametrize("target_type", ["source", "converted"])
def test_the_scanner_does_not_read_through_a_symlink(
    tmp_path, example_module, target_type
):
    """A link to a file outside the tree is not read, in either target."""
    context = _context(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text(f"# {MARKER} host file\n", encoding="utf-8")
    if target_type == "source":
        target = context.source_dir
    else:
        target = context.work_dir / "my-example-converter"
        target.mkdir(parents=True)
    (target / "real.py").write_text(f"# {MARKER} real file\n", encoding="utf-8")
    (target / "link.py").symlink_to(outside)

    scanner = example_module("scanner").ExampleScanner(context=context)
    report = scanner.scan(target=target, target_type=target_type)

    uris = [
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for result in report.runs[0].results
    ]
    assert [Path(uri).name for uri in uris] == ["real.py"], uris


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_template_linked_outside_the_tree_never_reaches_the_converter(
    tmp_path, example_module
):
    """The scan set the converter reads leaves the link out, and warns about it."""
    context = _context(tmp_path)
    outside = tmp_path / "outside.py.tmpl"
    outside.write_text(f"HOST = 1  # {MARKER} host file\n", encoding="utf-8")
    (context.source_dir / "keep.py.tmpl").write_text("A = 1\n", encoding="utf-8")
    (context.source_dir / "linked.py.tmpl").symlink_to(outside)
    warnings: list[str] = []

    class _Collector(logging.Handler):
        def emit(self, record):
            if record.levelno == logging.WARNING:
                warnings.append(record.getMessage())

    converter = example_module("converter").ExampleConverter(context=context)
    handler = _Collector(level=logging.WARNING)
    logging.getLogger("ash").addHandler(handler)
    try:
        written = converter.convert()
    finally:
        logging.getLogger("ash").removeHandler(handler)

    assert sorted(Path(p).relative_to(converter.results_dir) for p in written) == [
        Path("keep.py")
    ]
    assert not (converter.results_dir / "linked.py").exists()
    assert "Not scanning 'linked.py.tmpl': link leaves the scanned tree" in warnings
    assert converter.refused_inputs == []


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_the_converter_refuses_a_template_linked_inside_the_tree(
    tmp_path, example_module
):
    """The converter reads through open_source_file, which refuses a link the scan
    set keeps."""
    context = _context(tmp_path)
    (context.source_dir / "keep.py.tmpl").write_text("A = 1\n", encoding="utf-8")
    (context.source_dir / "linked.py.tmpl").symlink_to(
        context.source_dir / "keep.py.tmpl"
    )

    converter = example_module("converter").ExampleConverter(context=context)
    written = converter.convert()

    assert sorted(Path(p).relative_to(converter.results_dir) for p in written) == [
        Path("keep.py")
    ]
    assert not (converter.results_dir / "linked.py").exists()
    assert [Path(r.path).name for r in converter.refused_inputs] == ["linked.py.tmpl"]


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating hard links needs privileges on Windows"
)
@pytest.mark.parametrize("target_type", ["source", "converted"])
def test_the_scanner_does_not_read_a_hard_linked_file(
    tmp_path, example_module, target_type
):
    """A second hard link may be the same file as one outside the tree."""
    import os

    context = _context(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text(f"# {MARKER} host file\n", encoding="utf-8")
    if target_type == "source":
        target = context.source_dir
    else:
        target = context.work_dir / "my-example-converter"
        target.mkdir(parents=True)
    (target / "real.py").write_text(f"# {MARKER} real file\n", encoding="utf-8")
    os.link(outside, target / "linked.py")

    scanner = example_module("scanner").ExampleScanner(context=context)
    report = scanner.scan(target=target, target_type=target_type)

    uris = [
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for result in report.runs[0].results
    ]
    assert [Path(uri).name for uri in uris] == ["real.py"], uris
