# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file whose path holds a backslash is scanned by detect-secrets like any other.

detect-secrets 1.5.0 scans a list of one file through ``SecretsCollection.scan_file``,
which passes the name through ``convert_local_os_path``; on POSIX that rewrites every
backslash in it to a slash. A backslash is an ordinary character in a POSIX file
name, so a single file under ``src-C:\\out\\`` is scanned at the path it was given
and gives the same findings as under ``src-plain``. Two or more files go through
detect-secrets' process pool, which scans each one at the path it was given.

The worker scans a single file at the path it was given on POSIX. Directory
names that a glob or a regular expression reads as syntax are covered here too, as
the source directory and as a directory inside it, through the scan set and through
the plugin, and through ``ash scan`` itself.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils.get_scan_set import scan_set
from tests.utils.helpers import checkout_env
from tests.utils.tool_guard import CHILD_TOOL_PROBE_STUBS

# Assembled at runtime in that module, so this file holds no key-shaped literal for
# ASH's own self-scan to report.
from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_scanner_behavior import (
    PLANTED_KEY,
)

AshConfig.model_rebuild()
PluginContext.model_rebuild()

SECRET = f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n"

#: The control first; the rest are names a checkout path or a repository can hold.
CONTROL = "src-plain"
POSIX_ONLY = pytest.mark.skipif(
    sys.platform == "win32", reason="Windows does not allow this character in a name"
)
NAMES = [
    pytest.param("src-C:\\out\\", id="backslashes-and-a-colon", marks=POSIX_ONLY),
    pytest.param("a\\b", id="backslash", marks=POSIX_ONLY),
    pytest.param("src-[x]", id="glob-class"),
    pytest.param("src-*", id="glob-star", marks=POSIX_ONLY),
    pytest.param("src-?", id="glob-question", marks=POSIX_ONLY),
    pytest.param("src-{a,b}", id="glob-braces"),
    pytest.param("src-(x)+$", id="regex-syntax"),
]

#: One file in the scan set, and two: detect-secrets takes a different path for each.
LAYOUTS = {
    "one-file": {"settings.py": SECRET},
    "two-files": {"settings.py": SECRET, "sub/app.py": SECRET},
}


# No uv probe and no tool update check, as tests/snapshot/conftest.py pins. Answering
# is_uv_available and get_tool_version alone left the dependency check's own probe,
# ``uv tool run detect-secrets --version``, which started the tool in every test here;
# no_tool_probes (tests/unit/conftest.py) answers that one too.
pytestmark = pytest.mark.usefixtures("no_tool_probes")


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _plugin_findings(source: Path, output: Path) -> list[str]:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    report = scanner.scan(target=source, target_type="source")
    return sorted(
        result.locations[0].physicalLocation.root.artifactLocation.uri
        for result in report.runs[0].results
    )


def _relative(root: Path, files) -> list[str]:
    return sorted(Path(f).relative_to(root).as_posix() for f in files)


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
@pytest.mark.parametrize("name", NAMES)
def test_a_source_directory_named_so_is_scanned_as_the_control_is(
    tmp_path, name, layout
):
    files = LAYOUTS[layout]
    control = _tree(tmp_path / "a" / CONTROL, files)
    odd = _tree(tmp_path / "b" / name, files)

    assert _relative(odd, scan_set(source=str(odd))) == _relative(
        control, scan_set(source=str(control))
    )
    expected = _plugin_findings(control, tmp_path / "a" / "out")
    assert expected, "the control found nothing"
    found = _plugin_findings(odd, tmp_path / "b" / "out")
    assert found == expected
    for uri in found:
        assert (odd / uri).is_file(), uri


@pytest.mark.parametrize("layout", sorted(LAYOUTS))
@pytest.mark.parametrize("name", NAMES)
def test_a_directory_named_so_inside_the_source_is_scanned(tmp_path, name, layout):
    files = {f"{name}/{path}": text for path, text in LAYOUTS[layout].items()}
    control_files = {
        f"{CONTROL}/{path}": text for path, text in LAYOUTS[layout].items()
    }
    control = _tree(tmp_path / "a" / "repo", control_files)
    odd = _tree(tmp_path / "b" / "repo", files)

    expected = _plugin_findings(control, tmp_path / "a" / "out")
    assert expected, "the control found nothing"
    found = _plugin_findings(odd, tmp_path / "b" / "out")
    assert len(found) == len(expected), found
    for uri in found:
        assert (odd / uri).is_file(), uri


WORKER_SETTINGS = {"plugins_used": [{"name": "AWSKeyDetector"}]}


def _run_worker(tmp_path: Path, root: Path, paths: list[str]) -> list:
    """The worker's OUTPUT, started in its own process as the scanner starts it.

    Not called in this process: the worker sets the multiprocessing start method.
    """
    request = tmp_path / "request.json"
    output = tmp_path / "output.json"
    request.write_text(
        json.dumps(
            {
                "root": str(root),
                "baseline": None,
                "settings": WORKER_SETTINGS,
                "paths": paths,
            }
        ),
        encoding="utf-8",
    )
    subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request),
            str(output),
        ],
        check=True,
        cwd=tmp_path,
        env=checkout_env(),
        timeout=300,
    )
    return json.loads(output.read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", [CONTROL, *NAMES])
def test_the_worker_keys_a_lone_file_by_the_name_it_was_handed(tmp_path, name):
    root = _tree(tmp_path / name, LAYOUTS["one-file"])
    path = str(root / "settings.py")

    written = _run_worker(tmp_path, root, [path])

    assert [key for key, secrets in written if secrets] == [path]


def test_the_worker_scans_nothing_for_an_empty_file_list(tmp_path):
    assert _run_worker(tmp_path, tmp_path, []) == []


#: The child's probes are answered first: it found the uv installed with ASH beside its
#: interpreter and ran ``uv tool run --offline detect-secrets --version``, which left
#: uv's tool-directory lock in the test's HOME.
_DRIVER = CHILD_TOOL_PROBE_STUBS + (
    "import sys\n"
    "from automated_security_helper.cli.main import app\n"
    "sys.argv = ['ash', 'scan', *sys.argv[1:]]\n"
    "app()\n"
)


def _findings_of_ash_scan(cwd: Path, source_dir: str) -> list[str]:
    """``ash scan --scanners detect-secrets`` run in a child process, as a user runs it."""
    output = cwd / f"out-{abs(hash(source_dir))}"
    env = dict(os.environ)
    env.update({"ASH_OFFLINE": "YES", "NO_COLOR": "1", "COLUMNS": "200"})
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-c",
            _DRIVER,
            "--source-dir",
            source_dir,
            "--output-dir",
            str(output),
            "--mode",
            "local",
            "--scanners",
            "detect-secrets",
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=checkout_env(env),
        cwd=cwd,
    )
    assert completed.returncode == 0, (
        completed.stdout[-2000:] + completed.stderr[-2000:]
    )
    results = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return sorted(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for run in (results.get("sarif") or {}).get("runs") or []
        for result in run.get("results") or []
    )


@POSIX_ONLY
@pytest.mark.parametrize("name", ["src-C:\\out\\", "src-[x]", "src-*"])
def test_ash_scan_of_a_source_directory_named_so_finds_what_the_control_finds(
    tmp_path, name
):
    """The measured case: one file, ``--source-dir`` given as typed, relative."""
    _tree(tmp_path / CONTROL, LAYOUTS["one-file"])
    _tree(tmp_path / name, LAYOUTS["one-file"])

    expected = _findings_of_ash_scan(tmp_path, CONTROL)
    assert expected, "the control found nothing"
    assert _findings_of_ash_scan(tmp_path, name) == expected
