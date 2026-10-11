"""Real scans: a failed semgrep run fails the scan, and the sandbox confines nbconvert.

Three behaviors, each through ``ash scan`` with the real tools:

1. semgrep exits 7 when it cannot use a rule configuration and still writes SARIF that
   holds only error notifications. The scanner's row must be ERROR and the scan must
   not exit 0, with or without a sandbox. Measured before the change: ``PASSED``, 0
   findings, exit 0 under ``--fail-on-findings``.
2. An offline scan under ``--sandbox bwrap`` reads the operator's
   ``$SEMGREP_RULES_CACHE_DIR``. Measured before the change: semgrep could not see the
   directory, exited 7, and the scan reported no findings and exited 0.
3. Under ``--sandbox bwrap`` nbconvert runs in the sandbox. The stand-in is a
   ``sitecustomize.py`` on ``$PYTHONPATH``, which nbconvert loads when it starts and
   which records the network namespace it ran in, whether a credential-shaped
   variable reached it, and whether it could read the original notebook in the
   scanned tree, when it is handed a staged copy. Measured before the change: the
   host's namespace, with the home directory and the variable visible. Measured
   before nbconvert's reads were narrowed: the original notebook readable.

The ``--sandbox off`` runs are the controls. Skipped unless ``--run-integration`` is
given, and per test when semgrep, nbconvert or bubblewrap is not installed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils.sandbox import clear_backend_cache, resolve_backend
from automated_security_helper.utils.sandbox.scope import SandboxUnavailable

pytestmark = pytest.mark.integration

RULE = """\
rules:
  - id: offline-print-call
    pattern: print(...)
    message: a print call
    languages: [python]
    severity: ERROR
"""

# A rule file semgrep rejects: no pattern.
BROKEN_RULE = """\
rules:
  - id: offline-broken
    message: no pattern
    languages: [python]
    severity: ERROR
"""

NOTEBOOK = json.dumps(
    {
        "cells": [
            {
                "cell_type": "code",
                "metadata": {},
                "execution_count": None,
                "outputs": [],
                "source": ["print('notebook')\n"],
            }
        ],
        "metadata": {"language_info": {"name": "python", "file_extension": ".py"}},
        "nbformat": 4,
        "nbformat_minor": 5,
    }
)


def _ash_executable() -> str:
    beside = Path(sys.executable).with_name("ash")
    found = str(beside) if beside.exists() else shutil.which("ash")
    if not found:
        pytest.fail("the ash entry point is not installed beside this interpreter")
    return found


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        pytest.skip(f"{tool} is not installed")


def _require_bwrap() -> None:
    clear_backend_cache()
    try:
        resolve_backend("bwrap")
    except SandboxUnavailable as e:
        pytest.skip(f"bwrap unavailable: {e}")


def _rules(tmp_path: Path, content: str) -> Path:
    rules = tmp_path / "rule-cache"
    rules.mkdir()
    (rules / "rules.yml").write_text(content)
    (rules / ".ash-rules-fetched-at").write_text("2026-10-10T00:00:00Z\n")
    return rules


def _scan(tmp_path: Path, sandbox: str, *, scanners: str, env_extra: dict, extra=()):
    source = tmp_path / "src"
    output = tmp_path / "out"
    env = {**os.environ, **env_extra}
    command = [
        _ash_executable(),
        "scan",
        "--mode",
        "local",
        "--source-dir",
        str(source),
        "--output-dir",
        str(output),
        "--scanners",
        scanners,
        "--sandbox",
        sandbox,
        "--offline",
        "--no-progress",
        *extra,
    ]
    result = subprocess.run(  # nosec B603 - fixed argv
        command,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
        cwd=tmp_path,
    )
    return result, output


def _semgrep_row(output: Path) -> dict:
    row = output / "scanners" / "semgrep" / "source" / "ASH.ScanResults.json"
    assert row.exists(), f"no semgrep result at {row}"
    return json.loads(row.read_text())


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n")
    return source


def test_a_semgrep_run_with_a_rejected_rule_file_fails_the_scan(tmp_path):
    _require("semgrep")
    _source(tmp_path)
    rules = _rules(tmp_path, BROKEN_RULE)

    result, output = _scan(
        tmp_path,
        "off",
        scanners="semgrep",
        env_extra={"SEMGREP_RULES_CACHE_DIR": str(rules)},
        extra=["--fail-on-findings"],
    )

    row = _semgrep_row(output)
    assert row.get("exit_code") not in (0, 1), f"semgrep accepted the rules: {row}"
    assert row.get("status") == "ERROR", (
        f"semgrep exited {row.get('exit_code')} and was graded {row.get('status')} "
        f"with {row.get('finding_count')} findings"
    )
    assert result.returncode != 0, (
        "the scan exited 0 although semgrep failed:\n" + result.stdout[-2000:]
    )


def test_an_offline_sandboxed_scan_reads_the_operators_rule_cache(tmp_path):
    _require("semgrep")
    _require_bwrap()
    _source(tmp_path)
    rules = _rules(tmp_path, RULE)

    result, output = _scan(
        tmp_path,
        "bwrap",
        scanners="semgrep",
        env_extra={"SEMGREP_RULES_CACHE_DIR": str(rules)},
        extra=["--fail-on-findings"],
    )

    row = _semgrep_row(output)
    assert row.get("finding_count", 0) >= 1, (
        f"the sandboxed scan found nothing with the rule cache at {rules}: {row}"
    )
    assert result.returncode == 2, result.stdout[-2000:]


def test_an_offline_unsandboxed_scan_reads_the_rule_cache(tmp_path):
    """Control: the same rules and source without a sandbox report the finding."""
    _require("semgrep")
    _source(tmp_path)
    rules = _rules(tmp_path, RULE)

    result, output = _scan(
        tmp_path,
        "off",
        scanners="semgrep",
        env_extra={"SEMGREP_RULES_CACHE_DIR": str(rules)},
        extra=["--fail-on-findings"],
    )

    assert _semgrep_row(output).get("finding_count", 0) >= 1
    assert result.returncode == 2, result.stdout[-2000:]


# Loaded by every Python process started with the probe directory on PYTHONPATH,
# including nbconvert inside the sandbox: PYTHON* variables pass the environment
# filter, and a directory on ASH's own sys.path outside $HOME is mounted read-only.
# It acts only in nbconvert, and writes where nbconvert may write.
SITECUSTOMIZE = """\
import os, sys
if os.path.basename(sys.argv[0] if sys.argv else "") == "jupyter-nbconvert":
    target = os.environ.get("PYTHONASHPROBE")
    if target:
        try:
            namespace = os.readlink("/proc/self/ns/net")
        except OSError as error:
            namespace = "unreadable:" + type(error).__name__
        token = "present" if "NOTEBOOK_PROBE_TOKEN" in os.environ else "absent"
        try:
            with open(os.environ["PYTHONASHPROBE_READ"], "rb"):
                read = "read"
        except (KeyError, OSError):
            read = "unreadable"
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(namespace + " " + token + " " + read + "\\n")
"""


def _write_probe(tmp_path: Path) -> Path:
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    (probe_dir / "sitecustomize.py").write_text(SITECUSTOMIZE, encoding="utf-8")
    return probe_dir


def _recorded(marker: Path) -> list:
    lines = marker.read_text(encoding="utf-8").split("\n") if marker.exists() else []
    return [line.split() for line in lines if line.strip()]


def _notebook_scan(tmp_path: Path, sandbox: str):
    source = _source(tmp_path)
    (source / "analysis.ipynb").write_text(NOTEBOOK)
    probe_dir = _write_probe(tmp_path)
    # The jupyter converter's results directory, which nbconvert may write.
    marker = tmp_path / "out" / "converted" / "jupyter" / "namespace.txt"
    rules = _rules(tmp_path, RULE)
    _result, output = _scan(
        tmp_path,
        sandbox,
        scanners="semgrep",
        env_extra={
            "SEMGREP_RULES_CACHE_DIR": str(rules),
            "PYTHONPATH": str(probe_dir),
            "PYTHONASHPROBE": str(marker),
            "PYTHONASHPROBE_READ": str(source / "analysis.ipynb"),
            "NOTEBOOK_PROBE_TOKEN": "token-value",
        },
        extra=[
            "--fail-on-findings",
            "false",
            "--config-overrides",
            f"sandbox.extra_read_paths=[{rules}]",
        ],
    )
    converted = sorted((output / "converted").rglob("*-converted.*"))
    return converted, _recorded(marker)


def test_nbconvert_runs_inside_the_sandbox(tmp_path):
    _require("semgrep")
    _require("jupyter-nbconvert")
    _require_bwrap()
    host = os.readlink("/proc/self/ns/net")

    converted, recorded = _notebook_scan(tmp_path, "bwrap")

    assert recorded, "the probe recorded nothing, so nothing was measured"
    assert all(namespace != host for namespace, _token, _read in recorded), (
        f"nbconvert ran in the host's network namespace {host} under --sandbox bwrap"
    )
    assert all(token == "absent" for _namespace, token, _read in recorded), (
        f"a credential-shaped variable reached nbconvert: {recorded}"
    )
    assert all(read == "unreadable" for _namespace, _token, read in recorded), (
        f"nbconvert could read the scanned tree beside its staged copy: {recorded}"
    )
    assert converted, "the notebook was not converted under the sandbox"


def test_without_a_sandbox_nbconvert_runs_on_the_host(tmp_path):
    """Control: the probe works, and without a sandbox it reports the host."""
    _require("semgrep")
    _require("jupyter-nbconvert")
    host = os.readlink("/proc/self/ns/net")

    converted, recorded = _notebook_scan(tmp_path, "off")

    assert [host, "present", "read"] in recorded, (
        f"the probe did not record the host: {recorded}"
    )
    assert converted


@pytest.mark.parametrize("sandbox", ["bwrap", "off"])
def test_the_converter_runs_nbconvert_in_its_own_namespace(
    tmp_path, monkeypatch, sandbox
):
    """The jupyter converter itself, with the real backend: where nbconvert ran.

    The same probe as the scans above, without the rest of a scan around it. ``off``
    is the control: the host's namespace and the variable.
    """
    _require("jupyter-nbconvert")
    if sandbox != "off":
        _require_bwrap()
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
    from automated_security_helper.plugin_modules.ash_builtin.converters.jupyter_converter import (
        JupyterConverter,
    )

    AshConfig.model_rebuild()
    probe_dir = _write_probe(tmp_path)
    source = _source(tmp_path)
    (source / "analysis.ipynb").write_text(NOTEBOOK)
    output = tmp_path / "out"
    results_dir = output / "converted" / "jupyter"
    results_dir.mkdir(parents=True)
    marker = results_dir / "namespace.txt"
    monkeypatch.syspath_prepend(str(probe_dir))
    monkeypatch.setenv("PYTHONPATH", str(probe_dir))
    monkeypatch.setenv("PYTHONASHPROBE", str(marker))
    monkeypatch.setenv("PYTHONASHPROBE_READ", str(source / "analysis.ipynb"))
    monkeypatch.setenv("NOTEBOOK_PROBE_TOKEN", "token-value")
    clear_backend_cache()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(project_name="nb", sandbox=SandboxConfig(mode=sandbox)),
    )

    converted = JupyterConverter(context=context).convert()

    assert converted, "the notebook was not converted"
    recorded = _recorded(marker)
    assert recorded, "the probe recorded nothing, so nothing was measured"
    host = os.readlink("/proc/self/ns/net")
    if sandbox == "off":
        assert [host, "present", "read"] in recorded, recorded
    else:
        assert all(namespace != host for namespace, _token, _read in recorded), (
            f"nbconvert ran in the host's network namespace {host}: {recorded}"
        )
        assert all(token == "absent" for _namespace, token, _read in recorded), (
            f"a credential-shaped variable reached nbconvert: {recorded}"
        )
        assert all(read == "unreadable" for _namespace, _token, read in recorded), (
            f"nbconvert could read the scanned tree beside its staged copy: {recorded}"
        )


def test_bwrap_hides_a_tree_inside_a_mounted_directory_from_a_staged_tool(
    tmp_path, monkeypatch
):
    """A tree checked out inside a directory tools are read from, as under /opt.

    A tool handed a staged copy (nbconvert) may not read the tree even though the
    directory around it is mounted, and still writes its results directory inside
    the tree. The file beside the tree is the control: the mount is there.
    """
    _require_bwrap()
    from automated_security_helper.utils.sandbox import SandboxRequirements
    from automated_security_helper.utils.sandbox.policy import build_scanner_policy

    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    opt = tmp_path / "opt"
    source = opt / "repo"
    output = source / ".ash" / "ash_output"
    results = output / "converted" / "jupyter"
    output.mkdir(parents=True)
    (source / "analysis.ipynb").write_text(NOTEBOOK)
    (opt / "beside.txt").write_text("beside\n")
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "analysis.ipynb").write_text(NOTEBOOK)
    clear_backend_cache()
    backend = resolve_backend("bwrap")
    policy = build_scanner_policy(
        "jupyter",
        SandboxRequirements(staged_input_only=True),
        argv0="/bin/sh",
        source_dir=source,
        output_dir=output,
        results_dir=results,
        scan_target=staging,
        cwd=staging,
        offline=True,
        network_scanners=None,
        extra_read_paths=[str(opt)],
    )

    def run(script: str) -> subprocess.CompletedProcess:
        plan = backend.plan(["/bin/sh", "-c", script], dict(os.environ), policy)
        try:
            return subprocess.run(
                plan.argv, env=plan.env, capture_output=True, text=True, timeout=60
            )
        finally:
            plan.run_cleanup()

    assert run(f"cat {opt / 'beside.txt'}").stdout == "beside\n"
    assert run(f"cat {staging / 'analysis.ipynb'}").returncode == 0
    tree = run(f"cat {source / 'analysis.ipynb'}")
    assert tree.returncode != 0 and tree.stdout == "", (
        f"the staged tool read the tree: {tree.stdout[:200]}"
    )
    wrote = run(f"echo converted > {results / 'out.py'}")
    assert wrote.returncode == 0, wrote.stderr
    assert (results / "out.py").read_text() == "converted\n"
