# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whole ``ash scan`` runs over one tree, with and without honoring its ignore files.

The scanned repository's ``.gitignore`` and ``.ignore`` files decide which of its files
are in ASH's scan set, the list detect-secrets, cfn-nag, cdk-nag, npm-audit and the
converters read. Two things are required of that:

- An operator can tell ASH not to honor them, with a CLI flag or with operator-tier
  config (a config file outside the scanned tree, ``ASH_CONFIG`` outside it, or
  ``--config-overrides``). A config file inside the scanned tree cannot: its value is
  ignored with a warning that names the key and the file, the way the in-tree
  ``ash_plugin_modules`` entries and sandbox grants are.
- Every scan records, in ``ash_aggregated_results.json`` and in both summaries, whether
  the ignore files were honored and how many files they removed from the scan set,
  per ignore file and in total, whatever the switch says.

Each run happens in a child process with no cloud credentials and an endpoint that
refuses connections, over a tree built here, and the tests inspect what it wrote.

Names this module assumes. The implementer may rename them; each is spelled only in
the constants below:

- ``--no-honor-ignore-files`` / ``--honor-ignore-files``: the CLI flag pair.
- ``honor_ignore_files``: the top-level config key, default ``true``.
- ``metadata.ignore_file_exclusions`` in the aggregated results, an object with
  ``honored`` (bool), ``excluded_file_count`` (int: files the repository's ignore files
  removed; ASH's own exclusions such as ``.git`` are not counted) and
  ``by_ignore_file`` (ignore file, relative to the scan root, to the number of files it
  removed; zeros included).

The tree::

    .gitignore            build/  *.log  !keep.log
    .ignore               notes.txt
    .git/HEAD             ASH's own exclusion, never scanned
    app.py
    settings.py           holds a credential, never ignored (the control)
    debug.log             holds a credential, excluded by .gitignore
    keep.log              re-included by the negation in .gitignore
    notes.txt             excluded by .ignore
    build/out1.txt        excluded by .gitignore; its directory is never walked
    build/out2.txt        excluded by .gitignore; its directory is never walked
    vendor/.gitignore     lib/
    vendor/lib/dep.py     excluded by vendor/.gitignore
    vendor/lib/util.py    excluded by vendor/.gitignore
    sub/.ignore           *.tmp  !keep.tmp
    sub/scratch.tmp       excluded by sub/.ignore
    sub/keep.tmp          re-included by the negation in sub/.ignore
    sub/deep/.gitignore   !trace.log
    sub/deep/trace.log    *.log at the root, re-included by the deeper negation

So with the ignore files honored they remove 7 files: 3 for ``.gitignore`` (two of them
under the pruned ``build/``), 1 for ``.ignore``, 2 for ``vendor/.gitignore``, 1 for
``sub/.ignore`` and 0 for ``sub/deep/.gitignore``. The total, 7, appears nowhere else
in the tree, so a summary line carrying it is about this.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List

import pytest

# Proposed names; see the module docstring.
SWITCH_OFF_FLAG = "--no-honor-ignore-files"
CONFIG_KEY = "honor_ignore_files"
RECORD_KEY = "ignore_file_exclusions"
RECORD_HONORED = "honored"
RECORD_TOTAL = "excluded_file_count"
RECORD_BY_FILE = "by_ignore_file"

# Built at run time so the test source holds no credential-shaped literal.
CREDENTIAL = "AKIA" + "IOSFODNN7" + "EXAMPLE"

TREE: Dict[str, str] = {
    ".gitignore": "build/\n*.log\n!keep.log\n",
    ".ignore": "notes.txt\n",
    ".git/HEAD": "ref: refs/heads/main\n",
    "app.py": "print('hello')\n",
    "settings.py": f'value = "{CREDENTIAL}"\n',
    "debug.log": f'value = "{CREDENTIAL}"\n',
    "keep.log": "kept by the negation\n",
    "notes.txt": "local notes\n",
    "build/out1.txt": "build output\n",
    "build/out2.txt": "build output\n",
    "vendor/.gitignore": "lib/\n",
    "vendor/lib/dep.py": "y = 2\n",
    "vendor/lib/util.py": "z = 3\n",
    "sub/.ignore": "*.tmp\n!keep.tmp\n",
    "sub/scratch.tmp": "scratch\n",
    "sub/keep.tmp": "kept by the negation\n",
    "sub/deep/.gitignore": "!trace.log\n",
    "sub/deep/trace.log": "kept by the deeper negation\n",
}

#: What the ignore files remove when they are honored, and which file removes each.
EXCLUDED_BY_IGNORE_FILES = {
    "debug.log": ".gitignore",
    "build/out1.txt": ".gitignore",
    "build/out2.txt": ".gitignore",
    "notes.txt": ".ignore",
    "vendor/lib/dep.py": "vendor/.gitignore",
    "vendor/lib/util.py": "vendor/.gitignore",
    "sub/scratch.tmp": "sub/.ignore",
}
EXPECTED_COUNTS = {
    ".gitignore": 3,
    ".ignore": 1,
    "vendor/.gitignore": 2,
    "sub/.ignore": 1,
    "sub/deep/.gitignore": 0,
}
EXPECTED_TOTAL = 7
KEPT_BY_NEGATION = ("keep.log", "sub/keep.tmp", "sub/deep/trace.log")
ASH_OWN_EXCLUSION = ".git/HEAD"

# Run in the child: ASH's own CLI, nothing replaced.
DRIVER = textwrap.dedent(
    """
    import sys

    from automated_security_helper.cli.main import app

    sys.argv = ["ash", *sys.argv[1:]]
    app()
    """
)

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def build_tree(root: Path, extra: Dict[str, str] | None = None) -> Path:
    for relative, text in {**TREE, **(extra or {})}.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def child_env() -> Dict[str, str]:
    """The caller's environment without cloud credentials or ASH settings.

    Every AWS_* variable is dropped and the SDK is pointed at files that hold nothing
    and an endpoint that refuses connections, so a reporter that tries to reach AWS
    fails locally. ASH_* variables are dropped so an operator's ASH_CONFIG on the
    host cannot decide the outcome.
    """
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "ASH_"))
    }
    env.update(
        {
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
            "AWS_REGION": "us-east-1",
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "200",
        }
    )
    return env


def run_ash(cwd: Path, *args: str):
    # A fixed argv: this interpreter and the driver above, no shell. `-I` keeps the
    # child's imports to the interpreter's own site-packages, which is the ASH under
    # test.
    return subprocess.run(
        [sys.executable, "-I", "-c", DRIVER, *args],
        capture_output=True,
        text=True,
        timeout=600,
        env=child_env(),
        cwd=cwd,
    )


@dataclass
class ScanRun:
    tree: Path
    output: Path
    stdout: str

    @property
    def project_output(self) -> Path:
        return self.output

    @property
    def scan_set(self) -> set[str]:
        listing = self.project_output / "ash-scan-set-files-list.txt"
        names = set()
        for line in listing.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                names.add(Path(line).relative_to(self.tree).as_posix())
        return names

    @property
    def results(self) -> dict:
        return json.loads(
            (self.project_output / "ash_aggregated_results.json").read_text(
                encoding="utf-8"
            )
        )

    @property
    def log(self) -> str:
        return (self.project_output / "ash.log").read_text(encoding="utf-8")

    def summary(self, extension: str) -> str:
        return (self.project_output / "reports" / f"ash.summary.{extension}").read_text(
            encoding="utf-8"
        )


@dataclass
class WorkspaceRun(ScanRun):
    project: str = "proj"

    @property
    def project_output(self) -> Path:
        return self.output / "projects" / self.project


def scan(
    base: Path,
    name: str,
    *extra_args: str,
    tree_extra: Dict[str, str] | None = None,
    with_secrets_scan: bool = False,
) -> ScanRun:
    work = base / name
    tree = build_tree(work / "tree", tree_extra)
    output = work / "out"
    phases = (
        ["convert", "scan", "report"] if with_secrets_scan else ["convert", "report"]
    )
    args = [
        "scan",
        "--source-dir",
        str(tree),
        "--output-dir",
        str(output),
        "--mode",
        "local",
        "--no-progress",
        "--no-fail-on-findings",
    ]
    for phase in phases:
        args += ["--phases", phase]
    if with_secrets_scan:
        args += ["--scanners", "detect-secrets"]
    completed = run_ash(work, *args, *extra_args)
    # A precondition of every test below rather than a test of its own: a scan that
    # did not finish leaves nothing to inspect.
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    return ScanRun(tree=tree, output=output, stdout=completed.stdout)


def _operator_config(base: Path, honor: bool) -> Path:
    path = base / "operator" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"project_name: operator\n{CONFIG_KEY}: {'true' if honor else 'false'}\n",
        encoding="utf-8",
    )
    return path


def _workspace_scan(base: Path, *extra_args: str) -> WorkspaceRun:
    work = base / "workspace"
    tree = build_tree(work / "proj")
    (work / "w.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    output = work / "out"
    completed = run_ash(
        work,
        "scan",
        "--workspace",
        str(work / "w.code-workspace"),
        "--output-dir",
        str(output),
        "--phases",
        "convert",
        "--phases",
        "report",
        "--no-progress",
        "--no-fail-on-findings",
        *extra_args,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    return WorkspaceRun(tree=tree, output=output, stdout=completed.stdout)


VARIANTS: Dict[str, Callable[[Path], ScanRun]] = {
    # The ignore files honored, as today. detect-secrets runs so a finding shows
    # which files a scanner actually read.
    "default": lambda base: scan(base, "default", with_secrets_scan=True),
    "flag": lambda base: scan(base, "flag", SWITCH_OFF_FLAG, with_secrets_scan=True),
    "override": lambda base: scan(
        base, "override", "--config-overrides", f"{CONFIG_KEY}=false"
    ),
    "operator_config": lambda base: scan(
        base, "operator_config", "--config", str(_operator_config(base, honor=False))
    ),
    # The repository's own config asks for it; it must not get it.
    "in_tree_config": lambda base: scan(
        base,
        "in_tree_config",
        tree_extra={".ash/.ash.yaml": f"project_name: scanned\n{CONFIG_KEY}: false\n"},
    ),
    # The repository's config asks to keep honoring them; the operator's flag wins.
    "in_tree_config_with_flag": lambda base: scan(
        base,
        "in_tree_config_with_flag",
        SWITCH_OFF_FLAG,
        tree_extra={".ash/.ash.yaml": f"project_name: scanned\n{CONFIG_KEY}: true\n"},
    ),
    "workspace_flag": lambda base: _workspace_scan(base, SWITCH_OFF_FLAG),
}


@pytest.fixture(scope="module")
def scans(tmp_path_factory) -> Callable[[str], ScanRun]:
    base = tmp_path_factory.mktemp("ignore-switch")
    done: Dict[str, ScanRun] = {}

    def get(name: str) -> ScanRun:
        if name not in done:
            done[name] = VARIANTS[name](base)
        return done[name]

    yield get
    shutil.rmtree(base, ignore_errors=True)


def record_of(run: ScanRun) -> dict:
    metadata = run.results.get("metadata", {})
    record = metadata.get(RECORD_KEY)
    assert isinstance(record, dict), (
        f"ash_aggregated_results.json has no metadata.{RECORD_KEY} record of what the "
        f"ignore files excluded; metadata keys: {sorted(metadata)}"
    )
    return record


def counts_by_ignore_file(record: dict) -> Dict[str, int]:
    """The per-file counts, keyed relative to the scan root whatever prefix is used."""
    by_file = record.get(RECORD_BY_FILE)
    assert isinstance(by_file, dict), f"the record has no {RECORD_BY_FILE}: {record}"
    return {
        str(key).replace("${SOURCE_DIR}/", "", 1).lstrip("/"): value
        for key, value in by_file.items()
        if Path(str(key)).name in (".gitignore", ".ignore")
    }


def ignore_lines(text: str) -> List[str]:
    """Summary lines about the ignore files, with terminal styling removed."""
    return [
        line
        for line in _ANSI.sub("", text).splitlines()
        if re.search(r"(?i)\.gitignore|ignore files?", line)
    ]


def finding_paths(run: ScanRun) -> set[str]:
    paths = set()
    for sarif_run in run.results.get("sarif", {}).get("runs", []):
        for result in sarif_run.get("results", []) or []:
            for location in result.get("locations", []) or []:
                uri = (
                    location.get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri")
                )
                if uri:
                    paths.add(uri)
    return paths


def warnings_in(log: str) -> List[str]:
    return [line for line in log.splitlines() if "\tWARNING\t" in line]


# --------------------------------------------------------------------------- default


class TestIgnoreFilesHonoredByDefault:
    """Today's exclusion still happens without the switch; these are the controls."""

    def test_every_file_an_ignore_file_matches_is_left_out(self, scans):
        found = scans("default").scan_set
        assert not found & set(EXCLUDED_BY_IGNORE_FILES), sorted(found)
        assert "app.py" in found and "settings.py" in found, sorted(found)

    def test_negated_patterns_keep_their_files(self, scans):
        found = scans("default").scan_set
        for name in KEPT_BY_NEGATION:
            assert name in found, (
                f"{name} is negated and must stay; got {sorted(found)}"
            )

    def test_a_credential_in_an_ignored_file_is_not_reported(self, scans):
        paths = finding_paths(scans("default"))
        assert "settings.py" in paths, (
            f"the control credential was not found, so detect-secrets did not run: "
            f"{sorted(paths)}"
        )
        assert "debug.log" not in paths, sorted(paths)


class TestTheRecordOfWhatIgnoreFilesExcluded:
    def test_the_results_say_the_ignore_files_were_honored(self, scans):
        record = record_of(scans("default"))
        assert record.get(RECORD_HONORED) is True, record

    def test_each_ignore_file_has_its_own_count(self, scans):
        """Nested files, .ignore files and a file that removed nothing, each named.

        The root .gitignore's count includes the two files under build/, which the
        walk never descends into. A count of 1 there is the number the log carries
        today, and it understates what that file removed.
        """
        counts = counts_by_ignore_file(record_of(scans("default")))
        assert counts == EXPECTED_COUNTS, counts

    def test_the_total_is_the_number_of_files_actually_missing(self, scans):
        run = scans("default")
        record = record_of(run)
        missing_by_ignore_files = set(TREE) - run.scan_set - {ASH_OWN_EXCLUSION}
        assert (
            record.get(RECORD_TOTAL) == len(missing_by_ignore_files) == EXPECTED_TOTAL
        ), (
            record,
            sorted(missing_by_ignore_files),
        )
        assert sum(counts_by_ignore_file(record).values()) == EXPECTED_TOTAL, record

    @pytest.mark.parametrize("extension", ["txt", "md"])
    def test_the_summary_says_how_many_files_ignore_files_excluded(
        self, scans, extension
    ):
        lines = ignore_lines(scans("default").summary(extension))
        assert any(re.search(rf"\b{EXPECTED_TOTAL}\b", line) for line in lines), (
            f"ash.summary.{extension} does not say that the ignore files excluded "
            f"{EXPECTED_TOTAL} files; lines about ignore files: {lines}"
        )

    @pytest.mark.parametrize("report_format", ["text", "markdown"])
    def test_a_re_rendered_summary_keeps_the_record(self, scans, report_format):
        """``ash report`` renders from the stored results, not from the scan's memory."""
        run = scans("default")
        completed = run_ash(
            run.output.parent,
            "report",
            "--format",
            report_format,
            "--output-dir",
            str(run.output),
        )
        assert completed.returncode == 0, (
            completed.stdout[-4000:] + completed.stderr[-4000:]
        )
        lines = ignore_lines(completed.stdout)
        assert any(re.search(rf"\b{EXPECTED_TOTAL}\b", line) for line in lines), (
            f"`ash report --format {report_format}` lost the ignore-file record; lines "
            f"about ignore files: {lines}"
        )


# --------------------------------------------------------------------------- the switch


OPERATOR_VARIANTS = ["flag", "override", "operator_config", "in_tree_config_with_flag"]


class TestTheOperatorSwitch:
    @pytest.mark.parametrize("variant", OPERATOR_VARIANTS)
    def test_files_the_ignore_files_match_are_scanned(self, scans, variant):
        found = scans(variant).scan_set
        missing = sorted(set(EXCLUDED_BY_IGNORE_FILES) - found)
        assert missing == [], (
            f"{variant}: ignore files were still honored; not in the scan set: {missing}"
        )

    @pytest.mark.parametrize("variant", OPERATOR_VARIANTS)
    def test_the_scan_set_is_every_file_but_ash_own_exclusions(self, scans, variant):
        """Every file on disk, ignore files and negated files included, but not .git.

        Not honoring the repository's ignore files is not the same as dropping ASH's
        own exclusions, so .git/HEAD stays out.
        """
        run = scans(variant)
        on_disk = {
            path.relative_to(run.tree).as_posix()
            for path in run.tree.rglob("*")
            if path.is_file()
        }
        expected = on_disk - {ASH_OWN_EXCLUSION}
        found = run.scan_set
        assert found == expected, (
            f"{variant}: missing {sorted(expected - found)}, "
            f"unexpected {sorted(found - expected)}"
        )

    def test_a_credential_in_an_ignored_file_is_reported(self, scans):
        paths = finding_paths(scans("flag"))
        assert "settings.py" in paths, (
            f"the control credential was not found, so detect-secrets did not run: "
            f"{sorted(paths)}"
        )
        assert "debug.log" in paths, (
            f"detect-secrets did not read the ignored file under {SWITCH_OFF_FLAG}; "
            f"findings: {sorted(paths)}"
        )

    @pytest.mark.parametrize("variant", OPERATOR_VARIANTS)
    def test_the_results_say_the_ignore_files_were_not_honored(self, scans, variant):
        record = record_of(scans(variant))
        assert record.get(RECORD_HONORED) is False, record
        assert record.get(RECORD_TOTAL) == 0, record

    @pytest.mark.parametrize("extension", ["txt", "md"])
    def test_the_summary_says_the_ignore_files_were_not_honored(self, scans, extension):
        lines = ignore_lines(scans("flag").summary(extension))
        assert any(
            re.search(r"(?i)\bnot\b.*\b(honored|applied|used)\b", line)
            for line in lines
        ), (
            f"ash.summary.{extension} does not say the ignore files were not honored; "
            f"lines about ignore files: {lines}"
        )

    def test_workspace_mode_passes_the_switch_to_each_project(self, scans):
        run = scans("workspace_flag")
        missing = sorted(set(EXCLUDED_BY_IGNORE_FILES) - run.scan_set)
        assert missing == [], f"workspace project still honored ignore files: {missing}"
        assert record_of(run).get(RECORD_HONORED) is False


# --------------------------------------------------------------------------- trust tiers


class TestARepositoryConfigCannotSetTheSwitch:
    """Matches the trust tiers on main: ignored, with one warning naming key and file."""

    def test_the_ignore_files_are_still_honored(self, scans):
        run = scans("in_tree_config")
        now_scanned = sorted(run.scan_set & set(EXCLUDED_BY_IGNORE_FILES))
        assert now_scanned == [], (
            f"the repository's own config turned the ignore files off: {now_scanned}"
        )
        record = record_of(run)
        assert record.get(RECORD_HONORED) is True, record
        assert record.get(RECORD_TOTAL) == EXPECTED_TOTAL, record

    def test_a_warning_names_the_key_and_the_file(self, scans):
        warnings = warnings_in(scans("in_tree_config").log)
        assert any(CONFIG_KEY in line and ".ash.yaml" in line for line in warnings), (
            f"no warning says the in-tree {CONFIG_KEY} was ignored; warnings: {warnings}"
        )
