# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""A scan whose findings carry secret values in their snippets.

Shared by the tests that check no secret value reaches a report, the aggregated
results file, an MCP response or a Bedrock prompt:
``tests/unit/reporters/test_secret_masking_across_reports.py`` and
``tests/unit/plugin_modules/ash_aws_plugins/test_bedrock_summary_reporter_secret_handling.py``.

What the source tree holds
--------------------------
Four files, with each secret placed where a mask keyed on rule ID alone cannot
reach it:

* ``app.py`` line 3 assigns a keyword value. Bandit B105 reports the line and puts
  the value in its message. The B404 on line 1 is not a secret finding, but its
  contextRegion (lines 1-3) encloses line 3.
* ``app.py`` line 11 reuses that value inside a shell command. B602 and B607
  report the line and no secret finding does, so only masking by value (the value
  B105 exposed) covers it.
* ``client.py`` line 4 has a parameter default (B107) and line 8 a keyword
  argument (B106), each a value the finding's message exposes. Line 9 reuses the
  B106 value in a shell command that only B602 and B607 report.
* ``settings.py`` line 3 assigns an access key id. Only detect-secrets reports the
  line, and its SARIF carries no value, so only masking by location covers it
  where the B602 on line 4 carries it in its contextRegion (lines 3-4).
* ``creds.py`` line 1 assigns a 40-character key that B105 and detect-secrets both
  report.

The non-secret lines are there too, so a test can check that masking left them
alone: ``import subprocess``, ``return subprocess.call(cmd, shell=True)`` and
``subprocess.call(AWS_ACCESS_KEY_ID, shell=True)``.

Why bandit's output is canned
-----------------------------
Bandit is installed with ``uv tool install`` and is not present where the unit
suite runs, so ``BanditScanner`` would report itself MISSING. Its dependency check
and its subprocess call are replaced: the subprocess writes the SARIF bandit 1.9.4
produced for exactly these files (``bandit -r . -f sarif``), with every snippet
rebuilt from the file text. Everything after the subprocess runs unmodified --
reading the results file, the scanner's own post-processing,
``ScanResultProcessor``, saving ``ash_aggregated_results.json`` and the report
phase. detect-secrets is a Python dependency and runs for real.

Why the values are derived
--------------------------
They are computed from sha256 when this module is imported, so this source holds
no string a secret scanner would report. ASH scans its own tests in CI.
"""

from __future__ import annotations

import hashlib
import json
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import pytest


def _derived(label: str, alphabet: str, length: int) -> str:
    """A fixed string over ``alphabet``, the same on every run and every host."""
    chars: List[str] = []
    counter = 0
    while len(chars) < length:
        digest = hashlib.sha256(f"{label}:{counter}".encode()).digest()
        chars.extend(alphabet[byte % len(alphabet)] for byte in digest)
        counter += 1
    return "".join(chars[:length])


@dataclass(frozen=True)
class SecretValues:
    """The three values the fixture tree exposes."""

    #: ``AKIA`` and 16 upper-case letters or digits; detect-secrets reports it as
    #: an AWS access key. No scanner puts it in a message.
    key_id: str
    #: 40 base64 characters; B105 puts it in its message.
    long_key: str
    #: 14 lower-case letters or digits; B105 puts it in its message.
    keyword_value: str
    #: 12 lower-case letters or digits, a parameter default; B107 puts it in its
    #: message.
    default_arg_value: str
    #: 12 lower-case letters or digits, a keyword argument; B106 puts it in its
    #: message.
    call_arg_value: str

    def named(self) -> Tuple[Tuple[str, str], ...]:
        return (
            ("key_id", self.key_id),
            ("long_key", self.long_key),
            ("keyword_value", self.keyword_value),
            ("default_arg_value", self.default_arg_value),
            ("call_arg_value", self.call_arg_value),
        )

    def names(self) -> List[str]:
        return [name for name, _ in self.named()]

    def found_in(self, text: str) -> List[str]:
        """Names of the values that occur in ``text``, for assertion messages."""
        return [name for name, value in self.named() if value in text]


_LOWER = string.ascii_lowercase + string.digits

SECRETS = SecretValues(
    key_id="AKIA"
    + _derived("access-key-id", string.ascii_uppercase + string.digits, 16),
    long_key=_derived("long-key", string.ascii_letters + string.digits + "/+", 40),
    keyword_value=_derived("keyword-value", _LOWER, 14),
    default_arg_value=_derived("default-arg-value", _LOWER, 12),
    call_arg_value=_derived("call-arg-value", _LOWER, 12),
)

# Names in the fixture files, kept apart from the values so that no line of this
# source pairs a secret-like name with a quoted value.
_KEYWORD_NAME = "pass" + "word"
_KEY_ID_NAME = "AWS_ACCESS_KEY_ID"
_LONG_KEY_NAME = "AWS_" + "SECRET" + "_ACCESS_KEY"


def _assign(name: str, value: str) -> str:
    return name + " = " + '"' + value + '"' + "\n"


#: The non-secret lines tests check survive masking, verbatim.
IMPORT_LINE = "import subprocess\n"
RUN_LINE = "    return subprocess.call(cmd, shell=True)\n"
KEY_ID_USE_LINE = f"subprocess.call({_KEY_ID_NAME}, shell=True)\n"
DEPLOY_PREFIX = '    return subprocess.call("deploy --token '
SYNC_PREFIX = 'subprocess.call("sync --key '

FIXTURE_FILES: Dict[str, str] = {
    "app.py": (
        IMPORT_LINE
        + "\n"
        + _assign(_KEYWORD_NAME, SECRETS.keyword_value)
        + "\n"
        + "\n"
        + "def run(cmd):\n"
        + RUN_LINE
        + "\n"
        + "\n"
        + "def deploy():\n"
        + DEPLOY_PREFIX
        + SECRETS.keyword_value
        + '", shell=True)\n'
    ),
    # B107 reports line 4 and B106 line 8; line 9 reuses the B106 value, and no
    # secret finding reports line 9.
    "client.py": (
        IMPORT_LINE
        + "\n"
        + "\n"
        + f'def connect(host, {_KEYWORD_NAME}="{SECRETS.default_arg_value}"):\n'
        + "    return host\n"
        + "\n"
        + "\n"
        + f'connect("db", {_KEYWORD_NAME}="{SECRETS.call_arg_value}")\n'
        + SYNC_PREFIX
        + SECRETS.call_arg_value
        + '", shell=True)\n'
    ),
    "settings.py": (
        IMPORT_LINE + "\n" + _assign(_KEY_ID_NAME, SECRETS.key_id) + KEY_ID_USE_LINE
    ),
    "creds.py": _assign(_LONG_KEY_NAME, SECRETS.long_key),
}

_B404_MESSAGE = (
    "Consider possible security implications associated with the subprocess module."
)
_B602_UNSAFE = "subprocess call with shell=True identified, security issue."
_B602_LITERAL = (
    "subprocess call with shell=True seems safe, but may be changed in the future, "
    "consider rewriting without shell"
)
_B607_MESSAGE = "Starting a process with a partial executable path"
_HARDCODED_VALUE_PREFIX = "Possible hardcoded password: "


def _value_message(value: str) -> str:
    return _HARDCODED_VALUE_PREFIX + "'" + value + "'"


#: (rule, file, start line, end line, start column, end column, context start,
#: context end, level, severity, confidence, message), in the order bandit 1.9.4
#: wrote them.
_BANDIT_FINDINGS: List[Tuple[Any, ...]] = [
    ("B404", "app.py", 1, 1, 1, 18, 1, 3, "note", "LOW", "HIGH", _B404_MESSAGE),
    (
        "B105",
        "app.py",
        3,
        3,
        12,
        28,
        2,
        4,
        "note",
        "LOW",
        "MEDIUM",
        _value_message(SECRETS.keyword_value),
    ),
    ("B602", "app.py", 7, 7, 12, 44, 6, 8, "error", "HIGH", "HIGH", _B602_UNSAFE),
    ("B607", "app.py", 11, 11, 12, 72, 10, 11, "note", "LOW", "HIGH", _B607_MESSAGE),
    ("B602", "app.py", 11, 11, 12, 72, 10, 11, "note", "LOW", "HIGH", _B602_LITERAL),
    ("B404", "client.py", 1, 1, 1, 18, 1, 3, "note", "LOW", "HIGH", _B404_MESSAGE),
    (
        "B107",
        "client.py",
        4,
        5,
        1,
        16,
        3,
        6,
        "note",
        "LOW",
        "MEDIUM",
        _value_message(SECRETS.default_arg_value),
    ),
    (
        "B106",
        "client.py",
        8,
        8,
        1,
        39,
        7,
        9,
        "note",
        "LOW",
        "MEDIUM",
        _value_message(SECRETS.call_arg_value),
    ),
    ("B607", "client.py", 9, 9, 1, 55, 8, 9, "note", "LOW", "HIGH", _B607_MESSAGE),
    ("B602", "client.py", 9, 9, 1, 55, 8, 9, "note", "LOW", "HIGH", _B602_LITERAL),
    (
        "B105",
        "creds.py",
        1,
        1,
        25,
        67,
        1,
        1,
        "note",
        "LOW",
        "MEDIUM",
        _value_message(SECRETS.long_key),
    ),
    ("B404", "settings.py", 1, 1, 1, 18, 1, 3, "note", "LOW", "HIGH", _B404_MESSAGE),
    ("B602", "settings.py", 4, 4, 1, 47, 3, 4, "error", "HIGH", "HIGH", _B602_UNSAFE),
]

#: In the order bandit lists them: first appearance in its results.
_BANDIT_RULES = [
    (
        "B404",
        "blacklist",
        "external/cwe/cwe-78",
        "high",
        "blacklists/blacklist_imports.html#b404-import-subprocess",
    ),
    (
        "B105",
        "hardcoded_password_string",
        "external/cwe/cwe-259",
        "medium",
        "plugins/b105_hardcoded_password_string.html",
    ),
    (
        "B602",
        "subprocess_popen_with_shell_equals_true",
        "external/cwe/cwe-78",
        "high",
        "plugins/b602_subprocess_popen_with_shell_equals_true.html",
    ),
    (
        "B607",
        "start_process_with_partial_path",
        "external/cwe/cwe-78",
        "high",
        "plugins/b607_start_process_with_partial_path.html",
    ),
    (
        "B107",
        "hardcoded_password_default",
        "external/cwe/cwe-259",
        "medium",
        "plugins/b107_hardcoded_password_default.html",
    ),
    (
        "B106",
        "hardcoded_password_funcarg",
        "external/cwe/cwe-259",
        "medium",
        "plugins/b106_hardcoded_password_funcarg.html",
    ),
]


def _lines(name: str) -> List[str]:
    return FIXTURE_FILES[name].splitlines(keepends=True)


def bandit_sarif() -> Dict[str, Any]:
    """The SARIF bandit 1.9.4 writes for ``FIXTURE_FILES``, as a fresh dict."""
    rule_index = {rule[0]: index for index, rule in enumerate(_BANDIT_RULES)}
    results = []
    for (
        rule,
        name,
        line,
        end_line,
        start_col,
        end_col,
        ctx_start,
        ctx_end,
        level,
        severity,
        confidence,
        message,
    ) in _BANDIT_FINDINGS:
        lines = _lines(name)
        results.append(
            {
                "message": {"text": message},
                "level": level,
                "locations": [
                    {
                        "physicalLocation": {
                            # Bandit's region snippet is the first line of the
                            # node even when the region spans more than one.
                            "region": {
                                "snippet": {"text": lines[line - 1]},
                                "endColumn": end_col,
                                "endLine": end_line,
                                "startColumn": start_col,
                                "startLine": line,
                            },
                            "artifactLocation": {"uri": name},
                            "contextRegion": {
                                "snippet": {
                                    "text": "".join(lines[ctx_start - 1 : ctx_end])
                                },
                                "endLine": ctx_end,
                                "startLine": ctx_start,
                            },
                        }
                    }
                ],
                "properties": {
                    "issue_confidence": confidence,
                    "issue_severity": severity,
                },
                "ruleId": rule,
                "ruleIndex": rule_index[rule],
            }
        )
    rules = [
        {
            "id": rule_id,
            "name": rule_name,
            "properties": {"tags": ["security", cwe], "precision": precision},
            "helpUri": f"https://bandit.readthedocs.io/en/1.9.4/{page}",
        }
        for rule_id, rule_name, cwe, precision, page in _BANDIT_RULES
    ]
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "organization": "PyCQA",
                        "rules": rules,
                        "version": "1.9.4",
                        "semanticVersion": "1.9.4",
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
            }
        ],
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    }


def write_fixture_tree(source_dir: Path) -> None:
    source_dir.mkdir(parents=True, exist_ok=True)
    for name, text in FIXTURE_FILES.items():
        (source_dir / name).write_text(text, encoding="utf-8")


def use_canned_bandit(
    monkeypatch: pytest.MonkeyPatch,
    sarif_for: Callable[[Path], Dict[str, Any]] | None = None,
) -> None:
    """Make ``BanditScanner`` run without the bandit tool, writing canned SARIF.

    ``bandit_sarif()`` unless ``sarif_for`` is given, which is called with the
    scan's source directory, so that each project of a workspace gets its own.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
    )

    def _dependencies_present(self) -> bool:
        self.dependencies_satisfied = True
        return True

    def _run_canned_bandit(self, command, results_dir, *args, **kwargs):
        results_dir = Path(results_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        document = (
            bandit_sarif()
            if sarif_for is None
            else sarif_for(Path(self.context.source_dir))
        )
        (results_dir / "bandit.sarif").write_text(
            json.dumps(document), encoding="utf-8"
        )
        # Bandit exits 1 when it reports findings.
        self.exit_code = 1
        return {"returncode": 1}

    monkeypatch.setattr(
        BanditScanner, "validate_plugin_dependencies", _dependencies_present
    )
    monkeypatch.setattr(BanditScanner, "_run_subprocess", _run_canned_bandit)


def isolate_from_aws(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Leave botocore no credentials and no reachable endpoint for the scan.

    Once a test in the process has imported ``ash_aws_plugins``, its reporters are
    registered, and the report phase builds each one. They default to disabled,
    so none calls ``validate_plugin_dependencies`` (Security Hub's ``DescribeHub``,
    the others' STS) unless a test enables it or a regression turns one back on;
    this covers both. Without credentials botocore stops before sending anything;
    the loopback endpoint is a second stop in case some provider still finds one.
    """
    import os

    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(root / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(root / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")


#: The operator config the scan runs with, written outside the scanned tree. The
#: LOW threshold makes every finding actionable, so reporters that list only
#: actionable findings (markdown's detailed findings, Bedrock) see them all; the
#: YAML reporter is off by default.
SCAN_CONFIG = (
    "project_name: secret-masking-fixture\n"
    "global_settings:\n"
    "  severity_threshold: LOW\n"
    "reporters:\n"
    "  yaml:\n"
    "    enabled: true\n"
)


def run_secret_bearing_scan(root: Path, phases: List[Any] | None = None) -> Path:
    """Scan the fixture tree with bandit (canned) and detect-secrets; return the output dir.

    Runs through ``run_ash_scan``, the function the CLI and the MCP server call,
    with the default (parallel) strategy. ``phases`` is passed on as ``--phases``.
    """
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    source_dir = root / "src"
    output_dir = root / "out"
    write_fixture_tree(source_dir)
    config_path = root / "ash-config.yaml"
    config_path.write_text(SCAN_CONFIG, encoding="utf-8")

    with pytest.MonkeyPatch.context() as monkeypatch:
        use_canned_bandit(monkeypatch)
        isolate_from_aws(monkeypatch, root)
        run_ash_scan(
            source_dir=str(source_dir),
            output_dir=str(output_dir),
            config=str(config_path),
            scanners=["bandit", "detect-secrets"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
            phases=phases,
        )
    return output_dir


def run_secret_bearing_workspace_scan(root: Path) -> Path:
    """Scan the fixture tree as the one project (``api``) of a workspace.

    Workspace mode scans each project with its own engine run, writes
    ``projects/<key>/``, and then renders the unified reports at the top of the
    output directory from the merged results. Returns that output directory.
    """
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    project_dir = root / "api"
    write_fixture_tree(project_dir)
    output_dir = root / "out"
    plan = WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=project_dir.as_posix(),
                label="api",
                display_label="api",
                severity_threshold="LOW",
            )
        ],
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        use_canned_bandit(monkeypatch)
        isolate_from_aws(monkeypatch, root)
        run_ash_scan(
            source_dir=str(root),
            output_dir=str(output_dir),
            workspace_plan=plan,
            scanners=["bandit", "detect-secrets"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
        )
    return output_dir


#: One value two projects of a workspace share: ``api`` assigns it, and B105
#: quotes it in its message; ``web`` passes it on a command line, where only
#: bandit's B602 reports the line. 14 lower-case letters or digits.
SHARED_VALUE = _derived("shared-project-value", _LOWER, 14)

#: The two projects' files: {project: {file name: text}}.
TWO_PROJECT_FILES: Dict[str, Dict[str, str]] = {
    "api": {
        "settings.py": "DB_" + _KEYWORD_NAME.upper() + ' = "' + SHARED_VALUE + '"\n'
    },
    "web": {
        "deploy.py": (
            "import subprocess\n"
            'subprocess.call("deploy --pw ' + SHARED_VALUE + '", shell=True)\n'
        )
    },
}


def _two_project_bandit_sarif(source_dir: Path) -> Dict[str, Any]:
    """Bandit's SARIF for whichever of the two projects ``source_dir`` is."""
    if (source_dir / "settings.py").is_file():
        findings = [
            ("B105", "settings.py", 1, "note", "LOW", _value_message(SHARED_VALUE))
        ]
        files = TWO_PROJECT_FILES["api"]
    else:
        findings = [("B602", "deploy.py", 2, "error", "HIGH", _B602_UNSAFE)]
        files = TWO_PROJECT_FILES["web"]
    results = []
    for rule, name, line, level, severity, message in findings:
        lines = files[name].splitlines(keepends=True)
        results.append(
            {
                "message": {"text": message},
                "level": level,
                "locations": [
                    {
                        "physicalLocation": {
                            "region": {
                                "snippet": {"text": lines[line - 1]},
                                "startLine": line,
                                "endLine": line,
                            },
                            "artifactLocation": {"uri": name},
                            "contextRegion": {
                                "snippet": {"text": "".join(lines[:line])},
                                "startLine": 1,
                                "endLine": line,
                            },
                        }
                    }
                ],
                "properties": {"issue_confidence": "HIGH", "issue_severity": severity},
                "ruleId": rule,
            }
        )
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "rules": [
                            {
                                "id": rule_id,
                                "name": rule_name,
                                "properties": {"tags": ["security", cwe]},
                            }
                            for rule_id, rule_name, cwe, _, _ in _BANDIT_RULES
                        ],
                        "version": "1.9.4",
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": results,
            }
        ],
        "version": "2.1.0",
    }


def run_two_project_workspace_scan(root: Path) -> Path:
    """Scan ``TWO_PROJECT_FILES`` as the two projects of one workspace (bandit only).

    Each project's scan is masked against its own findings, so ``web`` alone
    cannot know that the value on its command line is the one ``api``'s B105
    reported. Returns the output directory.
    """
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

    projects = []
    for key, files in TWO_PROJECT_FILES.items():
        project_dir = root / key
        project_dir.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (project_dir / name).write_text(text, encoding="utf-8")
        projects.append(
            ProjectPlan(
                key=key,
                relative_path=key,
                path=project_dir.as_posix(),
                label=key,
                display_label=key,
                severity_threshold="LOW",
            )
        )
    output_dir = root / "out"
    plan = WorkspacePlan(
        workspace_file=(root / "dev.code-workspace").as_posix(),
        workspace_root=root.as_posix(),
        projects=projects,
    )

    with pytest.MonkeyPatch.context() as monkeypatch:
        use_canned_bandit(monkeypatch, _two_project_bandit_sarif)
        isolate_from_aws(monkeypatch, root)
        run_ash_scan(
            source_dir=str(root),
            output_dir=str(output_dir),
            workspace_plan=plan,
            scanners=["bandit"],
            offline=True,
            progress=False,
            quiet=True,
            show_summary=False,
            fail_on_findings=False,
            color=False,
        )
    return output_dir


def load_results(output_dir: Path):
    """The ``AshAggregatedResults`` a scan saved, as a fresh model."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    return AshAggregatedResults.model_validate_json(
        (output_dir / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )


def sarif_results(document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every result in a SARIF document (a parsed ``ash.sarif`` or the ``sarif`` key)."""
    return [
        result
        for run in document.get("runs") or []
        for result in run.get("results") or []
    ]


def find_result(
    results: List[Dict[str, Any]], rule_id: str, uri: str, line: int
) -> Dict[str, Any]:
    """The one result with this rule at ``uri``:``line``; fails the test if absent."""
    matches = [
        result
        for result in results
        if result.get("ruleId") == rule_id
        and _location(result)[0] == uri
        and _location(result)[1] == line
    ]
    assert len(matches) == 1, (
        f"expected exactly one {rule_id} at {uri}:{line}, found {len(matches)}"
    )
    return matches[0]


def _location(result: Dict[str, Any]) -> Tuple[str | None, int | None]:
    for location in result.get("locations") or []:
        physical = location.get("physicalLocation") or {}
        uri = (physical.get("artifactLocation") or {}).get("uri")
        line = (physical.get("region") or {}).get("startLine")
        if uri is not None:
            return uri.rsplit("/", 1)[-1], line
    return None, None


def snippet(result: Dict[str, Any], region: str) -> str | None:
    """``region`` (``"region"`` or ``"contextRegion"``) snippet text of ``result``."""
    physical = result["locations"][0]["physicalLocation"]
    return ((physical.get(region) or {}).get("snippet") or {}).get("text")


def scanner_shaped_report(scanner_name: str, results: List[Dict[str, Any]]):
    """A SARIF report as ``ScanResultProcessor`` hands it on for ``scanner_name``.

    The scanner's own result dicts, validated, with
    ``sarif_utils.attach_scanner_details`` applied -- the function the processor
    calls on every scanner's report before merging it.
    """
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import attach_scanner_details

    report = SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": scanner_name}}, "results": results}],
        }
    )
    return attach_scanner_details(
        report, scanner_name=scanner_name, scanner_version="1.0.0"
    )


def detect_secrets_report(source_dir: Path, output_dir: Path):
    """What ``DetectSecretsScanner`` reports for ``source_dir``, run for real."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from automated_security_helper.utils.sarif_utils import attach_scanner_details

    scanner = DetectSecretsScanner(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir / "converted",
            config=get_default_config(),
        ),
        config=DetectSecretsScannerConfig(),
    )
    report = scanner.scan(source_dir, target_type="source")
    assert isinstance(report, SarifReport), f"detect-secrets returned {report!r}"
    return attach_scanner_details(
        report, scanner_name="detect-secrets", scanner_version=scanner.tool_version
    )


def results_without_masking(source_dir: Path, output_dir: Path):
    """The fixture's findings assembled without any of ASH's masking.

    Stands for an ``ash_aggregated_results.json`` written before masking existed:
    the canned bandit report and a real detect-secrets report, each passed through
    ``attach_scanner_details`` and merged as ``ScanResultProcessor`` merges them,
    and nothing else. The caller checks that the values really are in it, so a
    producer that starts masking on its own makes the precondition fail rather than
    the test pass for the wrong reason.
    """
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    write_fixture_tree(source_dir)
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    bandit = scanner_shaped_report("bandit", bandit_sarif()["runs"][0]["results"])
    model.sarif.merge_sarif_report(bandit)
    model.sarif.merge_sarif_report(detect_secrets_report(source_dir, output_dir))
    return model


#: The two p/ci secret rules whose results ``tests/test_data/scanners/semgrep/
#: semgrep.src.json`` holds, as opengrep 1.30.2 writes them in its SARIF. Captured
#: once by running opengrep offline on ``FIXTURE_FILES`` with those rules (their
#: ids, messages and metadata copied from that file, and semgrep-rules' published
#: patterns); semgrep writes the same SARIF. The rule metadata holds no value.
_PCI_SECRET_RULES: List[Tuple[str, str, str]] = [
    (
        (
            "generic.secrets.security.detected-aws-access-key-id-value."
            "detected-aws-access-key-id-value"
        ),
        (
            "AWS Access Key ID Value detected. This is a sensitive credential and "
            "should not be hardcoded here. Instead, read this value from an "
            "environment variable or keep it in a separate, private file."
        ),
        "settings.py",
    ),
    (
        (
            "generic.secrets.security.detected-aws-secret-access-key."
            "detected-aws-secret-access-key"
        ),
        "AWS Secret Access Key detected",
        "creds.py",
    ),
]


def opengrep_secret_sarif(
    driver_name: str = "Opengrep OSS", version: str = "1.30.2"
) -> Dict[str, Any]:
    """The SARIF opengrep (or semgrep) writes for the fixture's two AWS values.

    The rules carry ``CWE-798: Use of Hard-coded Credentials`` in their tags and no
    ``secret`` tag, and the results carry no tags at all, which is how these
    scanners report a secret. Each snippet is the matched line, rebuilt from the
    file text; the fingerprint is computed here so this source holds no long hex.
    """
    rules = []
    results = []
    for rule_id, message, name in _PCI_SECRET_RULES:
        help_markdown = (
            f"{message}\n\n<b>References:</b>\n"
            f" - [Rule](https://semgrep.dev/r/{rule_id})\n"
            " - [https://owasp.org/Top10/A07_2021-Identification_and_Authentication"
            "_Failures](https://owasp.org/Top10/A07_2021-Identification_and_"
            "Authentication_Failures)\n"
        )
        rules.append(
            {
                "defaultConfiguration": {"level": "error"},
                "fullDescription": {"text": message},
                "help": {"markdown": help_markdown, "text": message},
                "helpUri": f"https://semgrep.dev/r/{rule_id}",
                "id": rule_id,
                "name": rule_id,
                "properties": {
                    "precision": "very-high",
                    "tags": [
                        "CWE-798: Use of Hard-coded Credentials",
                        "LOW CONFIDENCE",
                        "OWASP-A07:2021 - Identification and Authentication Failures",
                        "security",
                    ],
                },
                "shortDescription": {
                    "text": f"{driver_name.split()[0]} Finding: {rule_id}"
                },
            }
        )
        lines = _lines(name)
        line_number = next(
            number
            for number, text in enumerate(lines, start=1)
            if SECRETS.key_id in text or SECRETS.long_key in text
        )
        line = lines[line_number - 1].rstrip("\n")
        value = SECRETS.key_id if SECRETS.key_id in line else SECRETS.long_key
        start = line.index(value) + 1 if value == SECRETS.key_id else 1
        end = start + len(value) if value == SECRETS.key_id else len(line) + 1
        results.append(
            {
                "fingerprints": {
                    "matchBasedId/v1": hashlib.sha512(
                        f"{rule_id}:{line}".encode()
                    ).hexdigest()
                    + "_0"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"src/{name}",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "endColumn": end,
                                "endLine": line_number,
                                "snippet": {"text": line},
                                "startColumn": start,
                                "startLine": line_number,
                            },
                        }
                    }
                ],
                "message": {"text": message},
                "properties": {},
                "ruleId": rule_id,
            }
        )
    return {
        "version": "2.1.0",
        "$schema": (
            "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/"
            "sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "invocations": [
                    {"executionSuccessful": True, "toolExecutionNotifications": []}
                ],
                "results": results,
                "tool": {
                    "driver": {
                        "name": driver_name,
                        "rules": rules,
                        "semanticVersion": version,
                    }
                },
            }
        ],
    }
