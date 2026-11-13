# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit must read yarn's audit output and report yarn audit failures.

Before this, a yarn.lock project always came out clean. yarn 1 writes NDJSON,
which ``json.loads`` rejects, so a real report became "no output" and passed.
yarn 2 and later have no ``yarn audit`` at all, so the scanner ran a command
that printed a usage error and exited 1, and that passed too. A failed request
was never reported, because yarn had no report key for ``_audit_failure`` to
look for.

The payloads in tests/test_data/scanners/npmaudit/yarn are real output, with
the command, exit code, stdout and stderr each produced:

- yarn 1.22.22 (``yarn audit --json``) and yarn 4.18.1, the ``yarn@stable``
  the image prepares (``yarn npm audit --json --recursive``), plus yarn 3.8.7,
  whose ``yarn npm audit --json`` prints one npm v1 document instead.
- A project depending on lodash 4.17.20 and mkdirp 0.5.1 (which pulls in
  minimist 0.0.8) for the findings, and on is-number 7.0.0 for the clean case.
- Endpoint failures: yarn 1 sends its audit to a hardcoded registry, so it was
  pointed through ``HTTPS_PROXY`` at a closed port, and at a proxy that
  terminated TLS and answered 500 (the Node warning about the disabled
  certificate check that setup caused is removed from stderr). yarn 4 was
  pointed at a closed port and at a server answering 500 through
  ``YARN_NPM_AUDIT_REGISTRY``.
- No lockfile, and yarn 1 with ``--offline``.

Corepack's cache path in the stack traces is rewritten to the image's.
"""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    NpmAuditScannerConfigOptions,
)

pytestmark = pytest.mark.unit

CAPTURES = (
    Path(__file__).resolve().parents[4] / "test_data" / "scanners" / "npmaudit" / "yarn"
)


def _capture(name):
    return json.loads((CAPTURES / f"{name}.json").read_text(encoding="utf-8"))


def _response(capture):
    return {
        "stdout": capture["stdout"],
        "stderr": capture["stderr"],
        "returncode": capture["returncode"],
    }


# The advisories each capture of the vulnerable project holds, as
# (rule id, package, installed version, SARIF level).
LODASH = [
    ("GHSA-35jh-r3h4-6jhm", "lodash", "4.17.20", "error"),
    ("GHSA-29mw-wpgm-hmr9", "lodash", "4.17.20", "warning"),
    ("GHSA-r5fr-rjxr-66jc", "lodash", "4.17.20", "error"),
    ("GHSA-f23m-r3pf-42rh", "lodash", "4.17.20", "warning"),
    ("GHSA-xxjr-mmjv-4gpg", "lodash", "4.17.20", "warning"),
]
MINIMIST = [
    ("GHSA-vh95-rmgr-6w4m", "minimist", "0.0.8", "warning"),
    ("GHSA-xvch-5gv4-984h", "minimist", "0.0.8", "error"),
]
ALL_FINDINGS = sorted(LODASH + MINIMIST)

# (capture, findings the scan must report)
REPORTS = [
    ("classic-vuln", ALL_FINDINGS),
    ("classic-clean", []),
    ("berry-vuln-recursive", ALL_FINDINGS),
    ("berry-clean", []),
    ("berry3-vuln", ALL_FINDINGS),
    ("berry3-clean", []),
]

# (capture, text the failure must carry)
FAILURES = [
    ("classic-closedport", "ECONNREFUSED"),
    ("classic-500", 'Request failed "500 Internal Server Error"'),
    ("berry-closedport", "ECONNREFUSED"),
    ("berry-500", "Response code 500"),
    ("berry-nolock", "doesn't seem to be present in your lockfile"),
]

EXPECTED_COMMAND = {
    1: ["yarn", "audit", "--json"],
    3: ["yarn", "npm", "audit", "--json", "--all", "--recursive"],
    4: ["yarn", "npm", "audit", "--json", "--all", "--recursive"],
}

#: The yarn 2+ captures were produced without ``--all``, which widens the set of
#: workspaces audited and changes nothing in the output format, so a capture's
#: command is the scanner's command without that flag.
WIDENING_FLAGS = {"--all"}


def _as_captured(command):
    return [part for part in command if part not in WIDENING_FLAGS]


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return context


@pytest.fixture(autouse=True)
def tools_on_path(monkeypatch, tmp_path):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )


def _scanner(context, offline=False):
    return NpmAuditScanner(
        context=context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=offline)
        ),
    )


def _project(root, lock_name="yarn.lock"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "placeholder-app", "version": "1.0.0"}), encoding="utf-8"
    )
    if lock_name:
        (root / lock_name).write_text("# yarn lockfile v1\n", encoding="utf-8")
    return root


def _respond(yarn_version, *responses):
    """_run_subprocess side effect: `--version` answers with ``yarn_version``,
    every other command takes the next response. Commands are recorded."""
    queue = list(responses)
    commands = []

    def _side_effect(self, command, **kwargs):
        commands.append(list(command))
        if "--version" in command:
            return {"stdout": f"{yarn_version}\n", "stderr": "", "returncode": 0}
        response = queue.pop(0)
        if "returncode" in response:
            self._process_command_response(response)
        return response

    return _side_effect, commands


def _scan(context, capture, offline=False):
    scanner = _scanner(context, offline=offline)
    _project(context.work_dir)
    side_effect, commands = _respond(capture["yarn_version"], _response(capture))
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
    ):
        report = scanner.scan(target=context.work_dir, target_type="converted")
    return report, commands


def _findings(report):
    return sorted(
        (
            r.ruleId,
            r.properties.model_extra["package_name"],
            r.properties.model_extra["installed_version"],
            r.level,
        )
        for r in report.runs[0].results
    )


@pytest.mark.parametrize("name, expected", REPORTS, ids=[n for n, _ in REPORTS])
def test_yarn_reports_become_findings(plugin_context, name, expected):
    capture = _capture(name)

    report, commands = _scan(plugin_context, capture)

    assert _findings(report) == expected
    # The capture was produced by the command the scanner now runs, less the
    # flags that only widen what is audited.
    audit = [c for c in commands if "--version" not in c]
    major = int(capture["yarn_version"].split(".")[0])
    assert audit == [EXPECTED_COMMAND[major]]
    assert [_as_captured(c) for c in audit] == [capture["command"]]


@pytest.mark.parametrize(
    "name", ["berry3-clean", "berry-clean"], ids=["yarn-3", "yarn-4"]
)
def test_yarn_2_and_later_audit_every_workspace(plugin_context, name):
    """A yarn workspace monorepo has one lockfile at its root. ``yarn npm audit``
    without ``--all`` audits the root workspace's dependencies only, so the member
    workspaces' dependencies were never checked; ``--all`` audits every workspace
    from the same lockfile, as npm does. yarn 1 has one ``yarn audit`` for the whole
    project and takes no such flag (``test_yarn_1_takes_no_workspace_flag``).

    This pins the argument on each yarn 2+ major the captures cover (3 and 4;
    there is no yarn 2 capture); yarn does not care where it stands among the
    others. What the flag changes in a report (an advisory reached only through
    a member workspace) is not pinned here: every yarn 2+ capture in the test
    data comes from a single-workspace project run without ``--all``, and a
    two-workspace capture has to be recorded by running the tool."""
    report, commands = _scan(plugin_context, _capture(name))

    (audit,) = [c for c in commands if "--version" not in c]
    assert "--all" in audit, audit
    assert report.runs[0].results == []


def test_yarn_1_takes_no_workspace_flag(plugin_context):
    _, commands = _scan(plugin_context, _capture("classic-clean"))

    (audit,) = [c for c in commands if "--version" not in c]
    assert "--all" not in audit, audit
    assert audit == ["yarn", "audit", "--json"]


@pytest.mark.parametrize("name, reason", FAILURES, ids=[n for n, _ in FAILURES])
def test_a_failed_yarn_audit_raises_instead_of_reporting_clean(
    plugin_context, name, reason
):
    with pytest.raises(ScannerError) as excinfo:
        _scan(plugin_context, _capture(name))

    message = str(excinfo.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert "yarn.lock" in message, message
    assert reason in message, message
    assert "\x1b[" not in message, "terminal colour codes leaked into the reason"
    assert "    at " not in message, "a stack frame leaked into the reason"


def test_a_raising_values_hook_degrades_the_failure_detail_not_the_scan(
    plugin_context,
):
    """_values_to_redact is an overridable hook, and the audit-failure texts
    are best-effort records: a raising hook costs the quoted tool text, never
    the scan. Before the guarded read it crashed the scan from inside the
    failure builder."""
    capture = _capture("classic-closedport")
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)
    side_effect, _commands = _respond(capture["yarn_version"], _response(capture))

    with (
        patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
        ),
        patch.object(
            NpmAuditScanner,
            "_values_to_redact",
            side_effect=RuntimeError("hook broke on '/opt/qz4b/config'"),
        ),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert "yarn.lock" in message, message
    assert "qz4b" not in message, "an unredacted text reached the reason"
    # The degrade drops the tool's excerpt: without the values it cannot be
    # redacted, and showing it with an empty value set would print what the
    # values would have hidden. The same capture's reason normally carries
    # this text (test_a_failed_yarn_audit_raises_instead_of_reporting_clean).
    assert "ECONNREFUSED" not in message, message


def test_yarn_audit_on_yarn_4_is_a_usage_error_not_a_report():
    """What the scanner used to run on yarn 2+: `yarn audit` is not a command
    there, and its usage error must not read as a clean report."""
    capture = _capture("berry-legacycmd-vuln")
    assert capture["returncode"] == 1

    report, reason = NpmAuditScanner._parse_yarn_audit(4, _response(capture))

    assert report is None
    assert "Couldn't find a script named" in reason, reason


def test_yarn_1_without_a_lockfile_still_reports():
    """yarn 1 audits from package.json when there is no lockfile, and says so in
    an info event. That is a report, not a failure."""
    report, reason = NpmAuditScanner._parse_yarn_audit(
        1, _response(_capture("classic-nolock"))
    )

    assert reason is None
    assert {r["package"] for r in report["yarn_advisories"]} == {"lodash"}


def test_no_lockfile_runs_no_yarn(plugin_context):
    """Without a lockfile there is nothing to audit and no command is run, as for
    npm and pnpm."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir, lock_name=None)
    side_effect, commands = _respond("1.22.22")
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert [c for c in commands if "audit" in c] == []
    assert report.runs[0].results == []


def test_yarn_findings_carry_the_npm_result_shape(plugin_context):
    report, _ = _scan(plugin_context, _capture("classic-vuln"))
    run = report.runs[0]

    (critical,) = [r for r in run.results if r.ruleId == "GHSA-xvch-5gv4-984h"]
    props = critical.properties.model_extra
    assert critical.level == "error"
    location = critical.locations[0].model_dump(by_alias=True, exclude_none=True)
    assert (
        location["physicalLocation"]["artifactLocation"]["uri"]
        == "node_modules/minimist/package.json"
    )
    assert props["package_name"] == "minimist"
    assert props["package_version"] == "0.0.8"
    assert props["severity"] == "critical"
    assert props["vulnerable_versions"] == "<0.2.4"
    assert props["patched_versions"] == ">=0.2.4"
    assert props["fix_available"] is True
    assert props["cwe"] == ["CWE-1321"]
    assert props["cvss"]["score"] == 9.8
    assert props["dependency_paths"] == ["mkdirp>minimist"]
    assert "package_path" not in props, "yarn does not say where a copy is installed"
    assert "Prototype Pollution in minimist" in critical.message.root.text

    rule = {r.id: r for r in run.tool.driver.rules}["GHSA-xvch-5gv4-984h"]
    assert rule.properties.model_extra["security_severity"] == 9.8
    assert "npm-audit" in rule.properties.tags
    assert run.properties.model_extra["metrics"]["critical"] == 1


def test_yarn_4_deprecations_are_not_findings(plugin_context):
    """yarn 4 lists deprecated packages in the advisory stream; mkdirp 0.5.1 is
    one. npm audit does not report deprecations and neither does this."""
    capture = _capture("berry-vuln-recursive")
    assert "mkdirp (deprecation)" in capture["stdout"]

    report, _ = _scan(plugin_context, capture)

    assert "mkdirp" not in {
        r.properties.model_extra["package_name"] for r in report.runs[0].results
    }
    rule = {r.id: r for r in report.runs[0].tool.driver.rules}["GHSA-xvch-5gv4-984h"]
    assert "security_severity" not in (rule.properties.model_extra or {}), (
        "yarn 4 gives no CVSS score, and a made-up one would move the severity"
    )


def test_a_version_yarn_cannot_report_is_a_failure(plugin_context):
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    def _side_effect(self, command, **kwargs):
        return {
            "stdout": "",
            "stderr": "Internal Error: Usage Error: corepack could not fetch yarn",
            "returncode": 1,
        }

    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=_side_effect
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert "could not tell which yarn version runs here" in str(excinfo.value)
    assert "corepack could not fetch yarn" in str(excinfo.value)


class TestOffline:
    """Offline no yarn runs: yarn 1's `yarn audit --offline` refuses to ask the
    registry ("Can't make a request in offline mode") and `yarn npm audit` has no
    offline mode, so the lockfile is recorded as not audited, with a warning, and
    scan() returns False, which the executor records MISSING."""

    @pytest.mark.parametrize("capture_name", ["classic-offline", "berry-clean"])
    def test_offline_yarn_is_not_run_and_the_lockfile_is_recorded(
        self, plugin_context, caplog, capture_name
    ):
        scanner = _scanner(plugin_context, offline=True)
        _project(plugin_context.work_dir)
        side_effect, commands = _respond(
            _capture(capture_name)["yarn_version"], _response(_capture(capture_name))
        )
        with (
            patch.object(
                NpmAuditScanner,
                "_run_subprocess",
                autospec=True,
                side_effect=side_effect,
            ),
            caplog.at_level(logging.WARNING),
        ):
            report = scanner.scan(
                target=plugin_context.work_dir, target_type="converted"
            )

        assert [c for c in commands if "--version" not in c] == [], commands
        assert report is False
        assert [entry["path"] for entry in scanner.inputs_not_scanned] == ["yarn.lock"]
        assert any(
            "Offline, npm-audit audits nothing" in r.message for r in caplog.records
        )


class TestExecutorStatus:
    """What the operator sees for a yarn project."""

    def _execute(self, context, capture):
        executor = ScannerExecutor(
            plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
        )
        _project(context.source_dir)
        side_effect, _ = _respond(capture["yarn_version"], _response(capture))
        with patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=side_effect
        ):
            (container,) = executor._execute_scanner(
                "npm-audit",
                _scanner(context),
                [{"path": context.source_dir, "type": "source"}],
            )
        return container

    def test_a_failed_yarn_audit_is_reported_as_error(self, plugin_context):
        container = self._execute(plugin_context, _capture("berry-500"))

        assert container.status == ScannerStatus.ERROR
        assert "Response code 500" in container.raw_results["errors"][0]

    def test_a_clean_yarn_audit_is_reported_as_passed(self, plugin_context):
        container = self._execute(plugin_context, _capture("classic-clean"))

        assert container.status == ScannerStatus.PASSED

    def test_yarn_findings_reach_the_executor(self, plugin_context):
        container = self._execute(plugin_context, _capture("classic-vuln"))

        assert container.status != ScannerStatus.ERROR
        assert container.finding_count == len(ALL_FINDINGS)


@pytest.mark.parametrize(
    "output, major",
    [
        ("1.22.22\n", 1),
        ("4.18.1", 4),
        ("\x1b[33mwarning\x1b[0m something\n3.8.7\n", 3),
        ("", None),
        ("Usage Error: nope", None),
    ],
)
def test_yarn_major(output, major):
    assert NpmAuditScanner._yarn_major(output) == major


def test_the_yarn_fallback_reason_is_redacted_before_its_cut():
    """A yarn failure whose only problem line is too long for the per-line
    detail falls back to that first line, cut at 300 characters: the
    redaction runs BEFORE the cut, so an env-read value straddling character
    300 is hidden whole and no fragment survives. This pins the fallback's
    own order -- reverting only this site's shown_tool_stderr leaves every
    other cell green."""
    value = "Zq7Kx9Lm2Pw4Nv"
    pad = "p" * (300 - 12 - 6)
    line = f"FetchError: {pad}{value} request to the registry failed"
    response = {"stdout": line, "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response, values=(value,))

    assert report is None
    assert "yarn audit reported an error" in (reason or ""), reason
    assert "Zq7K" not in (reason or ""), reason


def test_the_fallback_pass_runs_only_when_the_detail_is_empty(monkeypatch):
    """The first-line fallback redacts the WHOLE problem text a second time
    before its cut. That pass is computed only when the per-line detail
    answered nothing: when an error event already names the failure, nobody
    reads the fallback, so the text is not redacted again for it. The
    recorder pins that: with a reported event, no redaction call receives
    the joined problem text itself."""
    recorded = []
    real = npm_audit_scanner.shown_tool_stderr

    def recorder(piece, values=()):
        recorded.append(piece)
        return real(piece, values)

    monkeypatch.setattr(npm_audit_scanner, "shown_tool_stderr", recorder)
    event = json.dumps({"type": "error", "data": "Request failed\nmore detail"})
    response = {"stdout": event + "\n", "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response, values=())

    assert report is None
    assert "Request failed" in (reason or ""), reason
    assert (event + "\n") not in recorded, recorded


def test_the_plain_yarn_text_is_redacted_whole_before_it_is_split(monkeypatch):
    """An env-read value can hold a line break (a PEM, a multi-line token), and
    a split is a cut: redacting line by line matches neither half. The plain
    (non-event) text is put back together WITH its own separators -- a CRLF
    value does not match a "\\n" rejoin -- and redacted as ONE piece before the
    lines are split and filtered. The recorder pins that order: it sees one
    piece holding the raw multi-line value, never the halves."""
    value = "Zq7Kx9Lm\r\nPw4Nv2Rt"
    redacted_pieces = []
    real = npm_audit_scanner.shown_tool_stderr

    def recorder(piece, values=()):
        redacted_pieces.append(piece)
        return real(piece, values)

    monkeypatch.setattr(npm_audit_scanner, "shown_tool_stderr", recorder)
    text = f"Error: cannot reach {value}/registry now\nat foo (x.js:1:2)\n"

    detail = NpmAuditScanner._yarn_error_detail(text, values=(value,))

    assert redacted_pieces == [text], redacted_pieces
    assert "cannot reach" in detail, detail
    assert "at foo" not in detail, detail
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in detail, (part, detail)


# A value holding a line break, one case per separator ``str.splitlines``
# honors in real tool text (a PEM's LF, a CRLF-writing tool, a form feed).
MULTILINE_VALUES = {
    "lf": "Zq7Kx9Lm\nPw4Nv2Rt",
    "crlf": "Zq7Kx9Lm\r\nPw4Nv2Rt",
    "ff": "Zq7Kx9Lm\x0cPw4Nv2Rt",
}


@pytest.mark.parametrize("sep", sorted(MULTILINE_VALUES))
def test_a_multi_line_value_in_a_yarn_error_event_is_hidden(sep):
    """The error event's data is redacted WHOLE before its first line is
    taken: splitting first leaves each half unmatched, and the first half
    prints in the detail."""
    value = MULTILINE_VALUES[sep]
    event = json.dumps(
        {"type": "error", "data": f"fetch failed for {value} at the registry"}
    )

    detail = NpmAuditScanner._yarn_error_detail(event + "\n", (value,))

    assert "fetch failed" in detail, detail
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in detail, (part, detail)


@pytest.mark.parametrize("sep", sorted(MULTILINE_VALUES))
def test_a_multi_line_value_in_a_plain_yarn_line_is_hidden(sep):
    value = MULTILINE_VALUES[sep]
    text = f"Error: cannot reach {value}/registry now\nat foo (x.js:1:2)\n"

    detail = NpmAuditScanner._yarn_error_detail(text, (value,))

    assert "cannot reach" in detail, detail
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in detail, (part, detail)


def test_a_single_line_value_in_an_event_is_still_hidden():
    """Control: the whole-data redaction keeps the single-line contract."""
    value = "Zq7Kx9LmPw4Nv2Rt"
    event = json.dumps(
        {"type": "error", "data": f"fetch failed for {value} at the registry"}
    )

    detail = NpmAuditScanner._yarn_error_detail(event + "\n", (value,))

    assert "fetch failed" in detail and value not in detail, detail


@pytest.mark.parametrize("sep", sorted(MULTILINE_VALUES))
def test_a_multi_line_value_in_a_yarn_1_stdout_error_event_is_hidden(sep):
    """The same contract through _parse_yarn_audit's own problems path: a
    yarn 1 stdout error event's data was cut to its first RAW line before any
    redaction saw it."""
    value = MULTILINE_VALUES[sep]
    event = json.dumps(
        {"type": "error", "data": f"fetch failed for {value} at the registry"}
    )
    response = {"stdout": event + "\n", "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response, values=(value,))

    assert report is None
    assert "yarn audit reported an error" in (reason or ""), reason
    assert "fetch failed" in (reason or ""), reason
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in (reason or ""), (part, reason)


#: The separators ``str.splitlines`` honors that a JSON string may hold raw
#: (code points at or above U+0020; the ndjson-lines tests use the same three).
#: A form feed is not among them: JSON requires the control characters below
#: U+0020 to be escaped, so ``json.dumps`` writes ``\f`` and no raw form feed
#: ever reaches the stream, which made a form-feed case test nothing.
_RAW_SEPARATORS = {
    "line-separator": chr(0x2028),
    "paragraph-separator": chr(0x2029),
    "next-line": chr(0x0085),
}


@pytest.mark.parametrize("sep", sorted(_RAW_SEPARATORS), ids=sorted(_RAW_SEPARATORS))
def test_an_error_event_holding_a_unicode_line_separator_keeps_its_message(sep):
    """The detail reader splits the stream as the parse loops do, at line feeds
    only. A yarn 1 error event whose data holds a separator str.splitlines
    knows was cut in two here, neither half parsed, and the reason shown was
    the event's raw opening instead of its message."""
    separator = _RAW_SEPARATORS[sep]
    event = json.dumps(
        {"type": "error", "data": f"Request failed{separator}Error: ENOTFOUND host"},
        ensure_ascii=False,
    )
    assert separator in event, "the separator must reach the stream raw"

    detail = NpmAuditScanner._yarn_error_detail(event + "\n", ())

    assert detail.startswith("Request failed"), detail
    assert "{" not in detail and '"type"' not in detail, detail


def test_a_yarn_1_stdout_error_event_is_reduced_to_its_first_line():
    """An error event is reduced to its MESSAGE, the first line of its data,
    as the stderr events are: yarn writes the summary first and the Node
    error object after it. Unwrapping the data into plain text sent it down
    the plain branch, which prefers an "Error:"-named line, so a multi-line
    event's reason flipped from the message to the trailing Error line."""
    event = json.dumps(
        {"type": "error", "data": "Request failed\nError: getaddrinfo ENOTFOUND host"}
    )
    response = {"stdout": event + "\n", "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response, values=())

    assert report is None
    assert "Request failed" in (reason or ""), reason
    assert "getaddrinfo" not in (reason or ""), reason


def test_each_of_several_error_events_keeps_its_message():
    """One message per event: a multi-line event must not push a later
    event's message out of the three-item cap with its continuation lines."""
    events = [
        json.dumps({"type": "error", "data": f"request {i} failed\ndetail line {i}"})
        for i in (1, 2, 3)
    ]
    response = {"stdout": "\n".join(events) + "\n", "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response, values=())

    assert report is None
    for i in (1, 2, 3):
        assert f"request {i} failed" in (reason or ""), (i, reason)


SPANNING_SHAPES = {
    # The decoded stream reads "first request Zq7Kx9Lm\nPw4Nv2Rt second":
    # the value's own LF falls exactly at the boundary between two decoded
    # segments, so a per-segment redaction matches neither half.
    "two-events": (
        json.dumps({"type": "error", "data": "first request Zq7Kx9Lm"})
        + "\n"
        + json.dumps({"type": "error", "data": "Pw4Nv2Rt second"})
        + "\n"
    ),
    "event-then-plain": (
        json.dumps({"type": "error", "data": "first request Zq7Kx9Lm"})
        + "\n"
        + "Pw4Nv2Rt second line\n"
    ),
}


@pytest.mark.parametrize("shape", sorted(SPANNING_SHAPES))
def test_a_value_spanning_two_segments_is_hidden(shape):
    """A value whose own line break sits at a segment boundary -- the end of
    one error event's data and the start of the next event or plain line --
    has no whole spelling inside either segment, so per-segment redaction
    prints both halves. The decoded segments are redacted as ONE text."""
    value = "Zq7Kx9Lm\nPw4Nv2Rt"

    detail = NpmAuditScanner._yarn_error_detail(SPANNING_SHAPES[shape], (value,))

    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in detail, (part, detail)


def test_a_planted_segment_marker_line_cannot_split_a_message(monkeypatch):
    """The one-text redaction separates segments with a marker line carrying
    a fresh nonce, so tool text cannot name it. If a planted line does match
    it anyway (here: the marker hook pinned to a known value), the split no
    longer maps to the segments, and attribution is abandoned for the one
    redacted text rather than trusting a mapping the text controlled."""
    marker = "ash-segment-feedfacefeedface\n"
    monkeypatch.setattr(
        NpmAuditScanner, "_segment_marker", staticmethod(lambda: marker)
    )
    value = "Zq7Kx9LmPw4Nv2Rt"
    event = json.dumps({"type": "error", "data": f"fetch failed for {value} here"})
    text = event + "\n" + marker + "plain trailing line\n"

    detail = NpmAuditScanner._yarn_error_detail(text, (value,))

    assert value not in detail, detail
    assert "fetch failed" in detail, detail
    # The fallback's distinguishing effect: without it, the planted line is
    # read as a segment separator and the plain line after it is lost from
    # the detail. The words above survive either way; this one does not.
    assert "plain trailing line" in detail, detail


def test_a_crlf_value_spanning_plain_stdout_lines_is_hidden():
    """A non-JSON problem line was stripped and rejoined with "\\n" before the
    redaction: a CRLF value spanning the join no longer matched whole. The
    problem text must keep its own separators until it has been redacted."""
    value = "Zq7Kx9Lm\r\nPw4Nv2Rt"
    response = {
        "stdout": f"Error: cannot reach {value}/registry now\n",
        "stderr": "",
        "returncode": 1,
    }

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response, values=(value,))

    assert report is None
    assert "cannot reach" in (reason or ""), reason
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in (reason or ""), (part, reason)
