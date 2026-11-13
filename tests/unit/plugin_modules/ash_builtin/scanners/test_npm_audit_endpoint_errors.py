# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""npm-audit must not report PASSED when the audit itself failed.

npm exits 1 both when it finds vulnerabilities and when it cannot get advisories
at all, so the scanner, which accepts exit 1 as "findings present", parsed the
error document, found no ``vulnerabilities`` key, converted it to zero findings
and reported PASSED. A dependency audit that checked nothing read as clean.

The payloads below are what npm 10.9.4 (the npm bundled with Node 22, which the
image installs) actually wrote to stdout, with its exit code, for each failure.
They were captured by running ``npm audit --json`` against a real
package-lock.json with ``npm_config_registry`` pointed at a closed port and at a
local HTTP server answering 500, 503, 404 and a non-JSON body. Response headers
are trimmed to the fields that matter. The pnpm payload is pnpm's real output
for a refused connection: nothing on stdout, the error on stderr.

The tests drive ``NpmAuditScanner.scan`` and ``ScannerExecutor`` with
``_run_subprocess`` replaced, so no package manager is needed here.
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

NPM_ENDPOINT_STDERR = (
    "npm warn audit {message}\n"
    "npm error audit endpoint returned an error\n"
    "npm error A complete log of this run can be found in: /tmp/_logs/x-debug-0.log\n"
)


def _endpoint_error(message, **extra):
    """The document npm's audit-error.js writes under --json, then the error
    object npm's top-level handler appends (code is undefined, so dropped)."""
    return {"message": message, **extra, "error": {"summary": "", "detail": ""}}


CONNECTION_REFUSED = _endpoint_error(
    "request to http://127.0.0.1:1/-/npm/v1/security/audits/quick failed, "
    "reason: connect ECONNREFUSED 127.0.0.1:1"
)
REGISTRY_500 = _endpoint_error(
    "500 Internal Server Error - POST "
    "http://127.0.0.1:48701/-/npm/v1/security/audits/quick - internal",
    method="POST",
    uri="http://127.0.0.1:48701/-/npm/v1/security/audits/quick",
    headers={"content-type": ["application/json"], "x-fetch-attempts": ["1"]},
    statusCode=500,
    body={"error": "internal"},
)
REGISTRY_503 = _endpoint_error(
    "503 Service Unavailable - POST "
    "http://127.0.0.1:48702/-/npm/v1/security/audits/quick",
    method="POST",
    uri="http://127.0.0.1:48702/-/npm/v1/security/audits/quick",
    headers={"content-type": ["application/json"], "x-fetch-attempts": ["1"]},
    statusCode=503,
    body="Service Unavailable",
)
AUDIT_ENDPOINT_404 = _endpoint_error(
    "404 Not Found - POST "
    "http://127.0.0.1:48703/-/npm/v1/security/audits/quick - Not found",
    method="POST",
    uri="http://127.0.0.1:48703/-/npm/v1/security/audits/quick",
    headers={"content-type": ["application/json"], "x-fetch-attempts": ["1"]},
    statusCode=404,
    body={"error": "Not found"},
)
NON_JSON_BODY = _endpoint_error(
    "invalid json response body at "
    "http://127.0.0.1:48704/-/npm/v1/security/audits/quick reason: Unexpected "
    "token '<', \"<html>prox\"... is not valid JSON"
)
# npm's generic --json error shape, with a code. Captured from the same npm for
# ENOLOCK; npm 6 wrote ENOAUDIT in this shape.
ERROR_OBJECT_WITH_CODE = {
    "error": {
        "code": "ENOLOCK",
        "summary": "This command requires an existing lockfile.",
        "detail": "Try creating one first with: npm i --package-lock-only\n"
        "Original error: loadVirtual requires existing shrinkwrap file",
    }
}

CLEAN_AUDIT = {
    "auditReportVersion": 2,
    "vulnerabilities": {},
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 0,
            "total": 0,
        },
        "dependencies": {
            "prod": 2,
            "dev": 0,
            "optional": 0,
            "peer": 0,
            "peerOptional": 0,
            "total": 1,
        },
    },
}

VULNERABLE_AUDIT = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "minimist": {
            "name": "minimist",
            "severity": "critical",
            "isDirect": True,
            "via": [
                {
                    "source": 1179,
                    "name": "minimist",
                    "dependency": "minimist",
                    "title": "Prototype Pollution in minimist",
                    "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
                    "severity": "critical",
                    "cwe": ["CWE-1321"],
                    "cvss": {"score": 9.8, "vectorString": None},
                    "range": ">=1.0.0 <1.2.6",
                }
            ],
            "effects": [],
            "range": "",
            "nodes": ["node_modules/minimist"],
            "fixAvailable": True,
        }
    },
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 1,
            "total": 1,
        },
        "dependencies": {"prod": 2, "dev": 0, "total": 1},
    },
}


#: What ``npm audit --json`` wrote before npm 7: the v1 report, advisories
#: keyed by id with the counting metadata block, and no vulnerabilities key.
NPM6_V1_CLEAN_AUDIT = {
    "actions": [],
    "advisories": {},
    "muted": [],
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 0,
        },
        "dependencies": 1,
        "devDependencies": 0,
        "optionalDependencies": 0,
        "totalDependencies": 1,
    },
}


def _npm(doc, returncode=1, stderr=""):
    return {
        "stdout": json.dumps(doc, indent=2),
        "stderr": stderr,
        "returncode": returncode,
    }


# (id, lock file, subprocess response, text the reason must carry)
FAILURES = [
    (
        "network-failure",
        "package-lock.json",
        _npm(
            CONNECTION_REFUSED,
            stderr=NPM_ENDPOINT_STDERR.format(message=CONNECTION_REFUSED["message"]),
        ),
        "ECONNREFUSED",
    ),
    (
        "registry-500",
        "package-lock.json",
        _npm(REGISTRY_500),
        "500 Internal Server Error",
    ),
    (
        "registry-503",
        "package-lock.json",
        _npm(REGISTRY_503),
        "503 Service Unavailable",
    ),
    (
        "audit-endpoint-404",
        "package-lock.json",
        _npm(AUDIT_ENDPOINT_404),
        "404 Not Found",
    ),
    (
        "audit-endpoint-non-json-body",
        "package-lock.json",
        _npm(NON_JSON_BODY),
        "invalid json response body",
    ),
    (
        "error-object-with-code",
        "package-lock.json",
        _npm(ERROR_OBJECT_WITH_CODE),
        "ENOLOCK",
    ),
    (
        "error-object-on-exit-0",
        "package-lock.json",
        _npm(ERROR_OBJECT_WITH_CODE, returncode=0),
        "ENOLOCK",
    ),
    (
        "non-zero-exit-no-vulnerabilities-key",
        "package-lock.json",
        _npm({"metadata": {}}, returncode=1),
        "exited 1 without an audit report",
    ),
    (
        "non-zero-exit-no-output",
        "package-lock.json",
        {
            "stdout": "",
            "stderr": "npm error audit endpoint returned an error\n",
            "returncode": 1,
        },
        "audit endpoint returned an error",
    ),
    (
        "non-zero-exit-unparseable-output",
        "package-lock.json",
        {"stdout": "npm ERR! code ENOAUDIT", "stderr": "", "returncode": 1},
        "exited 1 without an audit report",
    ),
    # Exit 0 is not evidence either: a reply with no report, or with a report
    # key and nothing showing the lockfile was checked, is an audit that
    # evaluated nothing, however it exited.
    (
        "hollow-report-on-exit-0",
        "package-lock.json",
        _npm({"metadata": {}}, returncode=0),
        "exited 0 with output that is not an audit report, so no advisory was checked",
    ),
    (
        "bare-report-key-on-exit-0",
        "package-lock.json",
        _npm({"vulnerabilities": {}}, returncode=0),
        "exited 0 with output that is not an audit report, so no advisory was checked",
    ),
    (
        "bare-advisories-key-on-exit-0",
        "package-lock.json",
        _npm({"advisories": {}}, returncode=0),
        "exited 0 with output that is not an audit report, so no advisory was checked",
    ),
    (
        "no-output-on-exit-0",
        "package-lock.json",
        {"stdout": "", "stderr": "", "returncode": 0},
        "exited 0 printing nothing, so no advisory was checked",
    ),
    (
        "unparseable-output-on-exit-0",
        "package-lock.json",
        {"stdout": "npm notice audit skipped", "stderr": "", "returncode": 0},
        "exited 0 with output that is not an audit report, so no advisory was checked",
    ),
    (
        "pnpm-connection-refused",
        "pnpm-lock.yaml",
        {
            "stdout": "",
            "stderr": "\n\x1b[31mERR_PNPM_AUDIT_BAD_RESPONSE\x1b[0m\n\n"
            "  Failed to request the audit endpoint (at http://127.0.0.1:1/-/npm/v1/\n"
            "  security/advisories/bulk): error sending request\n",
            "returncode": 1,
        },
        "ERR_PNPM_AUDIT_BAD_RESPONSE",
    ),
    (
        "subprocess-wrapper-error",
        "package-lock.json",
        {"error": "Error running command: boom"},
        "did not run",
    ),
]


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


def _scanner(context, offline=False):
    return NpmAuditScanner(
        context=context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=offline)
        ),
    )


def _project(root, lock_name="package-lock.json"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "placeholder-app", "version": "1.0.0"}), encoding="utf-8"
    )
    (root / lock_name).write_text(
        json.dumps({"name": "placeholder-app", "lockfileVersion": 3}),
        encoding="utf-8",
    )
    return root


@pytest.fixture(autouse=True)
def tools_on_path(monkeypatch, tmp_path):
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )


def _respond(*responses):
    """_run_subprocess side effect: one response per audit, in order. The exit
    code is recorded the way the real method records it."""
    queue = list(responses)

    def _side_effect(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4", "stderr": "", "returncode": 0}
        response = queue.pop(0)
        if "returncode" in response:
            self._process_command_response(response)
        return response

    return _side_effect


@pytest.mark.parametrize(
    "lock_name, response, reason",
    [pytest.param(lock, resp, reason, id=i) for i, lock, resp, reason in FAILURES],
)
def test_a_failed_audit_raises_instead_of_reporting_clean(
    plugin_context, lock_name, response, reason
):
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir, lock_name)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(response),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert lock_name in message, message
    assert reason in message, message
    assert "\x1b[" not in message, "terminal colour codes leaked into the reason"


def test_a_real_clean_audit_still_returns_an_empty_report(plugin_context):
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(CLEAN_AUDIT, returncode=0)),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert report.runs[0].properties.model_extra["metrics"]["total"] == 0


def test_real_findings_on_exit_1_are_still_findings(plugin_context):
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(VULNERABLE_AUDIT, returncode=1)),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert [r.ruleId for r in report.runs[0].results] == ["GHSA-xvch-5gv4-984h"]


def test_pnpm_findings_on_exit_1_are_not_an_audit_failure():
    """pnpm's report has ``advisories``, not ``vulnerabilities``, and exits 1
    when there are any. That is a report, not a failure."""
    pnpm_report = {"advisories": {"1096465": {"id": 1096465}}, "metadata": {}}
    result = {"stdout": json.dumps(pnpm_report), "stderr": "", "returncode": 1}

    assert NpmAuditScanner._audit_failure("pnpm", result, pnpm_report) is None


def test_one_failed_lockfile_fails_the_scan_but_every_lockfile_is_audited(
    plugin_context,
):
    """The working lockfile is still audited, and the failed one is named."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir / "packages" / "api")
    _project(plugin_context.work_dir / "packages" / "web")
    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(CONNECTION_REFUSED), _npm(VULNERABLE_AUDIT)),
    ) as patched:
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")
        audits = [c for c in patched.call_args_list if "audit" in c.kwargs["command"]]

    assert len(audits) == 2, "the second lockfile was not audited"
    message = str(excinfo.value)
    assert "could not audit 1 lockfile(s)" in message, message
    assert "ECONNREFUSED" in message, message


def test_offline_audits_nothing_and_records_the_lockfile(plugin_context, caplog):
    """Offline, npm audit cannot reach the advisory service, so no audit runs: the
    lockfile is recorded as not audited, a warning names it, and scan() returns False,
    which the executor records MISSING."""
    scanner = _scanner(plugin_context, offline=True)
    _project(plugin_context.work_dir)

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_respond(_npm(CONNECTION_REFUSED)),
        ) as run,
        caplog.at_level(logging.WARNING),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    started = [
        call.kwargs.get("command") or call.args[1] for call in run.call_args_list
    ]
    assert [command for command in started if "audit" in command] == [], started
    assert report is False
    assert [entry["path"] for entry in scanner.inputs_not_scanned] == [
        "package-lock.json"
    ]
    assert any(
        "Offline, npm-audit audits nothing" in r.message for r in caplog.records
    ), [r.message for r in caplog.records]


def test_an_online_audit_passes_no_offline_flag(plugin_context):
    """offline is false by default and follows ASH's own mode. Online, the audit
    must ask the registry, so ``--offline`` reaches no command: npm would obey it
    by asking nothing and reporting every lockfile clean."""
    scanner = _scanner(plugin_context, offline=False)
    _project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(CLEAN_AUDIT, returncode=0)),
    ) as spawn:
        scanner.scan(target=plugin_context.work_dir, target_type="converted")

    (audit,) = [
        list(c.kwargs["command"])
        for c in spawn.call_args_list
        if "audit" in c.kwargs["command"]
    ]
    assert audit == ["npm", "audit", "--json"], audit


@pytest.mark.parametrize("binary", ["npm", "pnpm"])
def test_a_truthy_non_dict_advisories_is_no_report(binary):
    """A v1 document whose ``advisories`` is a truthy value of another type is
    what a truncated or broken tool emits. Graded as a report it would read
    as clean with zero findings; the evidence rule refuses it instead."""
    document = {"advisories": "not an advisories object", "metadata": {}}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 0}

    reason = NpmAuditScanner._audit_failure(binary, result, document)

    assert reason is not None
    assert "so no advisory was checked" in reason, reason


@pytest.mark.parametrize("binary", ["npm", "pnpm"])
def test_an_empty_advisories_with_null_metadata_is_no_report(binary):
    """``{"advisories": {}, "metadata": null}`` carries a metadata KEY and no
    counting block. Read as a report, the null metadata reaches the
    conversion; the evidence rule reads the key's value, not its presence."""
    document = {"advisories": {}, "metadata": None}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 0}

    reason = NpmAuditScanner._audit_failure(binary, result, document)

    assert reason is not None
    assert "so no advisory was checked" in reason, reason


def test_an_empty_v1_report_with_null_metadata_is_an_error_not_a_crash(
    plugin_context,
):
    """The whole scan path for the shape above: the run ends in the named
    audit failure, not in an exception from converting a null metadata."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm({"advisories": {}, "metadata": None}, returncode=0)),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert "so no advisory was checked" in str(excinfo.value), excinfo.value


def test_a_v1_report_with_advisories_is_findings_not_a_failure(plugin_context):
    """The must-not-fire for the evidence rule, and the npm-6 findings case:
    a real captured v1 document with advisories (the yarn 3 capture carries
    the npm v1 shape) scans into one finding per advisory id and module."""
    capture_path = (
        Path(__file__).resolve().parents[4]
        / "test_data"
        / "scanners"
        / "npmaudit"
        / "yarn"
        / "berry3-vuln.json"
    )
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    document = json.loads(capture["stdout"])
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(document, returncode=1)),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    expected = sorted(
        {
            (advisory["github_advisory_id"], advisory["module_name"])
            for advisory in document["advisories"].values()
        }
    )
    found = sorted(
        {
            (result.ruleId, result.properties.model_extra["package_name"])
            for result in report.runs[0].results
        }
    )
    assert found == expected


def _v1_vuln_document():
    """The yarn 3 capture's npm v1 document: 7 advisories and a metadata dict."""
    capture_path = (
        Path(__file__).resolve().parents[4]
        / "test_data"
        / "scanners"
        / "npmaudit"
        / "yarn"
        / "berry3-vuln.json"
    )
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    return json.loads(capture["stdout"])


def _advisory_pairs(document):
    return sorted(
        {
            (advisory["github_advisory_id"], advisory["module_name"])
            for advisory in document["advisories"].values()
        }
    )


def _found_pairs(report):
    return sorted(
        {
            (result.ruleId, result.properties.model_extra["package_name"])
            for result in report.runs[0].results
        }
    )


@pytest.mark.parametrize("metadata", [None, "half a report"], ids=["null", "non-dict"])
@pytest.mark.parametrize(
    "lock_name", ["package-lock.json", "pnpm-lock.yaml"], ids=["npm", "pnpm"]
)
def test_a_v1_report_with_null_metadata_converts_its_findings(
    plugin_context, lock_name, metadata
):
    """Real advisories beside ``"metadata": null`` are a report (the evidence
    rule reads the records), so the conversion must yield their findings. The
    conversion used to read ``.get("metadata", {})``, whose default fires only
    when the key is absent; a present null reached ``.get("vulnerabilities")``
    and the scan crashed, so the row went ERROR and the 7 findings were lost,
    while yarn 2/3 converted the same document. The non-dict variant pins the
    same read against any other junk value in the key."""
    document = _v1_vuln_document()
    document["metadata"] = metadata
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir, lock_name)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(document, returncode=1)),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert _found_pairs(report) == _advisory_pairs(document)


@pytest.mark.parametrize(
    "first, second",
    [
        pytest.param("null", "dict", id="null-then-dict"),
        pytest.param("dict", "null", id="dict-then-null"),
        pytest.param("string", "dict", id="string-then-dict"),
        pytest.param("dict", "string", id="dict-then-string"),
        pytest.param("list", "list", id="list-then-list"),
    ],
)
@pytest.mark.parametrize(
    "lock_name", ["package-lock.json", "pnpm-lock.yaml"], ids=["npm", "pnpm"]
)
def test_two_lockfiles_with_non_dict_metadata_merge(
    plugin_context, lock_name, first, second
):
    """Every ordering of junk and real metadata across two lockfiles merges
    into the findings both reports carry. The merge resets a non-dict value
    that was merged FIRST before reading keys into it; without the reset,
    null-then-dict crashed on the read and failed the whole scan closed."""
    source = _v1_vuln_document()
    values = {
        "null": None,
        "string": "half a report",
        "list": [1],
        "dict": source["metadata"],
    }
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir / "a", lock_name)
    _project(plugin_context.work_dir / "b", lock_name)
    first_doc = dict(source, metadata=values[first])
    second_doc = dict(source, metadata=values[second])

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(
            _npm(first_doc, returncode=1), _npm(second_doc, returncode=1)
        ),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert _found_pairs(report) == _advisory_pairs(source)


def test_a_second_lockfile_with_null_metadata_still_merges(plugin_context):
    """The merge between lockfiles reads each report's ``metadata`` as a dict
    too. With the key present and null it crashed on ``.items()``, and the
    exception graded the second, valid report as a failed audit, so the whole
    scan raised instead of reporting the findings both reports carry."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir / "a")
    _project(plugin_context.work_dir / "b")
    first = _v1_vuln_document()
    first["metadata"] = None
    second = _v1_vuln_document()
    second["metadata"] = None

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(first, returncode=1), _npm(second, returncode=1)),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert _found_pairs(report) == _advisory_pairs(first)


# ``advisories`` dicts that yield no advisory record, and the two ways a v1
# document carries no counting metadata. Together they are the no-evidence
# shapes a truncated or broken tool emits around a truthy advisories dict.
_NO_ADVISORY_OBJECTS = [
    pytest.param({"1": 5}, id="entry-not-an-object"),
    pytest.param(
        {"GHSA-xxxx-xxxx-xxxx": {"title": "no module name", "severity": "high"}},
        id="entry-without-module-name",
    ),
]
_NO_COUNTING_METADATA = [
    pytest.param({}, id="no-metadata-key"),
    pytest.param({"metadata": None}, id="null-metadata"),
]


@pytest.mark.parametrize("extra", _NO_COUNTING_METADATA)
@pytest.mark.parametrize("advisories", _NO_ADVISORY_OBJECTS)
@pytest.mark.parametrize("binary", ["npm", "pnpm"])
def test_an_advisories_object_holding_no_advisory_is_no_report(
    binary, advisories, extra
):
    """An ``advisories`` dict that yields no advisory record - entries that
    are not objects, or that name no module - beside no counting metadata is
    no evidence any dependency was checked. Graded on the dict's truthiness
    it read as a clean report with zero findings."""
    document = {"advisories": advisories, **extra}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 0}

    reason = NpmAuditScanner._audit_failure(binary, result, document)

    assert reason is not None
    assert "so no advisory was checked" in reason, reason


@pytest.mark.parametrize("extra", _NO_COUNTING_METADATA)
@pytest.mark.parametrize("advisories", _NO_ADVISORY_OBJECTS)
@pytest.mark.parametrize("yarn_major", [2, 3])
def test_a_yarn_advisories_object_holding_no_advisory_is_no_report(
    yarn_major, advisories, extra
):
    """The yarn 2/3 reader of the same v1 shape gives the same answer for the
    same no-evidence documents."""
    document = {"advisories": advisories, **extra}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 0}

    report, reason = NpmAuditScanner._parse_yarn_audit(yarn_major, result)

    assert report is None
    assert reason is not None and "so no advisory was checked" in reason, reason


@pytest.mark.parametrize("binary", ["npm", "pnpm"])
def test_one_real_advisory_counts_as_a_report_without_metadata(binary):
    """Must-not-fire for the record rule: one advisory that yields a record,
    even among junk entries and with no metadata at all, is evidence."""
    key, advisory = next(iter(_v1_vuln_document()["advisories"].items()))
    document = {"advisories": {key: advisory, "junk": 5}}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 1}

    assert NpmAuditScanner._audit_failure(binary, result, document) is None


def test_a_yarn_v1_document_with_one_real_advisory_is_a_report():
    """The yarn 2/3 twin of the must-not-fire above."""
    key, advisory = next(iter(_v1_vuln_document()["advisories"].items()))
    document = {"advisories": {key: advisory}}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(3, result)

    assert reason is None, reason
    assert report is not None


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            {"vulnerabilities": "not a vulnerabilities object"},
            id="truthy-non-dict",
        ),
        pytest.param(
            {"vulnerabilities": {}, "metadata": None}, id="empty-with-null-metadata"
        ),
    ],
)
def test_an_npm7_report_without_evidence_is_no_report(document):
    """The npm 7+ shape is held to the same bar as the v1 readers: findings
    under ``vulnerabilities`` as a dict, or the counting metadata dict. On the
    key's truthiness alone these graded as clean with zero findings."""
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 0}

    reason = NpmAuditScanner._audit_failure("npm", result, document)

    assert reason is not None
    assert "so no advisory was checked" in reason, reason


def test_an_npm7_report_with_findings_counts_without_metadata():
    """Must-not-fire for the npm 7+ bar: a findings-bearing vulnerabilities
    dict is evidence with no metadata at all."""
    document = {"vulnerabilities": {"lodash": {"severity": "high", "via": []}}}
    result = {"stdout": json.dumps(document), "stderr": "", "returncode": 1}

    assert NpmAuditScanner._audit_failure("npm", result, document) is None


# Every way a v1 document can carry no evidence around a truthy ``advisories``
# value: values of another type (with or without a counting block beside them)
# and an empty dict beside an explicit null. Each must end in the named
# audit-without-report failure through every reader, whatever the exit code.
_NO_EVIDENCE_V1_DOCUMENTS = {
    "adv-string": {"advisories": "not an advisories object", "metadata": {}},
    "adv-list": {"advisories": [1], "metadata": {}},
    "adv-int": {"advisories": 7},
    "adv-true-with-counts": {"advisories": True, "metadata": {"vulnerabilities": {}}},
    "empty-null-metadata": {"advisories": {}, "metadata": None},
}

#: yarn majors that write one npm v1 document, with the version answer that
#: routes the scan to that reader.
_YARN_V1_VERSIONS = {"yarn2": "2.4.3", "yarn3": "3.8.7"}


def _yarn_project(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "placeholder-app", "version": "1.0.0"}), encoding="utf-8"
    )
    (root / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")


def _versioned_respond(version, document, returncode):
    """_run_subprocess side effect answering ``--version`` with *version* and
    every audit with *document*, the way ``_respond`` records exit codes."""

    def _side_effect(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": f"{version}\n", "stderr": "", "returncode": 0}
        response = {
            "stdout": json.dumps(document),
            "stderr": "",
            "returncode": returncode,
        }
        self._process_command_response(response)
        return response

    return _side_effect


@pytest.mark.parametrize("returncode", [0, 1])
@pytest.mark.parametrize("shape", sorted(_NO_EVIDENCE_V1_DOCUMENTS))
@pytest.mark.parametrize("yarn", sorted(_YARN_V1_VERSIONS))
def test_a_yarn_scan_of_a_no_evidence_v1_document_is_the_named_failure(
    plugin_context, yarn, shape, returncode
):
    """Each no-evidence shape, scanned end to end through yarn 2 and yarn 3,
    ends in the named audit-without-report failure: never a clean report, and
    never a conversion crash. The exit code changes nothing, since yarn's
    audit exit is a severity bitmask, not a success signal."""
    scanner = _scanner(plugin_context)
    _yarn_project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_versioned_respond(
            _YARN_V1_VERSIONS[yarn], _NO_EVIDENCE_V1_DOCUMENTS[shape], returncode
        ),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "without an audit report" in message or "not an audit report" in message, (
        message
    )


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            {"vulnerabilities": "not a vulnerabilities object", "metadata": {}},
            id="vulns-string",
        ),
        pytest.param(
            {"vulnerabilities": {}, "metadata": None}, id="vulns-empty-null-metadata"
        ),
    ],
)
def test_an_npm7_scan_of_a_no_evidence_report_is_the_named_failure(
    plugin_context, document
):
    """The npm 7+ shapes of the same bar, end to end: a truthy non-dict
    vulnerabilities value, or an empty one beside a null metadata, is the
    named no-report failure through the whole scan, not a report or a crash."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)

    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(_npm(document, returncode=0)),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "without an audit report" in message or "not an audit report" in message, (
        message
    )


def _execute(context, scanner, response):
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    _project(context.source_dir)
    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(response),
    ):
        (container,) = executor._execute_scanner(
            "npm-audit", scanner, [{"path": context.source_dir, "type": "source"}]
        )
    return container


class TestExecutorStatus:
    """What the operator sees: ERROR for a failed audit, PASSED for a clean one."""

    def test_a_failed_audit_is_reported_as_error(self, plugin_context):
        scanner = _scanner(plugin_context)

        container = _execute(plugin_context, scanner, _npm(REGISTRY_500))

        assert container.status == ScannerStatus.ERROR
        first = container.raw_results["errors"][0]
        assert "Failed to execute npm-audit scanner on source" in first, first
        assert "500 Internal Server Error" in first, first

    def test_a_clean_audit_is_reported_as_passed(self, plugin_context):
        scanner = _scanner(plugin_context)

        container = _execute(plugin_context, scanner, _npm(CLEAN_AUDIT, returncode=0))

        assert container.status == ScannerStatus.PASSED

    def test_a_clean_npm_6_report_is_reported_as_passed(self, plugin_context):
        """npm 6 and earlier write the v1 shape - actions, advisories and the
        metadata block, no vulnerabilities key - and the SARIF converter reads
        advisories, so a clean v1 run grades PASSED, not "output that is not
        an audit report"."""
        scanner = _scanner(plugin_context)

        container = _execute(
            plugin_context, scanner, _npm(NPM6_V1_CLEAN_AUDIT, returncode=0)
        )

        assert container.status == ScannerStatus.PASSED, (
            container.status,
            _row_errors(container),
        )


#: The run's response when ASH's wait on the audit failed while it ran and ASH
#: stopped it: no exit code, post_run_error and the reason.
_ASH_STOPPED_THE_AUDIT = {
    "returncode": None,
    "post_run_error": True,
    "spawn_failed": False,
    "error": "ASH stopped the tool after: reading the output failed",
}


@pytest.mark.parametrize("binary", ["npm", "pnpm"])
def test_an_audit_ash_stopped_is_no_audit_that_did_not_run(binary):
    """The flags are read before the code: "no code and an error" with
    post_run_error set is an audit that ran and whose output ASH could not
    record, not one that did not run. And it is still a failure, not a report."""
    reason = NpmAuditScanner._audit_failure(binary, dict(_ASH_STOPPED_THE_AUDIT), None)

    assert reason, "an audit ASH stopped produced no report, so it is a failure"
    assert "did not run" not in reason, reason
    assert "reading the output failed" in reason, reason


def _timed_out_text(limit, command):
    """The error text subprocess_utils writes for a killed run, built with the
    same token production uses (timeout_limit_token: the limit quoted whole,
    then " s"), so every timeout fixture in this file carries the measured
    form and cannot drift from it."""
    from automated_security_helper.utils.error_text import timeout_limit_token

    return f"Command timed out after {timeout_limit_token(limit, ())}: {command}"


#: Audits that timed out: one ASH stopped at its timeout (124), and one the stop
#: did not end, which has no code.
_TIMED_OUT_AUDITS = [
    pytest.param(
        {
            "returncode": 124,
            "timed_out": True,
            "error": _timed_out_text(5, "npm audit"),
            "stderr": _timed_out_text(5, "npm audit"),
        },
        id="stopped-at-the-timeout",
    ),
    pytest.param(
        {
            "returncode": None,
            "timed_out": True,
            "error": _timed_out_text(5, "npm audit") + ". ASH could not stop the "
            "tool (pid 4242), which may still be running",
        },
        id="the-stop-did-not-end-it",
    ),
]


@pytest.mark.parametrize("binary", ["npm", "pnpm"])
@pytest.mark.parametrize("response", _TIMED_OUT_AUDITS)
def test_an_audit_that_timed_out_is_no_audit_that_did_not_run(binary, response):
    """A timed-out audit ran and was stopped, or could not be: it did not finish.
    Its reason says so, with the timeout's own text, never "did not run"."""
    reason = NpmAuditScanner._audit_failure(binary, dict(response), None)

    assert reason, "a timed-out audit produced no report, so it is a failure"
    assert "did not run" not in reason, reason
    assert "timed out after '5' s" in reason, reason


@pytest.mark.parametrize("yarn_major", [1, 4])
@pytest.mark.parametrize("response", _TIMED_OUT_AUDITS)
def test_a_yarn_audit_that_timed_out_is_no_audit_that_did_not_run(yarn_major, response):
    report, reason = NpmAuditScanner._parse_yarn_audit(yarn_major, dict(response))

    assert report is None, report
    assert reason, "a timed-out yarn audit produced no report, so it is a failure"
    assert "did not run" not in reason, reason
    assert "timed out after '5' s" in reason, reason


@pytest.mark.parametrize("yarn_major", [1, 4])
def test_a_yarn_audit_ash_stopped_is_no_audit_that_did_not_run(yarn_major):
    report, reason = NpmAuditScanner._parse_yarn_audit(
        yarn_major, dict(_ASH_STOPPED_THE_AUDIT)
    )

    assert report is None, report
    assert reason, "a yarn audit ASH stopped produced no report, so it is a failure"
    assert "did not run" not in reason, reason
    assert "reading the output failed" in reason, reason


def test_no_exit_code_and_no_error_is_not_called_exited_0():
    """A response with no exit code and no error text reads as a run that
    ended without one, not as a run that "exited 0": the wording must not
    claim an exit code the response does not carry."""
    reason = NpmAuditScanner._audit_failure("npm", {"returncode": None}, None)

    assert reason, "no exit code and no report is a failure"
    assert "exited 0" not in reason, reason
    assert "no exit code" in reason, reason


def test_a_yarn_reply_with_no_exit_code_is_not_called_exited_none():
    """The same wording rule on the yarn side: a reply with no exit code
    recorded is worded as that, never as the literal word None."""
    report, reason = NpmAuditScanner._parse_yarn_audit(
        3, {"stdout": "", "stderr": "", "returncode": None}
    )

    assert report is None
    assert "ended with no exit code recorded" in reason, reason
    assert "None" not in reason, reason
    assert "so no advisory was checked" in reason, reason


@pytest.mark.parametrize("yarn_major", [2, 3])
@pytest.mark.parametrize(
    "reply",
    [
        pytest.param({"stdout": "", "stderr": "", "returncode": 0}, id="empty"),
        pytest.param(
            {"stdout": '{"advisories":{}}', "stderr": "", "returncode": 0},
            id="bare-advisories-document",
        ),
    ],
)
def test_a_reply_without_evaluation_evidence_is_no_yarn_2_or_3_report(
    yarn_major, reply
):
    """yarn 2 and 3's real clean audit writes the npm v1 document with found
    advisories or the counting metadata block
    (tests/test_data/scanners/npmaudit/yarn/berry3-clean.json, yarn 3.8.7),
    and a run that cannot reach the registry exits 1 with error text. So
    nothing on stdout with exit 0, and a bare advisories document - what a
    truncated or broken tool emits, which _audit_failure grades ERROR for
    pnpm's identical shape - are no evidence any advisory was checked. The
    reason is this branch's own wording, which no other failure path writes,
    so the cell cannot be satisfied by a version probe or parse failure."""
    report, reason = NpmAuditScanner._parse_yarn_audit(yarn_major, dict(reply))

    assert report is None, report
    assert "exited 0 without an audit report, so no advisory was checked" in (
        reason or ""
    ), reason


# A value the config read from the environment can span a line yarn's parse
# loops used to drop: a blank or whitespace-only line, or one that parses as
# JSON without being an event or advisory (a number, a quoted string). The
# dropped segment broke the value's whole spelling, so the redaction over the
# rejoined problem text matched nothing and the reason printed the value's
# first line. Each fragment here is distinctive, so its absence can only come
# from redaction.
_SPANNED_SEGMENTS = [
    pytest.param("", id="a-blank-line"),
    pytest.param("   ", id="a-whitespace-line"),
    pytest.param("123", id="a-json-number-line"),
    pytest.param('"word"', id="a-json-string-line"),
    pytest.param('{"k":1}', id="a-json-object-line"),
]


@pytest.mark.parametrize("yarn_major", [1, 4])
@pytest.mark.parametrize("segment", _SPANNED_SEGMENTS)
def test_a_value_spanning_a_dropped_line_is_hidden_from_the_reason(yarn_major, segment):
    value = f"Zq7Kx9LmLeak\n{segment}\nPw4Nv2RtTail"
    stdout = f"yarn failed resolving {value} against the registry\n"

    report, reason = NpmAuditScanner._parse_yarn_audit(
        yarn_major,
        {"stdout": stdout, "stderr": "", "returncode": 1},
        values=(value,),
    )

    assert report is None, report
    # The control: the failure is still reported as yarn's.
    assert reason and "yarn audit" in reason, reason
    assert "Zq7Kx9LmLeak" not in reason, reason
    assert "Pw4Nv2RtTail" not in reason, reason


def test_the_detail_reader_hides_the_same_spanning_value_on_its_own():
    """The control that places the drop: the SAME text handed straight to the
    detail reader is hidden, because that reader keeps every non-event
    segment with its own separators before redacting. So a fragment in the
    reason can only come from the parse loop's own segment drops."""
    value = 'Zq7Kx9LmLeak\n"word"\nPw4Nv2RtTail'
    text = f"yarn failed resolving {value} against the registry\n"

    detail = NpmAuditScanner._yarn_error_detail(text, (value,))

    assert "Zq7Kx9LmLeak" not in detail, detail
    assert "Pw4Nv2RtTail" not in detail, detail


def test_a_yarn_4_report_with_a_blank_line_is_still_a_report():
    """Keeping blank segments for the redaction must not demote a real
    report: a yarn 4 advisory stream with a stray blank line between entries
    still counts its advisories, and the whitespace alone is no problem text."""
    entry = json.dumps({"value": "minimist", "children": {"ID": 1, "Severity": "high"}})
    report, reason = NpmAuditScanner._parse_yarn_audit(
        4, {"stdout": f"{entry}\n\n{entry}\n", "stderr": "", "returncode": 1}
    )

    assert reason is None, reason
    assert report is not None, report


def test_a_yarn_4_stream_event_line_does_not_demote_a_report():
    """yarn berry's StreamReport writes info and warning event lines into the
    same --json stream the advisories ride. An event is the runner narrating,
    not a problem of the audit's, so one between two advisories must not flip
    the stream into "reported an error" and drop the advisories with it."""
    entry = json.dumps({"value": "minimist", "children": {"ID": 1, "Severity": "high"}})
    event = json.dumps({"type": "info", "name": None, "data": "resolution step"})
    report, reason = NpmAuditScanner._parse_yarn_audit(
        4, {"stdout": f"{entry}\n{event}\n{entry}\n", "stderr": "", "returncode": 1}
    )

    assert reason is None, reason
    assert report is not None, report


def test_a_clean_yarn_4_run_with_an_info_event_is_still_a_report():
    """The clean-exit side of the same read: yarn 4 finding nothing exits 0,
    and an info event line on that stream is still no evidence of a problem,
    so the run keeps counting as an audit report with no findings."""
    event = json.dumps({"type": "info", "name": None, "data": "audit done"})
    report, reason = NpmAuditScanner._parse_yarn_audit(
        4, {"stdout": f"{event}\n", "stderr": "", "returncode": 0}
    )

    assert reason is None, reason
    assert report is not None, report


def test_blank_only_yarn_1_output_keeps_the_no_report_wording():
    """The other side of the same gate: nothing but whitespace on stdout is
    not "an error the tool reported", so the reason stays the no-report
    wording rather than an error wording with nothing to show."""
    report, reason = NpmAuditScanner._parse_yarn_audit(
        1, {"stdout": "\n\n", "stderr": "", "returncode": 0}
    )

    assert report is None, report
    assert "without an audit report" in (reason or ""), reason


def test_an_empty_yarn_4_reply_is_its_clean_report():
    """yarn 4 prints nothing for a clean audit and exits 0
    (tests/test_data/scanners/npmaudit/yarn/berry-clean.json, yarn 4.18.1), so
    the empty exit-0 reply is accepted as the clean report on purpose: it is
    the tool's own clean shape. A run that cannot reach the registry exits 1
    with error text, so a blocked audit does not read as clean."""
    report, reason = NpmAuditScanner._parse_yarn_audit(
        4, {"stdout": "", "stderr": "", "returncode": 0}
    )

    assert reason is None, reason
    assert report == {"yarn_advisories": [], "metadata": {"vulnerabilities": {}}}, (
        report
    )


def _execute_prepared(context, scanner, *responses):
    """The executor row for a source tree the test prepared itself, with one
    subprocess response per audit, in order."""
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    with patch.object(
        NpmAuditScanner,
        "_run_subprocess",
        autospec=True,
        side_effect=_respond(*responses),
    ):
        (container,) = executor._execute_scanner(
            "npm-audit", scanner, [{"path": context.source_dir, "type": "source"}]
        )
    return container


def _row_errors(container) -> str:
    raw = container.raw_results if isinstance(container.raw_results, dict) else {}
    return " | ".join([*(raw.get("errors") or []), *(container.errors or [])])


def _verdict(container, named: str):
    """The row's status and whether its errors name *named*, checked together so
    that neither hides the other."""
    return container.status, named in _row_errors(container)


def test_a_failures_raw_results_write_home_as_a_tilde(plugin_context):
    """The errors, exception and stack_trace a failed row records in
    raw_results are ASH-written text, not tool output, and they reach the saved
    results, so a home directory they name is written as a tilde."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.source_dir)
    home = Path.home().as_posix()

    def exploding(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4", "stderr": "", "returncode": 0}
        # A second home-naming error, recorded the way a scanner records one,
        # so the row carries more than one entry and a rewrite that stops at
        # the first is caught.
        self._plugin_log(f"skipping {home}/project/.yarnrc", level=logging.ERROR)
        # And one on the scanner's OUTPUT stream, so the rewrite is checked on
        # both streams raw_results persists, not only on errors.
        self._plugin_log(
            f"reading {home}/project/package.json", append_to_stream="stdout"
        )
        raise OSError(f"cannot read {home}/project/.npmrc")

    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    with patch.object(
        NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=exploding
    ):
        (container,) = executor._execute_scanner(
            "npm-audit",
            scanner,
            [{"path": plugin_context.source_dir, "type": "source"}],
        )

    raw = container.raw_results
    # Both fields are recorded as text before their content is checked: a row
    # that stopped recording them would otherwise pass the loop silently.
    assert isinstance(raw.get("exception"), str), raw.get("exception")
    assert isinstance(raw.get("stack_trace"), str), raw.get("stack_trace")
    # Each path is named by its own entry: some entry has the .npmrc path and a
    # DIFFERENT entry has the .yarnrc path, so a rewrite that stops at the
    # first entry is caught even if one entry happened to carry both names.
    npmrc_entries = {
        index
        for index, error in enumerate(raw["errors"])
        if "~/project/.npmrc" in error
    }
    yarnrc_entries = {
        index
        for index, error in enumerate(raw["errors"])
        if "~/project/.yarnrc" in error
    }
    assert npmrc_entries and yarnrc_entries, raw["errors"]
    assert any(
        npmrc_at != yarnrc_at
        for npmrc_at in npmrc_entries
        for yarnrc_at in yarnrc_entries
    ), raw["errors"]
    output_lines = raw.get("output") or []
    assert any("~/project/package.json" in line for line in output_lines), output_lines
    for field, text in (
        *(("errors", error) for error in raw["errors"]),
        *(("output", line) for line in output_lines),
        ("exception", raw["exception"]),
        ("stack_trace", raw["stack_trace"]),
    ):
        assert home not in text, (field, text)


#: Audit responses after which no advisory was checked against the lockfile,
#: while the exit code alone reads as a clean run.
UNEVALUATED_RESPONSES = [
    pytest.param(
        "package-lock.json",
        {"stdout": "", "stderr": "", "returncode": 0},
        id="npm-empty-stdout-exit-0",
    ),
    pytest.param(
        "package-lock.json",
        {"stdout": "<html>proxy error</html>", "stderr": "", "returncode": 0},
        id="npm-unparseable-stdout-exit-0",
    ),
    pytest.param(
        "pnpm-lock.yaml",
        {"stdout": "", "stderr": "", "returncode": 0},
        id="pnpm-empty-stdout-exit-0",
    ),
    # The tool's report key and nothing else: what a truncated or broken tool
    # emits. No finding and no metadata block shows the lockfile was evaluated.
    pytest.param(
        "package-lock.json",
        {"stdout": '{"vulnerabilities":{}}', "stderr": "", "returncode": 0},
        id="npm-bare-report-key-exit-0",
    ),
    pytest.param(
        "pnpm-lock.yaml",
        {"stdout": '{"advisories":{}}', "stderr": "", "returncode": 0},
        id="pnpm-bare-report-key-exit-0",
    ),
]


class TestATargetTheToolNeverEvaluatedIsNotClean:
    """A lockfile no advisory ran against is not a clean result, whatever the
    failure type. Every such failure grades as the endpoint errors above do:
    ERROR naming the lockfile, never PASSED. One failure type never gets a
    stricter grade than another for the same nothing-evaluated outcome."""

    @pytest.mark.parametrize("lock_name, response", UNEVALUATED_RESPONSES)
    def test_an_audit_that_evaluated_nothing_is_an_error_naming_the_lockfile(
        self, plugin_context, lock_name, response
    ):
        scanner = _scanner(plugin_context)
        _project(plugin_context.source_dir, lock_name)

        container = _execute_prepared(plugin_context, scanner, response)

        # One assertion for both, so a right grade that names nothing fails too.
        assert _verdict(container, lock_name) == (ScannerStatus.ERROR, True), (
            _row_errors(container)
        )

    def test_a_timeout_is_reported_even_when_its_partial_output_parses(
        self, plugin_context
    ):
        """A timed-out audit can leave a complete-looking document on stdout
        (the response keeps whatever the tool printed before it was stopped).
        The timeout is a cause recorded for the run, and a rendered report
        never swallows it.

        The stub answers from _run_subprocess directly, so the executor's own
        record of a timeout, made where the real _run_subprocess calls
        _record_timeout, is bypassed here: this cell turns on the scanner's
        reading of a timed-out response alone. The response carries the error
        and stderr text in the shape subprocess_utils writes for a killed run
        (``Command timed out after {quoted limit} s: {command}``, the limit
        quoted whole for redact_values); the assertion is on wording only the
        timeout branch writes, which the other branches' quotes of that text
        cannot supply."""
        scanner = _scanner(plugin_context)
        _project(plugin_context.source_dir)
        timed_out = {
            "error": _timed_out_text(1, "npm audit --json"),
            "returncode": 124,
            "timed_out": True,
            "stderr": _timed_out_text(1, "npm audit --json"),
            "stdout": json.dumps(CLEAN_AUDIT),
        }

        container = _execute_prepared(plugin_context, scanner, timed_out)

        assert _verdict(container, "timed out, so its report is incomplete") == (
            ScannerStatus.ERROR,
            True,
        ), _row_errors(container)

    def test_one_unevaluated_lockfile_refuses_a_passed_verdict(
        self, plugin_context, monkeypatch
    ):
        """One lockfile's package manager is absent and the other audits clean.
        The audited lockfile's report is kept, and the row is ERROR naming the
        lockfile whose dependencies went unchecked, never PASSED."""
        monkeypatch.setattr(
            npm_audit_scanner,
            "find_executable",
            lambda name: None if name == "yarn" else f"/usr/bin/{name}",
        )
        scanner = _scanner(plugin_context)
        _project(plugin_context.source_dir / "api", "yarn.lock")
        _project(plugin_context.source_dir / "web")

        container = _execute_prepared(
            plugin_context, scanner, _npm(CLEAN_AUDIT, returncode=0)
        )

        assert _verdict(container, "yarn.lock") == (ScannerStatus.ERROR, True), (
            _row_errors(container)
        )
        # web/package-lock.json's own audit report, written as the scan wrote it.
        written = Path(scanner.results_dir) / "source" / "results.json"
        assert json.loads(written.read_text(encoding="utf-8")) == CLEAN_AUDIT

    def test_the_control_a_run_whose_every_lockfile_evaluates_is_passed(
        self, plugin_context
    ):
        scanner = _scanner(plugin_context)
        _project(plugin_context.source_dir / "api")
        _project(plugin_context.source_dir / "web")

        container = _execute_prepared(
            plugin_context,
            scanner,
            _npm(CLEAN_AUDIT, returncode=0),
            _npm(CLEAN_AUDIT, returncode=0),
        )

        assert container.status == ScannerStatus.PASSED, (
            container.status,
            container.errors,
        )

    def test_a_yarn_3_audit_that_evaluated_nothing_is_an_error_naming_the_lockfile(
        self, plugin_context
    ):
        """The yarn arm of the rows above: yarn 3's clean audit prints a
        document (berry3-clean.json), so an empty exit-0 reply left the
        lockfile unchecked, and the row grades as the npm and pnpm
        evaluated-nothing rows do. The stand-in answers the version question
        the yarn flow asks before it audits. The assertion pins the no-report
        branch's own wording behind the lockfile prefix, so a version probe,
        an offline refusal, a parse failure or a setup exception - every one
        of which also prefixes the lockfile - cannot satisfy this cell."""
        scanner = _scanner(plugin_context)
        _project(plugin_context.source_dir, "yarn.lock")
        audit = {"stdout": "", "stderr": "", "returncode": 0}

        def tool(scanner_self, command, **kwargs):
            if "--version" in command:
                return {"stdout": "3.8.7\n", "stderr": "", "returncode": 0}
            scanner_self._process_command_response(audit)
            return audit

        executor = ScannerExecutor(
            plugin_context=plugin_context,
            progress_display=MagicMock(),
            scanner_tasks=[],
        )
        with patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=tool
        ):
            (container,) = executor._execute_scanner(
                "npm-audit",
                scanner,
                [{"path": plugin_context.source_dir, "type": "source"}],
            )

        assert _verdict(
            container,
            "yarn.lock: yarn audit exited 0 without an audit report, "
            "so no advisory was checked",
        ) == (ScannerStatus.ERROR, True), _row_errors(container)


def test_an_audit_failures_excerpt_hides_a_value_straddling_its_cut():
    """npm's stderr is redacted BEFORE the excerpt's 300-character cut.

    The filler puts the cut inside the value: cut first, the detail would
    keep the fragment ``EDGE-S``, which the downstream whole-spelling
    redaction cannot match.
    """
    value = "EDGE-SECRET-5519"
    result = {
        "returncode": 1,
        "stderr": "npm ERR! " + "n" * 285 + value + " tail",
        "stdout": "",
    }

    reason = NpmAuditScanner._audit_failure("npm", result, None, [value])

    assert reason is not None and "exited 1" in reason, reason
    assert value not in reason, reason
    assert "EDGE-S" not in reason, reason


def test_a_yarn_version_probe_excerpt_hides_a_value_straddling_its_cut(
    plugin_context,
):
    """`yarn --version` output is redacted BEFORE the 80-character cut.

    The 72 filler characters put the cut inside the value: cut first, the
    failure line would keep the fragment ``EDGE-SEC``, which the downstream
    whole-spelling redaction cannot match.
    """
    value = "EDGE-SECRET-2213"
    scanner = _scanner(plugin_context)
    _yarn_project(plugin_context.work_dir)

    def _version_only(self, command, **kwargs):
        if "--version" in command:
            return {
                "stdout": "v" * 72 + value + " tail\n",
                "stderr": "",
                "returncode": 0,
            }
        raise AssertionError("the audit must not run without a yarn version")

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_version_only,
        ),
        patch.object(
            NpmAuditScanner,
            "_values_to_redact",
            autospec=True,
            side_effect=lambda self: (value,),
        ),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "could not tell which yarn" in message, message
    assert value not in message, message
    assert "EDGE-SEC" not in message, message


def test_a_bare_string_values_answer_is_hidden_whole_in_the_yarn_probe_text(
    plugin_context,
):
    """_values_to_redact is an overridable hook. A bare string it answers is ONE
    value, not its characters: split into characters, each one is shorter than
    any band the redaction replaces, so the probe excerpt printed the value."""
    value = "tool-qz4b9secret"
    scanner = _scanner(plugin_context)
    _yarn_project(plugin_context.work_dir)

    def _version_only(self, command, **kwargs):
        if "--version" in command:
            return {
                "stdout": "not a version: " + value + " tail\n",
                "stderr": "",
                "returncode": 0,
            }
        raise AssertionError("the audit must not run without a yarn version")

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_version_only,
        ),
        patch.object(
            NpmAuditScanner,
            "_values_to_redact",
            autospec=True,
            side_effect=lambda self: value,
        ),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "could not tell which yarn" in message, message
    assert "not a version" in message, "the cell must show the excerpt: " + message
    assert value not in message, message


# A value that itself holds a complete escape sequence strips to a short word
# (4 to 7 characters), which the redaction matches only at word boundaries. So
# the value must be matched as written, in its own band, wherever it is read.
_ESC = "\x1b"
_CODE_HOLDING_VALUES = {
    "four-char-word-in-sgr": (_ESC + "[31m" + "zumq" + _ESC + "[0m", "zumq"),
    "six-char-word-in-sgr": (_ESC + "[31m" + "dovrek" + _ESC + "[0m", "dovrek"),
    "seven-char-word-then-csi": ("beltrax" + _ESC + "[K", "beltrax"),
}


@pytest.mark.parametrize("shape", sorted(_CODE_HOLDING_VALUES))
def test_a_glued_code_holding_value_in_a_raw_code_error_event_is_hidden(shape):
    """The NDJSON error event takes its message from the line as written when
    that line parses (a raw control character inside a JSON string parses
    non-strictly), so the value is matched in its as-written spelling and its
    glued stripped spelling does not print."""
    value, visible = _CODE_HOLDING_VALUES[shape]
    line = '{"type":"error","data":"token=zz' + value + 'zz end"}\n'

    detail = NpmAuditScanner._yarn_error_detail(line, [value])

    assert "token=zz" in detail, "the cell must show the message: " + repr(detail)
    assert visible not in detail, repr(detail)
    assert _ESC not in detail, repr(detail)


@pytest.mark.parametrize("shape", sorted(_CODE_HOLDING_VALUES))
def test_a_glued_code_holding_value_in_an_encoded_error_event_is_hidden(shape):
    """The control: a conformant writer encodes the control as \\u001b, which
    decodes to the as-written spelling."""
    value, visible = _CODE_HOLDING_VALUES[shape]
    line = json.dumps({"type": "error", "data": "token=zz" + value + "zz end"}) + "\n"
    assert "\\u001b" in line

    detail = NpmAuditScanner._yarn_error_detail(line, [value])

    assert "token=zz" in detail, "the cell must show the message: " + repr(detail)
    assert visible not in detail, repr(detail)
    assert _ESC not in detail, repr(detail)


@pytest.mark.parametrize("shape", sorted(_CODE_HOLDING_VALUES))
def test_a_glued_code_holding_value_in_a_plain_yarn_line_is_hidden(shape):
    """The control: the plain-text arm keeps the as-written spelling."""
    value, visible = _CODE_HOLDING_VALUES[shape]

    detail = NpmAuditScanner._yarn_error_detail(
        "error token=zz" + value + "zz end\n", [value]
    )

    assert "token=zz" in detail, "the cell must show the message: " + repr(detail)
    assert visible not in detail, repr(detail)
    assert _ESC not in detail, repr(detail)


def test_a_colored_error_event_line_is_still_read_as_an_event():
    """The control for the fallback: a line whose JSON is wrapped in color
    codes does not parse as written, so it is read from its stripped form."""
    line = _ESC + '[31m{"type":"error","data":"registry unreachable"}' + _ESC + "[0m\n"

    detail = NpmAuditScanner._yarn_error_detail(line, ["unrelated-secret"])

    assert detail == "registry unreachable", repr(detail)


def test_a_non_color_escape_inside_a_value_does_not_split_the_match():
    """The value layer strips only color codes itself, so a non-color escape
    inside a value ("EDGE\\x1b[KSECRET...") split the match, and the later
    whole-escape strip re-joined the value in clear in the detail. Every
    escape is stripped BEFORE the redaction now."""
    value = "EDGESECRET-9912"
    result = {
        "returncode": 1,
        "stderr": "npm ERR! saw EDGE\x1b[KSECRET-9912 in its config",
        "stdout": "",
    }

    reason = NpmAuditScanner._audit_failure("npm", result, None, [value])

    assert reason is not None and "exited 1" in reason, reason
    assert value not in reason, reason
    assert "\x1b" not in reason, repr(reason)


def test_a_yarn_error_details_cuts_see_only_redacted_text():
    """yarn's error event is redacted BEFORE the 200-character message cut.

    The filler puts the cut inside the value: cut first, the detail would
    keep the fragment ``EDGE-SECRET-5``, which the downstream whole-spelling
    redaction cannot match.
    """
    value = "EDGE-SECRET-5519"
    event = json.dumps(
        {"type": "error", "data": "Error: " + "d" * 180 + value + " tail"}
    )

    detail = NpmAuditScanner._yarn_error_detail(event, [value])

    assert detail, "the error event's message is kept"
    assert value not in detail, detail
    assert "EDGE-SECRET-5" not in detail, detail


@pytest.mark.parametrize("value", ["error", "data"])
def test_a_value_colliding_with_a_json_word_keeps_yarns_error(value):
    """The redaction must not run before the NDJSON parse: an env-read value
    that is also a JSON key or event-type word ("error" from a log-level
    variable, "data") then rewrites ``{"type":"error","data":...}`` before
    ``json.loads`` reads it, the event stops looking like an error, and
    yarn 1's only error message is dropped -- the reason falls back to
    "exited 1 without an audit report". The structural read comes first, on
    the raw line; the redaction sees each extracted message before the cuts."""
    event = json.dumps(
        {"type": "error", "data": "Request failed https://registry.example.com/pkg"}
    )

    detail = NpmAuditScanner._yarn_error_detail(event, [value])

    assert "Request failed" in detail, detail


def test_the_audit_failure_stderr_excerpt_hides_a_multi_line_value():
    """The stderr excerpt is redacted BEFORE its lines are split and the 300-
    character cut is taken: splitting first leaves each half of a value with
    its own line break unmatched, and both halves print in the reason."""
    value = "Zq7Kx9Lm\r\nPw4Nv2Rt"
    result = {
        "returncode": 1,
        "stdout": "",
        "stderr": f"npm ERR! request to {value}/registry failed\n",
    }

    reason = NpmAuditScanner._audit_failure("npm", result, {}, (value,))

    assert reason is not None and "without an audit report" in reason, reason
    for part in ("Zq7Kx9Lm", "Pw4Nv2Rt"):
        assert part not in reason, (part, reason)


def _raising_values_hook(self):
    raise RuntimeError("the plugin's values hook failed")


def test_a_raising_values_hook_drops_the_yarn_probe_excerpts(plugin_context):
    """When the overridable values hook raises, the scan has no value set to
    redact with. The yarn probe text must drop its tool excerpts rather than
    show them with an empty value set, which would print what the values
    would have hidden."""
    scanner = _scanner(plugin_context)
    _yarn_project(plugin_context.work_dir)

    def _version_only(self, command, **kwargs):
        if "--version" in command:
            return {
                "stdout": "not a version: stdout-marker-7731 tail\n",
                "stderr": "yarn error stderr-marker-7731 failed\n",
                "returncode": 0,
            }
        raise AssertionError("the audit must not run without a yarn version")

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_version_only,
        ),
        patch.object(
            NpmAuditScanner,
            "_values_to_redact",
            autospec=True,
            side_effect=_raising_values_hook,
        ),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "could not tell which yarn" in message, message
    assert "(not shown)" in message, message
    assert "stdout-marker-7731" not in message, message
    assert "stderr-marker-7731" not in message, message


def test_a_raising_values_hook_drops_the_npm_audit_failure_excerpt(plugin_context):
    """The npm audit-failure text names the exit code and drops its stderr
    excerpt when the values hook raised."""
    scanner = _scanner(plugin_context)
    _project(plugin_context.work_dir)
    failed = {
        "stdout": "",
        "stderr": "npm ERR! request to stderr-marker-5290 failed\n",
        "returncode": 1,
    }

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_respond(failed),
        ),
        patch.object(
            NpmAuditScanner,
            "_values_to_redact",
            autospec=True,
            side_effect=_raising_values_hook,
        ),
    ):
        with pytest.raises(ScannerError) as excinfo:
            scanner.scan(target=plugin_context.work_dir, target_type="converted")

    message = str(excinfo.value)
    assert "exited 1 without an audit report" in message, message
    assert "stderr-marker-5290" not in message, message


def test_an_error_event_holding_a_bare_control_character_is_read_as_an_event():
    """A raw TAB inside a JSON string is invalid under strict parsing but
    parses non-strictly. The event is read as written with the lenient parse,
    so its data is the message; a strict read of the as-written line would
    fail it, and stripping codes would not repair it (a TAB is no escape
    sequence), leaving the JSON line to print as plain text."""
    line = '{"type":"error","data":"left\tright failed"}\n'

    detail = NpmAuditScanner._yarn_error_detail(line, ["unrelated-secret"])

    assert detail == "left\tright failed", repr(detail)
    assert "type" not in detail, repr(detail)
    assert "{" not in detail, repr(detail)


def test_a_color_wrapped_line_with_a_bare_control_character_is_plain_text():
    """The stripped form of a color-wrapped line is read strictly. The line
    does not start with a brace as written, so only its stripped form is
    tried, and a raw TAB inside that JSON string fails the strict parse:
    the line is no event and prints as the plain text it is. A lenient read
    of the stripped form would turn it into an error event and print only
    its data."""
    line = _ESC + '[31m{"type":"error","data":"left\tright failed"}' + _ESC + "[0m\n"

    detail = NpmAuditScanner._yarn_error_detail(line, ["unrelated-secret"])

    assert detail == '{"type":"error","data":"left\tright failed"}', repr(detail)
    assert _ESC not in detail, repr(detail)
