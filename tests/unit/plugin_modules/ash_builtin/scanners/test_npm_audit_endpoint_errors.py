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


def test_offline_keeps_its_existing_behaviour(plugin_context, caplog):
    """Offline, an unreachable advisory source is expected and the scan goes on
    as before; the warning says which lockfile was not audited."""
    scanner = _scanner(plugin_context, offline=True)
    _project(plugin_context.work_dir)

    with (
        patch.object(
            NpmAuditScanner,
            "_run_subprocess",
            autospec=True,
            side_effect=_respond(_npm(CONNECTION_REFUSED)),
        ),
        caplog.at_level(logging.WARNING),
    ):
        report = scanner.scan(target=plugin_context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert any(
        "npm-audit (offline) could not audit 1 lockfile(s)" in r.message
        for r in caplog.records
    ), [r.message for r in caplog.records]


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
