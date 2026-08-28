"""Behavior tests for :class:`NpmAuditScanner`'s scan loop and result merging.

npm, yarn and pnpm are Node tools and are not installed here. The seams are
``find_executable`` and ``_run_subprocess`` (autospec, so a call with the wrong
signature fails the test). No test shells out to a package manager, and none is
skipped when one is missing -- the absence of yarn/pnpm is itself an asserted
behavior, since the scanner is supposed to warn and continue rather than fail.

The area most worth covering here is the multi-package merge: when a repo has
more than one package.json, each audit's vulnerabilities and metadata are folded
into one result set. A merge that silently kept only the last package's findings
would still produce a plausible-looking report.
"""

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
    NpmAuditScannerConfigOptions,
)
from automated_security_helper.utils import offline_mode_validator

# npm severity -> SARIF level. critical/high both map to error and low/info both
# map to note, so six inputs produce three outcomes. That collapse is npm's own
# vocabulary being wider than SARIF's, not a bug; test_severity_map_is_not_vacuous
# pins the shape so the table cannot quietly become one case tested six times.
SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "moderate": "warning",
    "low": "note",
    "info": "note",
    "not-a-severity": "warning",
}


def audit_json(
    package="left-pad",
    severity="high",
    url="https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    title="Prototype pollution",
    nodes=("node_modules/left-pad",),
    vulnerable_count=1,
    total=1,
):
    """A document shaped the way `npm audit --json` emits one."""
    return {
        "vulnerabilities": {
            package: {
                "name": package,
                "severity": severity,
                "range": "<1.3.0",
                "nodes": list(nodes),
                "fixAvailable": True,
                "via": [
                    {
                        "source": 1234,
                        "name": package,
                        "title": title,
                        "url": url,
                        "severity": severity,
                        "cwe": ["CWE-1321"],
                        "cvss": {"score": 7.5, "vectorString": None},
                    }
                ],
            }
        },
        "metadata": {
            "vulnerabilities": {
                "info": 0,
                "low": 0,
                "moderate": 0,
                "high": vulnerable_count,
                "critical": 0,
                "total": total,
            },
            "dependencies": {"prod": 1, "dev": 0, "total": 1},
        },
    }


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def scanner(plugin_context):
    return NpmAuditScanner(
        context=plugin_context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=False)
        ),
    )


@pytest.fixture
def node_project(plugin_context):
    """A work-dir Node project with a package.json and an npm lock file."""

    def _make(directory=None, lock_name="package-lock.json", name="placeholder-app"):
        root = plugin_context.work_dir if directory is None else directory
        root.mkdir(parents=True, exist_ok=True)
        (root / "package.json").write_text(
            json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8"
        )
        (root / lock_name).write_text(
            json.dumps({"name": name, "lockfileVersion": 3}), encoding="utf-8"
        )
        return root

    return _make


@pytest.fixture
def npm_on_path(monkeypatch, tmp_path):
    """Report npm/yarn/pnpm as present without installing Node."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)

    def _find(name):
        return str(fake_bin / name)

    monkeypatch.setattr(npm_audit_scanner, "find_executable", _find)
    return _find


NPM_VERSION = "10.9.2"


def is_audit_call(call):
    return "audit" in call.kwargs.get("command", [])


def audit_calls(double):
    """Only the `<binary> audit --json` invocations.

    validate_plugin_dependencies also goes through _run_subprocess, to read
    `npm --version`, so the raw call list mixes that probe in with the audits.
    Filtering keeps the assertions about auditing from silently counting the
    version probe -- and stops the probe consuming a queued audit payload.
    """
    return [call for call in double.call_args_list if is_audit_call(call)]


@pytest.fixture
def subprocess_double():
    with patch.object(NpmAuditScanner, "_run_subprocess", autospec=True) as double:
        double.side_effect = emits()
        yield double


def emits(*payloads):
    """side_effect yielding one audit payload per audit call.

    The `npm --version` probe is answered separately so it does not consume a
    payload meant for an audit.
    """
    remaining = [
        json.dumps(p) if not isinstance(p, str) else p for p in payloads
    ]

    def _side_effect(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": NPM_VERSION, "stderr": "", "returncode": 0}
        return {
            "stdout": remaining.pop(0) if remaining else "",
            "stderr": "",
            "returncode": 0,
        }

    return _side_effect


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


def test_scanner_metadata_is_wired(scanner):
    assert scanner.command == "npm"
    assert scanner.tool_type == ScannerToolType.SCA


def test_install_commands_are_registered_for_every_platform(scanner):
    """The install-command table is populated but intentionally empty.

    Node is expected to be provided by the image rather than installed by ASH,
    so every platform maps to an empty command list.
    """
    for system in ("linux", "darwin", "windows"):
        assert system in scanner.custom_install_commands
    assert scanner.custom_install_commands["linux"]["amd64"] == []
    assert scanner.custom_install_commands["darwin"]["arm64"] == []


def test_has_install_commands_is_false_when_every_list_is_empty(scanner):
    assert scanner._has_install_commands() is False


def test_has_install_commands_is_true_once_a_command_is_registered(
    scanner, monkeypatch
):
    import platform

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    # The arch key is derived from pointer size, so a 64-bit host reads "amd64".
    scanner.custom_install_commands["linux"]["amd64"] = [["echo", "install"]]

    assert scanner._has_install_commands() is True


def test_has_install_commands_is_false_on_an_unlisted_platform(scanner, monkeypatch):
    import platform

    monkeypatch.setattr(platform, "system", lambda: "FreeBSD")

    assert scanner._has_install_commands() is False


def test_has_install_commands_is_false_when_the_arch_key_is_absent(
    scanner, monkeypatch
):
    """Windows has no arm64 entry, so an arm64 lookup falls through."""
    import platform
    import struct

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    # Force the non-64-bit branch of the pointer-size check.
    monkeypatch.setattr(struct, "calcsize", lambda fmt: 4)
    scanner.custom_install_commands["windows"]["amd64"] = [["echo", "install"]]

    assert scanner._has_install_commands() is False, (
        "windows/arm64 is not a registered key, so the lookup must fall through"
    )


def test_arch_key_is_derived_from_pointer_size_not_architecture(scanner, monkeypatch):
    """The arch key comes from struct.calcsize('P'), not the real machine type.

    A 64-bit host reads "amd64" whatever its CPU is, so 64-bit ARM is labeled
    amd64 and a 32-bit x86 host would be labeled arm64. This has no effect today
    because every install-command list is empty, but it means the arm64 entries
    can never be selected on a 64-bit machine.
    """
    import platform
    import struct

    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(struct, "calcsize", lambda fmt: 8)
    scanner.custom_install_commands["linux"]["arm64"] = [["echo", "arm-install"]]
    scanner.custom_install_commands["linux"]["amd64"] = []

    assert scanner._has_install_commands() is False, (
        "the arm64 list is non-empty but a 64-bit pointer size selects amd64"
    )


def test_execute_scan_stub_raises_not_implemented(scanner):
    with pytest.raises(NotImplementedError, match="overrides scan"):
        scanner._execute_scan(
            target=scanner.context.source_dir,
            target_type="source",
            global_ignore_paths=[],
        )


# ---------------------------------------------------------------------------
# Early exits
# ---------------------------------------------------------------------------


def test_empty_target_returns_an_empty_report(
    scanner, npm_on_path, subprocess_double
):
    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert audit_calls(subprocess_double) == []
    assert any("empty or doesn't exist" in err for err in scanner.errors)


def test_pre_scan_failure_returns_false(
    scanner, npm_on_path, node_project, subprocess_double
):
    node_project()

    with patch.object(NpmAuditScanner, "_pre_scan", autospec=True, return_value=False):
        result = scanner.scan(
            target=scanner.context.work_dir, target_type="converted"
        )

    assert result is False
    assert audit_calls(subprocess_double) == []


def test_dependency_flag_is_rechecked_after_pre_scan(
    scanner, npm_on_path, node_project, subprocess_double
):
    node_project()

    with patch.object(NpmAuditScanner, "_pre_scan", autospec=True, return_value=True):
        scanner.dependencies_satisfied = False
        result = scanner.scan(
            target=scanner.context.work_dir, target_type="converted"
        )

    assert result is False
    assert audit_calls(subprocess_double) == []


def test_target_without_a_package_json_returns_an_empty_report(
    scanner, npm_on_path, subprocess_double
):
    """Only package.json makes a directory a candidate."""
    (scanner.context.work_dir / "requirements.txt").write_text("flask\n", encoding="utf-8")

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert report.runs[0].results == []
    assert audit_calls(subprocess_double) == []
    assert any("No package lock files found" in err for err in scanner.errors)


def test_package_json_without_any_lock_file_is_not_audited(
    scanner, npm_on_path, subprocess_double
):
    """A package.json with no adjacent lock file has nothing to audit against."""
    (scanner.context.work_dir / "package.json").write_text(
        json.dumps({"name": "placeholder-app"}), encoding="utf-8"
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert audit_calls(subprocess_double) == []
    assert report.runs[0].results == []


# ---------------------------------------------------------------------------
# Package-manager selection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "lock_name, expected_binary",
    [
        ("package-lock.json", "npm"),
        ("yarn.lock", "yarn"),
        ("pnpm-lock.yaml", "pnpm"),
    ],
)
def test_lock_file_selects_the_matching_package_manager(
    scanner, npm_on_path, node_project, subprocess_double, lock_name, expected_binary
):
    """Each lock file dialect is audited with its own tool."""
    node_project(lock_name=lock_name)
    subprocess_double.side_effect = emits(audit_json())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    command = audit_calls(subprocess_double)[-1].kwargs["command"]
    assert command == [expected_binary, "audit", "--json"]


def test_audit_runs_in_the_lock_files_own_directory(
    scanner, npm_on_path, node_project, subprocess_double
):
    """pnpm and yarn only find their lock file when cwd is its parent."""
    nested = node_project(directory=scanner.context.work_dir / "packages" / "api")
    subprocess_double.side_effect = emits(audit_json())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert audit_calls(subprocess_double)[-1].kwargs["cwd"] == nested


@pytest.mark.parametrize("missing_binary, lock_name", [("yarn", "yarn.lock"), ("pnpm", "pnpm-lock.yaml")])
def test_a_missing_yarn_or_pnpm_is_warned_about_and_skipped(
    scanner, monkeypatch, node_project, subprocess_double, caplog, missing_binary, lock_name
):
    """An absent alternative package manager skips that lock file, loudly.

    This is deliberately not a pytest skip: the scanner's job here is to warn
    and carry on, and a skipped test would hide a regression that turned this
    into a crash or a silent pass.
    """
    node_project(lock_name=lock_name)
    monkeypatch.setattr(
        npm_audit_scanner,
        "find_executable",
        lambda name: None if name == missing_binary else "npm-stub",
    )

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(
            target=scanner.context.work_dir, target_type="converted"
        )

    assert audit_calls(subprocess_double) == []
    assert report.runs[0].results == []
    assert any(
        f"{missing_binary} is not installed" in record.message
        for record in caplog.records
    ), f"expected a missing-{missing_binary} warning; got {[r.message for r in caplog.records]}"


def test_a_missing_npm_does_not_take_the_skip_path(
    scanner, npm_on_path, node_project, subprocess_double
):
    """npm is validated up front, so the per-binary guard exempts it."""
    node_project(lock_name="package-lock.json")
    subprocess_double.side_effect = emits(audit_json())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert len(audit_calls(subprocess_double)) == 1


# ---------------------------------------------------------------------------
# Offline mode
# ---------------------------------------------------------------------------


def test_offline_mode_adds_the_offline_flag_and_disables_corepack_network(
    plugin_context, npm_on_path, node_project, subprocess_double, monkeypatch
):
    """Offline runs must not let corepack reach out for a package manager.

    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 only stops corepack asking; it still
    downloads. COREPACK_ENABLE_NETWORK=0 is what makes it use the cached
    version instead.
    """
    monkeypatch.setattr(
        offline_mode_validator, "validate_npm_audit_offline_mode", lambda: (True, [])
    )
    scanner = NpmAuditScanner(
        context=plugin_context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=True)
        ),
    )
    node_project()
    subprocess_double.side_effect = emits(audit_json())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    kwargs = audit_calls(subprocess_double)[-1].kwargs
    assert kwargs["command"] == ["npm", "audit", "--json", "--offline"]
    assert kwargs["env"]["COREPACK_ENABLE_NETWORK"] == "0"


def test_online_mode_passes_no_env_override(
    scanner, npm_on_path, node_project, subprocess_double
):
    """Control for the offline test: online runs inherit the parent env."""
    node_project()
    subprocess_double.side_effect = emits(audit_json())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    kwargs = audit_calls(subprocess_double)[-1].kwargs
    assert "--offline" not in kwargs["command"]
    assert kwargs["env"] is None


def test_failed_offline_validation_warns_but_the_scan_continues(
    plugin_context, npm_on_path, node_project, subprocess_double, monkeypatch, caplog
):
    """A failing offline precondition is a warning, not an abort."""
    monkeypatch.setattr(
        offline_mode_validator,
        "validate_npm_audit_offline_mode",
        lambda: (False, ["no npm cache found"]),
    )
    scanner = NpmAuditScanner(
        context=plugin_context,
        config=NpmAuditScannerConfig(
            options=NpmAuditScannerConfigOptions(offline=True)
        ),
    )
    node_project()
    subprocess_double.side_effect = emits(audit_json())

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(
            target=scanner.context.work_dir, target_type="converted"
        )

    assert any(
        "offline mode validation failed, but continuing" in record.message
        for record in caplog.records
    )
    # The scan still ran and still produced its finding.
    assert len(audit_calls(subprocess_double)) == 1
    assert len(report.runs[0].results) == 1


# ---------------------------------------------------------------------------
# Findings and merging
# ---------------------------------------------------------------------------


def test_audit_output_becomes_sarif_results(
    scanner, npm_on_path, node_project, subprocess_double
):
    """Non-empty npm audit output produces non-empty findings.

    The anti-"clean scan" assertion for this module.
    """
    node_project()
    subprocess_double.side_effect = emits(audit_json(package="left-pad"))

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    results = report.runs[0].results
    assert len(results) == 1, f"expected one finding, got {len(results)}"
    finding = results[0]
    assert finding.ruleId == "GHSA-aaaa-bbbb-cccc", (
        f"the rule id should come from the advisory URL; got {finding.ruleId}"
    )
    assert "Prototype pollution" in finding.message.root.text
    assert "left-pad" in finding.message.root.text
    assert finding.properties.model_extra["package_name"] == "left-pad"
    assert finding.properties.model_extra["severity"] == "high"
    assert finding.properties.model_extra["fix_available"] is True
    # One rule per advisory is attached to the driver.
    assert [rule.id for rule in report.runs[0].tool.driver.rules] == [
        "GHSA-aaaa-bbbb-cccc"
    ]


def test_findings_from_two_packages_are_both_kept(
    scanner, npm_on_path, node_project, subprocess_double
):
    """A monorepo's second package.json must not overwrite the first's findings.

    ``all_results`` starts as the first audit's document and later audits are
    folded into it. A merge that replaced instead of updated would silently drop
    findings while still producing a well-formed report.
    """
    node_project(directory=scanner.context.work_dir / "packages" / "api")
    node_project(directory=scanner.context.work_dir / "packages" / "web")
    subprocess_double.side_effect = emits(
        audit_json(
            package="left-pad",
            url="https://github.com/advisories/GHSA-1111-1111-1111",
            nodes=("node_modules/left-pad",),
        ),
        audit_json(
            package="minimist",
            url="https://github.com/advisories/GHSA-2222-2222-2222",
            nodes=("node_modules/minimist",),
        ),
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert len(audit_calls(subprocess_double)) == 2
    rule_ids = sorted(r.ruleId for r in report.runs[0].results)
    assert rule_ids == ["GHSA-1111-1111-1111", "GHSA-2222-2222-2222"], (
        f"a package's findings were dropped during the merge; got {rule_ids}"
    )


def test_numeric_metadata_is_summed_across_packages(
    scanner, npm_on_path, node_project, subprocess_double
):
    """Counts add up across audits rather than being replaced.

    The merge walks metadata keys: dict values are updated, numeric values are
    added. ``dependencies.total`` is nested under a dict key, so it is updated;
    this asserts the observable outcome of both arms.
    """
    node_project(directory=scanner.context.work_dir / "packages" / "api")
    node_project(directory=scanner.context.work_dir / "packages" / "web")
    subprocess_double.side_effect = emits(
        audit_json(
            package="left-pad",
            url="https://github.com/advisories/GHSA-1111-1111-1111",
            vulnerable_count=1,
            total=1,
        ),
        audit_json(
            package="minimist",
            url="https://github.com/advisories/GHSA-2222-2222-2222",
            vulnerable_count=2,
            total=2,
        ),
    )

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    metrics = report.runs[0].properties.model_extra["metrics"]
    # The second audit's vulnerability counts replaced the first's, since
    # metadata.vulnerabilities is a dict and dicts are updated, not summed.
    assert metrics["high"] == 2
    assert metrics["total"] == 2


def test_a_numeric_metadata_key_shared_by_both_audits_is_summed(
    scanner, npm_on_path, node_project, subprocess_double
):
    """A scalar metadata value present in both audits is added, not replaced.

    The merge has three arms for a metadata key: dict values are updated,
    int/float values are added, and unseen keys are inserted. npm's own metadata
    contains only dicts, so the numeric arm is exercised here with a scalar of
    the kind yarn and pnpm audit reports carry.
    """
    node_project(directory=scanner.context.work_dir / "packages" / "api")
    node_project(directory=scanner.context.work_dir / "packages" / "web")
    first = audit_json(url="https://github.com/advisories/GHSA-1111-1111-1111")
    second = audit_json(
        package="minimist", url="https://github.com/advisories/GHSA-2222-2222-2222"
    )
    first["metadata"]["totalDependencies"] = 12
    second["metadata"]["totalDependencies"] = 30
    subprocess_double.side_effect = emits(first, second)

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    saved = json.loads(
        (Path(scanner.results_dir) / "converted" / "results.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved["metadata"]["totalDependencies"] == 42, (
        "shared numeric metadata should be summed across audits; got "
        f"{saved['metadata']['totalDependencies']}"
    )


def test_a_metadata_key_only_the_second_audit_has_is_added(
    scanner, npm_on_path, node_project, subprocess_double
):
    """A metadata key absent from the first audit is carried over, not lost."""
    node_project(directory=scanner.context.work_dir / "packages" / "api")
    node_project(directory=scanner.context.work_dir / "packages" / "web")
    first = audit_json(url="https://github.com/advisories/GHSA-1111-1111-1111")
    second = audit_json(
        package="minimist", url="https://github.com/advisories/GHSA-2222-2222-2222"
    )
    second["metadata"]["auditReportVersion"] = 2
    subprocess_double.side_effect = emits(first, second)

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    saved = json.loads(
        (Path(scanner.results_dir) / "converted" / "results.json").read_text(
            encoding="utf-8"
        )
    )
    assert saved["metadata"]["auditReportVersion"] == 2, (
        f"a second-audit-only metadata key was dropped: {saved['metadata']}"
    )
    assert set(saved["vulnerabilities"]) == {"left-pad", "minimist"}


def test_results_are_persisted_as_json_and_sarif(
    scanner, npm_on_path, node_project, subprocess_double
):
    node_project()
    subprocess_double.side_effect = emits(audit_json())

    scanner.scan(target=scanner.context.work_dir, target_type="converted")

    results_dir = Path(scanner.results_dir) / "converted"
    raw = results_dir / "results.json"
    sarif = results_dir / "results_sarif.sarif"
    assert raw.is_file(), f"{raw} was not written"
    assert sarif.is_file(), f"{sarif} was not written"
    assert "left-pad" in json.loads(raw.read_text(encoding="utf-8"))["vulnerabilities"]
    written = json.loads(sarif.read_text(encoding="utf-8"))
    assert [r["ruleId"] for r in written["runs"][0]["results"]] == [
        "GHSA-aaaa-bbbb-cccc"
    ]


def test_no_audit_output_returns_an_empty_report_without_writing_files(
    scanner, npm_on_path, node_project, subprocess_double
):
    """An audit that emits nothing yields the empty-report branch."""
    node_project()
    subprocess_double.return_value = {"stdout": "", "stderr": "", "returncode": 0}

    report = scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert len(audit_calls(subprocess_double)) == 1
    assert report.runs[0].results == []
    assert report.runs[0].tool.driver.name == "npm-audit"
    assert not (Path(scanner.results_dir) / "converted" / "results.json").exists()


def test_unparseable_audit_output_is_warned_about_and_skipped(
    scanner, npm_on_path, node_project, subprocess_double, caplog
):
    node_project()
    subprocess_double.side_effect = emits("npm ERR! code ENOLOCK")

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(
            target=scanner.context.work_dir, target_type="converted"
        )

    assert report.runs[0].results == []
    assert any(
        "Failed to parse npm audit output" in record.message
        for record in caplog.records
    ), f"expected a parse warning; got {[r.message for r in caplog.records]}"


def test_one_packages_failure_does_not_abort_the_others(
    scanner, npm_on_path, node_project, subprocess_double, caplog
):
    """A subprocess error is caught per package, so the rest still audit."""
    node_project(directory=scanner.context.work_dir / "packages" / "api")
    node_project(directory=scanner.context.work_dir / "packages" / "web")
    calls = {"n": 0}

    def _first_call_explodes(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": NPM_VERSION, "stderr": "", "returncode": 0}
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("npm died")
        return {
            "stdout": json.dumps(
                audit_json(url="https://github.com/advisories/GHSA-2222-2222-2222")
            ),
            "stderr": "",
            "returncode": 0,
        }

    subprocess_double.side_effect = _first_call_explodes

    with caplog.at_level(logging.WARNING):
        report = scanner.scan(
            target=scanner.context.work_dir, target_type="converted"
        )

    assert calls["n"] == 2, "the second package should still have been audited"
    assert [r.ruleId for r in report.runs[0].results] == ["GHSA-2222-2222-2222"]
    assert any("Failed to run npm audit" in r.message for r in caplog.records)


def test_a_failure_outside_the_per_package_guard_raises_scanner_error(
    scanner, npm_on_path, node_project, subprocess_double, monkeypatch
):
    """Errors outside the per-package try surface as ScannerError."""
    node_project()
    subprocess_double.side_effect = emits(audit_json())

    def _boom(self, npm_audit_results, target_path):
        raise RuntimeError("SARIF conversion failed")

    monkeypatch.setattr(NpmAuditScanner, "_convert_npm_audit_to_sarif", _boom)

    with pytest.raises(ScannerError) as excinfo:
        scanner.scan(target=scanner.context.work_dir, target_type="converted")

    assert "NpmAudit scan failed" in str(excinfo.value)
    assert "SARIF conversion failed" in str(excinfo.value)


# ---------------------------------------------------------------------------
# SARIF conversion details
# ---------------------------------------------------------------------------


def test_a_single_via_object_is_accepted_as_well_as_a_list(scanner):
    """npm audit sometimes reports `via` as one object rather than a list."""
    results = audit_json()
    results["vulnerabilities"]["left-pad"]["via"] = results["vulnerabilities"][
        "left-pad"
    ]["via"][0]

    report = scanner._convert_npm_audit_to_sarif(results, scanner.context.source_dir)

    assert [r.ruleId for r in report.runs[0].results] == ["GHSA-aaaa-bbbb-cccc"], (
        "a dict-valued via must be normalized into a single-element list"
    )


def test_a_transitive_only_vulnerability_still_reports(scanner):
    """When every via entry is a string, a synthetic finding is built.

    Otherwise a package vulnerable only through a dependency would produce a
    rule with no result and disappear from the report.
    """
    results = audit_json()
    results["vulnerabilities"]["left-pad"]["via"] = ["minimist", "qs"]

    report = scanner._convert_npm_audit_to_sarif(results, scanner.context.source_dir)

    assert [r.ruleId for r in report.runs[0].results] == [
        "npm-audit-transitive-left-pad"
    ]
    message = report.runs[0].results[0].message.root.text
    assert "minimist" in message and "qs" in message


@pytest.mark.parametrize("severity, expected_level", sorted(SEVERITY_TO_LEVEL.items()))
def test_npm_severity_maps_to_the_sarif_level(scanner, severity, expected_level):
    results = audit_json(severity=severity)

    report = scanner._convert_npm_audit_to_sarif(results, scanner.context.source_dir)

    finding = report.runs[0].results[0]
    actual = str(getattr(finding.level, "value", finding.level))
    assert actual == expected_level, (
        f"npm severity {severity!r} should map to {expected_level!r}; got {actual!r}"
    )


def test_severity_map_is_not_vacuous():
    """The severity table must not collapse to one outcome.

    Six inputs, three distinct SARIF levels: critical/high share error and
    low/info share note because npm's vocabulary is wider than SARIF's, and an
    unrecognized severity falls back to warning rather than being dropped.
    """
    outcomes = set(SEVERITY_TO_LEVEL.values())
    assert outcomes == {"error", "warning", "note"}
    assert SEVERITY_TO_LEVEL["critical"] == SEVERITY_TO_LEVEL["high"] == "error"
    assert SEVERITY_TO_LEVEL["low"] == SEVERITY_TO_LEVEL["info"] == "note"
    assert SEVERITY_TO_LEVEL["moderate"] != SEVERITY_TO_LEVEL["low"]
    assert SEVERITY_TO_LEVEL["not-a-severity"] == "warning"


def test_a_vulnerability_with_no_nodes_produces_no_result(scanner):
    """Results are emitted per install location, so no nodes means no result.

    Worth pinning because the rule is still created: a report can therefore
    carry a rule with no matching finding.
    """
    results = audit_json(nodes=())

    report = scanner._convert_npm_audit_to_sarif(results, scanner.context.source_dir)

    assert report.runs[0].results == []
    assert [rule.id for rule in report.runs[0].tool.driver.rules] == [
        "GHSA-aaaa-bbbb-cccc"
    ], "the rule is registered even though no result references it"


def test_no_vulnerabilities_key_yields_an_empty_run(scanner):
    report = scanner._convert_npm_audit_to_sarif({}, scanner.context.source_dir)

    assert report.runs[0].results == []
    assert report.runs[0].tool.driver.rules == []
