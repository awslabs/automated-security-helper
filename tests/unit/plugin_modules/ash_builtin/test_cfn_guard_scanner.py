# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-guard scanner: rule selection, result normalization, exit codes, defaults.

The SARIF parsed here is real cfn-guard 3.2.1 output against the registry's
``wa-Security-Pillar.guard`` (aws-guard-rules-registry 1.0.2), captured from the
fixture repository with the repository bind-mounted at ``/srv`` so no host path is
recorded in the file::

    unshare -rm sh -c 'mount --bind tests/test_data/scanners/cfn_lint_guard/repo /srv &&
      cfn-guard validate --rules=<rules>/wa-Security-Pillar.guard \
        --data=/srv/templates/insecure.yaml --output-format=sarif --structured \
        --show-summary=none' > captured/cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif
    # exit 19; the compliant template gives exit 0 and no results

That is also why the captured URIs read ``srv/templates/insecure.yaml``: cfn-guard
writes the absolute path minus its leading ``/``, which is what the scanner replaces.

``cfn-guard-3.2.1-wa-Security-Pillar-and-cis-aws-benchmark-level-1-insecure.sarif`` is
the same command with a second ``--rules=<rules>/cis-aws-benchmark-level-1.guard``
(exit 19): two rule sets that share rules.
"""

from __future__ import annotations

import collections
import hashlib
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
    DEFAULT_RULE_SET,
    VIOLATION_LEVEL,
    VIOLATION_SEVERITY,
    CfnGuardScanner,
    CfnGuardScannerConfig,
    CfnGuardScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import rules_bundles
from automated_security_helper.utils.rules_bundles import (
    MANIFEST_NAME,
    RULES_DIR_ENV,
    RulesBundleUnavailable,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX
from automated_security_helper.utils.tool_downloads import get_rules_bundle

pytestmark = pytest.mark.unit

FIXTURES = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "cfn_lint_guard"
)
CAPTURED_INSECURE = (
    FIXTURES / "captured" / "cfn-guard-3.2.1-wa-Security-Pillar-insecure.sarif"
)
CAPTURED_COMPLIANT = (
    FIXTURES / "captured" / "cfn-guard-3.2.1-wa-Security-Pillar-compliant.sarif"
)
CAPTURED_OVERLAPPING_SETS = (
    FIXTURES
    / "captured"
    / "cfn-guard-3.2.1-wa-Security-Pillar-and-cis-aws-benchmark-level-1-insecure.sarif"
)

#: The captured insecure run, as (rule id, start line) -> number of results: 24 in
#: all. Counted from the raw captured JSON with a separate ``json.load`` rather than
#: through the scanner. The S3 rules report on the bucket's Properties (line 9) and
#: LAMBDA_INSIDE_VPC on the function's (line 13). cfn-guard emits one result per
#: failing clause, which is why most rules appear more than once.
EXPECTED_INSECURE = collections.Counter(
    {
        ("LAMBDA_INSIDE_VPC", 13): 2,
        ("S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED", 9): 5,
        ("S3_BUCKET_LOGGING_ENABLED", 9): 1,
        ("S3_BUCKET_PUBLIC_READ_PROHIBITED", 9): 5,
        ("S3_BUCKET_PUBLIC_WRITE_PROHIBITED", 9): 5,
        ("S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED", 9): 2,
        ("S3_BUCKET_VERSIONING_ENABLED", 9): 2,
        ("S3_DEFAULT_ENCRYPTION_KMS", 9): 2,
    }
)


def _observed(results, uri="templates/insecure.yaml") -> collections.Counter:
    counts = collections.Counter()
    for result in results:
        physical = result.locations[0].physicalLocation.root
        assert physical.artifactLocation.uri == uri
        # Literals, not the module's constants: a changed mapping must fail here.
        assert getattr(result.level, "value", result.level) == "error"
        assert result.properties.issue_severity == "HIGH"
        counts[(result.ruleId, physical.region.startLine)] += 1
    return counts


def _load(path: Path) -> SarifReport:
    return SarifReport.model_validate(json.loads(path.read_text(encoding="utf-8")))


#: The rule files ``_fake_bundle`` installs, and the pin the ``rules_root`` fixture
#: gives the scanner for them: the real pin with these files' contents digest.
_FAKE_RULES = {
    name: f"rule {name.split('.')[0].replace('-', '_')} {{ }}\n".encode()
    for name in ("wa-Security-Pillar.guard", "custom-set.guard")
}
_FAKE_PIN = replace(
    get_rules_bundle("aws-guard-rules-registry"),
    contents_sha256=rules_bundles.contents_digest(
        {name: hashlib.sha256(data).hexdigest() for name, data in _FAKE_RULES.items()}
    ),
)


def _fake_bundle(root: Path):
    """An installed bundle under ``root`` holding ``_FAKE_RULES``, as installed."""
    directory = root / rules_bundles.bundle_dir_name(_FAKE_PIN)
    directory.mkdir(parents=True)
    files = {}
    for name, data in _FAKE_RULES.items():
        path = directory / name
        path.write_bytes(data)
        files[name] = rules_bundles._sha256(path)
    (directory / MANIFEST_NAME).write_text(
        json.dumps(rules_bundles._manifest_for(_FAKE_PIN, files))
    )
    return directory


@pytest.fixture
def repo(ash_temp_path) -> Path:
    target = ash_temp_path / "repo"
    shutil.copytree(FIXTURES / "repo", target)
    return target


def _cfn_guard_on_path():
    """cfn-guard found, whether or not this host has one."""
    return patch(
        "automated_security_helper.plugin_modules.ash_builtin.scanners."
        "cfn_guard_scanner.find_executable",
        return_value="/usr/local/bin/cfn-guard",
    )


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


@pytest.fixture
def rules_root(ash_temp_path, monkeypatch) -> Path:
    """The rules root, with the scanner pinned to ``_fake_bundle``'s contents."""
    root = ash_temp_path / "rules"
    monkeypatch.setenv(RULES_DIR_ENV, str(root))
    monkeypatch.setattr(
        "automated_security_helper.plugin_modules.ash_builtin.scanners."
        "cfn_guard_scanner.get_rules_bundle",
        lambda name: _FAKE_PIN,
    )
    return root


def _scanner(repo: Path, *, operator: bool = True, **options) -> CfnGuardScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnGuardScanner(
        context=context,
        config=CfnGuardScannerConfig(
            enabled=True, options=CfnGuardScannerConfigOptions(**options)
        ),
    )


class TestNormalization:
    def test_captured_output_parses_to_the_expected_findings(self):
        results = CfnGuardScanner.normalize_results(
            _load(CAPTURED_INSECURE), "templates/insecure.yaml"
        )
        assert _observed(results) == EXPECTED_INSECURE

    def test_the_host_path_cfn_guard_writes_is_replaced(self):
        raw = CAPTURED_INSECURE.read_text()
        assert '"uri": "srv/templates/insecure.yaml"' in raw  # what cfn-guard wrote
        results = CfnGuardScanner.normalize_results(
            _load(CAPTURED_INSECURE), "templates/insecure.yaml"
        )
        assert {
            r.locations[0].physicalLocation.root.artifactLocation.uri for r in results
        } == {"templates/insecure.yaml"}

    def test_compliant_template_has_no_findings(self):
        assert CfnGuardScanner.normalize_results(_load(CAPTURED_COMPLIANT), "x") == []

    @pytest.mark.parametrize("field", ["ruleId", "startLine", "drop"])
    def test_negative_control_a_mutated_finding_fails_the_assertion(self, field):
        raw = json.loads(CAPTURED_INSECURE.read_text())
        results = raw["runs"][0]["results"]
        target = next(r for r in results if r["ruleId"] == "LAMBDA_INSIDE_VPC")
        if field == "ruleId":
            target["ruleId"] = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
        elif field == "startLine":
            target["locations"][0]["physicalLocation"]["region"]["startLine"] = 14
        else:
            results.remove(target)
        normalized = CfnGuardScanner.normalize_results(
            SarifReport.model_validate(raw), "templates/insecure.yaml"
        )
        assert _observed(normalized) != EXPECTED_INSECURE

    def test_a_rule_in_two_selected_rule_sets_is_reported_once(self):
        """The registry's rule sets share rules, and cfn-guard reports a shared
        rule's results once per set that holds it, identically.

        Counted from the raw capture with a separate ``json.load``: 42 results,
        29 distinct. The 24 wa-Security-Pillar gives alone are all among them, and
        cis-aws-benchmark-level-1 adds 5 of its own.
        """
        raw = json.loads(CAPTURED_OVERLAPPING_SETS.read_text())["runs"][0]["results"]
        distinct = {json.dumps(r, sort_keys=True) for r in raw}
        assert (len(raw), len(distinct)) == (42, 29)  # the control

        def finding(ruleId, message, region):
            return (ruleId, message, region["startLine"], region["startColumn"])

        expected = {
            finding(
                r["ruleId"],
                r["message"]["text"],
                r["locations"][0]["physicalLocation"]["region"],
            )
            for r in raw
        }
        assert len(expected) == 29

        results = CfnGuardScanner.normalize_results(
            _load(CAPTURED_OVERLAPPING_SETS), "templates/insecure.yaml"
        )

        assert len(results) == 29
        observed = [
            finding(
                r.ruleId,
                r.message.root.text,
                r.locations[0].physicalLocation.root.region.model_dump(),
            )
            for r in results
        ]
        assert set(observed) == expected
        # The single-set capture still parses to exactly its own findings.
        single = CfnGuardScanner.normalize_results(
            _load(CAPTURED_INSECURE), "templates/insecure.yaml"
        )
        assert _observed(single) == EXPECTED_INSECURE

    @pytest.mark.parametrize("field", ["ruleId", "message", "startLine", "startColumn"])
    def test_results_that_differ_in_any_field_are_never_merged(self, field):
        """A copy of a result that differs in one field is another finding.

        One rule's results for different failing clauses share the rule and the
        location and differ only in their message, which is why the captured run
        has five S3_BUCKET_PUBLIC_READ_PROHIBITED results at line 9.
        """
        raw = json.loads(CAPTURED_INSECURE.read_text())
        results = raw["runs"][0]["results"]
        twin = json.loads(json.dumps(results[0]))
        region = twin["locations"][0]["physicalLocation"]["region"]
        if field == "ruleId":
            twin["ruleId"] = "ANOTHER_RULE"
        elif field == "message":
            twin["message"]["text"] += " (another clause)"
        else:
            region[field] += 1
        results.append(twin)
        exact = json.loads(json.dumps(results[1]))
        results.append(exact)

        normalized = CfnGuardScanner.normalize_results(
            SarifReport.model_validate(raw), "templates/insecure.yaml"
        )

        # 24 captured, plus the twin; the exact copy of another result is dropped.
        assert len(normalized) == 25


class TestParseResponse:
    def _stdout(self, path=CAPTURED_INSECURE):
        return path.read_text()

    def test_exit_19_with_results_is_a_completed_run(self):
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 19, "stdout": self._stdout(), "stderr": ""}, values=()
        )
        assert failure is None and report.runs[0].results

    def test_exit_0_with_no_results_is_a_completed_run(self):
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 0, "stdout": self._stdout(CAPTURED_COMPLIANT), "stderr": ""},
            values=(),
        )
        assert failure is None and not report.runs[0].results

    def test_the_redaction_values_are_required(self):
        """A default of "redact nothing" let a caller that forgot the values print
        the stderr unredacted; the parameter is keyword-only with no default."""
        with pytest.raises(TypeError):
            CfnGuardScanner._parse_response({"returncode": 0, "stdout": "{}"})  # type: ignore[call-arg]

    @pytest.mark.parametrize(
        "response, reason",
        [
            # Measured: an unparseable data file or a missing rules path.
            (
                {
                    "returncode": 255,
                    "stdout": "",
                    "stderr": "Error occurred Parser Error",
                },
                "exited 255: Error occurred Parser Error",
            ),
            ({"returncode": 19, "stdout": "", "stderr": ""}, "without writing SARIF"),
            ({"returncode": 0, "stdout": "{not json", "stderr": ""}, "not valid SARIF"),
            ({"returncode": -9, "timed_out": True}, "timed out"),
            ({"error": "No such file"}, "could not be started"),
        ],
    )
    def test_failures_are_named(self, response, reason):
        failure, report = CfnGuardScanner._parse_response(response, values=())
        assert report is None and reason in failure

    def test_a_failing_exit_with_no_results_is_not_read_as_clean(self):
        failure, _ = CfnGuardScanner._parse_response(
            {
                "returncode": 19,
                "stdout": self._stdout(CAPTURED_COMPLIANT),
                "stderr": "",
            },
            values=(),
        )
        assert "no results" in failure

    def test_a_failing_exits_stderr_is_redacted_before_it_is_cut(self):
        """The value straddles the excerpt's cut (the first quarter of 500 characters
        ends inside it), so a redaction of the excerpt would see neither half of it;
        redacting the whole text first leaves nothing of it in the message."""
        value = "probe-value-that-must-not-print"
        stderr = "a" * 110 + value + "b" * 600
        failure, report = CfnGuardScanner._parse_response(
            {"returncode": 1, "stdout": "", "stderr": stderr}, values=(value,)
        )
        assert report is None and "cfn-guard exited 1" in failure
        assert value not in failure
        assert "probe-value" not in failure and "not-print" not in failure

    def test_unreadable_redaction_values_withhold_the_stderr(self):
        failure, _ = CfnGuardScanner._parse_response(
            {"returncode": 1, "stdout": "", "stderr": "secret-looking text"},
            values=None,
        )
        assert "secret-looking" not in failure
        assert "withheld" in failure


class TestRuleSelection:
    def test_default_rule_set_is_the_security_pillar(self):
        assert DEFAULT_RULE_SET == "wa-Security-Pillar"
        assert CfnGuardScannerConfigOptions().rule_sets == ["wa-Security-Pillar"]

    def test_default_resolves_to_the_verified_bundle_file(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        assert _scanner(repo).rule_files() == [directory / "wa-Security-Pillar.guard"]

    def test_missing_bundle_names_the_remedy(self, repo, rules_root):
        with pytest.raises(
            RulesBundleUnavailable, match="ash dependencies install --tool cfn-guard"
        ):
            _scanner(repo).rule_files()

    def test_an_unknown_rule_set_lists_what_is_available(self, repo, rules_root):
        _fake_bundle(rules_root)
        with pytest.raises(RulesBundleUnavailable, match="Available: custom-set.guard"):
            _scanner(repo, rule_sets=["no-such-set"]).rule_files()

    def test_a_modified_rules_file_is_refused(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        (directory / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            _scanner(repo).rule_files()

    def test_a_modified_rules_file_the_scan_does_not_select_is_refused(
        self, repo, rules_root
    ):
        directory = _fake_bundle(rules_root)
        (directory / "custom-set.guard").write_text("rule weakened { }\n")
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            _scanner(repo).rule_files()

    def test_an_added_rules_file_cannot_be_selected(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        (directory / "added.guard").write_text("rule added { }\n")
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            _scanner(repo, rule_sets=["added"]).rule_files()

    def test_an_edited_rule_with_a_rewritten_manifest_is_refused(
        self, repo, rules_root
    ):
        directory = _fake_bundle(rules_root)
        (directory / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
        manifest = json.loads((directory / MANIFEST_NAME).read_text())
        manifest["files"]["wa-Security-Pillar.guard"] = rules_bundles._sha256(
            directory / "wa-Security-Pillar.guard"
        )
        (directory / MANIFEST_NAME).write_text(json.dumps(manifest))
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            _scanner(repo).rule_files()

    def test_the_manifest_plays_no_part_in_the_check(self, repo, rules_root):
        """A manifest naming another archive does not refuse pinned files, and a
        missing one does not either: only the rule files are compared."""
        directory = _fake_bundle(rules_root)
        manifest = json.loads((directory / MANIFEST_NAME).read_text())
        manifest["sha256"] = "0" * 64
        (directory / MANIFEST_NAME).write_text(json.dumps(manifest))
        assert _scanner(repo).rule_files() == [directory / "wa-Security-Pillar.guard"]
        (directory / MANIFEST_NAME).unlink()
        assert _scanner(repo).rule_files() == [directory / "wa-Security-Pillar.guard"]

    def test_the_real_pin_refuses_the_fake_bundle(self, repo, rules_root, monkeypatch):
        """The fixture's pin is what lets ``_fake_bundle`` pass; the real one is
        the registry's 50 files and does not."""
        _fake_bundle(rules_root)
        monkeypatch.setattr(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner.get_rules_bundle",
            get_rules_bundle,
        )
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            _scanner(repo).rule_files()

    def test_own_rules_paths_are_resolved_against_the_source(self, repo, rules_root):
        (repo / "policy").mkdir()
        (repo / "policy" / "mine.guard").write_text("rule mine { }\n")
        scanner = _scanner(repo, rule_sets=[], rules_paths=["policy"])
        assert scanner.rule_files() == [repo / "policy" / "mine.guard"]

    @pytest.mark.parametrize("where", ["outside", "inside", "directory"])
    def test_rules_paths_from_the_scanned_tree_are_not_used(
        self, repo, rules_root, ash_temp_path, caplog, where
    ):
        """cfn-guard echoes a rules file it cannot parse, so a path the scanned
        repository chose could put any readable file into the report. With
        rule_sets emptied as well, the scan falls back to the default set instead
        of evaluating nothing."""
        directory = _fake_bundle(rules_root)
        if where == "outside":
            not_a_rule = ash_temp_path / "elsewhere" / "notes.txt"
            not_a_rule.parent.mkdir()
        elif where == "inside":
            not_a_rule = repo / "policy.guard"
        else:
            not_a_rule = repo / "policy" / "leak.guard"
            not_a_rule.parent.mkdir()
        not_a_rule.write_text("this line is not a rule\n")
        named = not_a_rule.parent if where == "directory" else not_a_rule
        scanner = _scanner(repo, operator=False, rule_sets=[], rules_paths=[str(named)])
        with caplog.at_level("WARNING"):
            assert scanner.rule_files() == [directory / "wa-Security-Pillar.guard"]
        assert "Ignoring scanners.cfn-guard.options.rules_paths entry" in caplog.text
        assert f"ASH's default rule set, {DEFAULT_RULE_SET}" in caplog.text

    def test_each_rules_warning_is_logged_once_per_scanner(
        self, repo, rules_root, caplog
    ):
        """The rules are selected for the dependency check and again per target."""
        _fake_bundle(rules_root)
        (repo / "policy.guard").write_text("rule mine { }\n")
        scanner = _scanner(
            repo, operator=False, rule_sets=[], rules_paths=["policy.guard"]
        )
        with caplog.at_level("WARNING"):
            for _ in range(3):
                scanner.rule_files()
        assert caplog.text.count("Ignoring scanners.cfn-guard.options.rules_paths") == 1
        assert caplog.text.count("ASH's default rule set") == 1

    @pytest.mark.parametrize("with_rules_paths", [False, True])
    def test_rule_sets_from_the_scanned_tree_are_ignored(
        self, repo, rules_root, caplog, with_rules_paths
    ):
        """A narrower set drops findings: wa-Reliability-Pillar alone turned 24
        findings on the fixture into 9, losing every S3 public-access, encryption
        and logging one. From the scanned tree, rule_sets is ignored with a
        warning and the default set runs."""
        directory = _fake_bundle(rules_root)
        options = {"rule_sets": ["custom-set"]}
        if with_rules_paths:
            (repo / "policy.guard").write_text("rule mine { }\n")
            options["rules_paths"] = ["policy.guard"]
        scanner = _scanner(repo, operator=False, **options)
        with caplog.at_level("WARNING"):
            assert scanner.rule_files() == [directory / "wa-Security-Pillar.guard"]
        assert "Ignoring scanners.cfn-guard.options.rule_sets" in caplog.text
        assert f"ASH's default rule set, {DEFAULT_RULE_SET}" in caplog.text

    def test_rule_sets_set_by_the_operator_are_used(self, repo, rules_root):
        directory = _fake_bundle(rules_root)
        scanner = _scanner(repo, operator=True, rule_sets=["custom-set"])
        assert scanner.rule_files() == [directory / "custom-set.guard"]

    def test_an_operator_rules_directory_is_read_as_cfn_guard_reads_one(
        self, repo, rules_root, ash_temp_path
    ):
        """.guard and .ruleset files at any depth, case-sensitively, and a link
        that stays inside the directory; measured against cfn-guard 3.2.1."""
        mine = ash_temp_path / "operator-rules"
        (mine / "sub").mkdir(parents=True)
        (mine / "a.guard").write_text("rule a { }\n")
        (mine / "sub" / "b.ruleset").write_text("rule b { }\n")
        (mine / "notes.txt").write_text("not a rule\n")
        (mine / "UPPER.GUARD").write_text("rule upper { }\n")
        _symlink_or_skip(mine / "same.guard", Path("a.guard"))
        scanner = _scanner(repo, rule_sets=[], rules_paths=[str(mine)])
        assert scanner.rule_files() == [
            mine.resolve() / "a.guard",
            mine.resolve() / "same.guard",
            mine.resolve() / "sub" / "b.ruleset",
        ]

    @pytest.mark.parametrize("link_to", ["file", "directory-file"])
    def test_a_rules_file_that_leaves_the_operator_directory_is_refused(
        self, repo, rules_root, ash_temp_path, caplog, link_to
    ):
        """cfn-guard follows a symlinked .guard in a rules directory and prints a
        target it cannot parse, so the link would put that file in the report."""
        not_a_rule = ash_temp_path / "elsewhere" / "notes.txt"
        not_a_rule.parent.mkdir()
        not_a_rule.write_text("this line is not a rule\n")
        mine = ash_temp_path / "operator-rules"
        mine.mkdir()
        (mine / "mine.guard").write_text("rule mine { }\n")
        if link_to == "file":
            _symlink_or_skip(mine / "leak.guard", not_a_rule)
        else:
            (mine / "nested").mkdir()
            _symlink_or_skip(
                mine / "nested" / "leak.guard",
                Path("..") / ".." / "elsewhere" / "notes.txt",
            )
        scanner = _scanner(repo, rule_sets=[], rules_paths=[str(mine)])
        with caplog.at_level("WARNING"):
            assert scanner.rule_files() == [mine.resolve() / "mine.guard"]
        assert "leak.guard" in caplog.text
        assert "resolves outside the rules directory" in caplog.text

    def test_operator_rules_paths_outside_the_tree_are_used(
        self, repo, rules_root, ash_temp_path
    ):
        mine = ash_temp_path / "operator" / "mine.guard"
        mine.parent.mkdir()
        mine.write_text("rule mine { }\n")
        scanner = _scanner(repo, rule_sets=[], rules_paths=[str(mine)])
        assert scanner.rule_files() == [mine.resolve()]

    @pytest.mark.parametrize("named", ["file", "directory", "parent-directory"])
    def test_an_operator_rules_path_in_the_tree_cannot_link_out_of_it(
        self, repo, rules_root, tmp_path, named
    ):
        """The operator may name rules inside the scanned tree, but the tree
        decides what is at that path. cfn-guard prints a rules file it cannot
        parse, whole, so a link there to a file outside the tree would put that
        file in the report (measured with 3.2.1 in a full scan: the file's
        content reached ash.sarif and ash.log). Such a path is MISSING."""
        # tmp_path, not ash_temp_path: the repo fixture lives inside this checkout,
        # which counts as the scanned tree.
        not_a_rule = tmp_path / "elsewhere" / "notes.txt"
        not_a_rule.parent.mkdir()
        not_a_rule.write_text("this line is not a rule\n")
        if named == "file":
            _symlink_or_skip(repo / "policy.guard", not_a_rule)
            value = "policy.guard"
        else:
            outside = tmp_path / "elsewhere" / "rules"
            outside.mkdir()
            (outside / "plain.guard").write_text(not_a_rule.read_text())
            _symlink_or_skip(repo / "policy", outside)
            value = "policy" if named == "directory" else "policy/plain.guard"
        scanner = _scanner(repo, rule_sets=[], rules_paths=[value])
        with pytest.raises(RulesBundleUnavailable, match="outside the scanned tree"):
            scanner.rule_files()
        with _cfn_guard_on_path():
            assert scanner.validate_plugin_dependencies() is False
        assert value in scanner.dependency_unavailable_reason

    def test_a_link_swapped_in_after_the_check_is_refused_when_read(
        self, repo, rules_root, tmp_path
    ):
        """The check above runs before the file is read. A rules file inside the
        tree is read under the tree's root, so a link swapped in between is
        refused when the file is opened, rather than followed."""
        not_a_rule = tmp_path / "elsewhere" / "notes.txt"
        not_a_rule.parent.mkdir()
        not_a_rule.write_text("this line is not a rule\n")
        named = repo / "policy.guard"
        named.write_text("rule mine { }\n")

        def check_then_swap(*_args):
            named.unlink()
            _symlink_or_skip(named, not_a_rule)
            return False

        scanner = _scanner(repo, rule_sets=[], rules_paths=["policy.guard"])
        with (
            patch(
                "automated_security_helper.utils.config_trust."
                "leaves_the_tree_through_a_link",
                side_effect=check_then_swap,
            ),
            pytest.raises(RulesBundleUnavailable, match="cannot be used"),
        ):
            scanner.rule_files()

    def test_an_operator_rules_path_in_the_tree_may_link_inside_it(
        self, repo, rules_root
    ):
        (repo / "policy").mkdir()
        (repo / "policy" / "real.guard").write_text("rule real { }\n")
        _symlink_or_skip(repo / "current.guard", Path("policy") / "real.guard")
        scanner = _scanner(repo, rule_sets=[], rules_paths=["current.guard"])
        (rule,) = scanner._selected_rules()
        assert rule.path == (repo / "policy" / "real.guard").resolve()
        assert rule.content == "rule real { }\n"

    def test_a_named_operator_file_outside_the_tree_may_link_anywhere(
        self, repo, rules_root, tmp_path
    ):
        """Outside the scanned tree the operator controls the path, so a named
        file is read where its link leads, even out of its own directory."""
        target = tmp_path / "shared" / "team.guard"
        target.parent.mkdir()
        target.write_text("rule team { }\n")
        link = tmp_path / "operator" / "rules.guard"
        link.parent.mkdir()
        _symlink_or_skip(link, target)
        scanner = _scanner(repo, rule_sets=[], rules_paths=[str(link)])
        (rule,) = scanner._selected_rules()
        assert rule.path == target.resolve()
        assert rule.content == "rule team { }\n"

    @pytest.mark.parametrize("written", ["relative", "absolute"])
    def test_a_path_that_leaves_the_tree_by_dot_dot_is_not_a_link_out(
        self, rules_root, tmp_path, written
    ):
        """``../team.guard`` from the source directory names a file next to the
        tree. No link in the tree is followed, so the tree did not choose it."""
        # tmp_path, not ash_temp_path, which is inside this checkout.
        repo = tmp_path / "repo"
        shutil.copytree(FIXTURES / "repo", repo)
        team = tmp_path / "team.guard"
        team.write_text("rule team { }\n")
        value = "../team.guard" if written == "relative" else f"{repo}/../team.guard"
        scanner = _scanner(repo, rule_sets=[], rules_paths=[value])
        (rule,) = scanner._selected_rules()
        assert rule.path == team.resolve()

    def test_a_symlinked_subdirectory_is_not_walked(
        self, repo, rules_root, ash_temp_path
    ):
        """As cfn-guard walks a rules directory: a linked subdirectory is not
        entered, even one that stays inside, so no rule is read twice."""
        mine = ash_temp_path / "operator-rules"
        (mine / "real").mkdir(parents=True)
        (mine / "real" / "a.guard").write_text("rule a { }\n")
        _symlink_or_skip(mine / "alias", Path("real"))
        scanner = _scanner(repo, rule_sets=[], rules_paths=[str(mine)])
        assert scanner.rule_files() == [mine.resolve() / "real" / "a.guard"]

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
        reason="needs a directory this user cannot list",
    )
    def test_a_subdirectory_that_cannot_be_listed_fails_closed(
        self, repo, rules_root, ash_temp_path
    ):
        """Its rules would otherwise be dropped without a word."""
        mine = ash_temp_path / "operator-rules"
        (mine / "locked").mkdir(parents=True)
        (mine / "a.guard").write_text("rule a { }\n")
        (mine / "locked" / "b.guard").write_text("rule b { }\n")
        (mine / "locked").chmod(0)
        try:
            scanner = _scanner(repo, rule_sets=[], rules_paths=[str(mine)])
            with pytest.raises(RulesBundleUnavailable, match="could not be read"):
                scanner.rule_files()
        finally:
            (mine / "locked").chmod(0o755)

    def test_own_rules_paths_that_do_not_exist_are_refused(self, repo, rules_root):
        with pytest.raises(RulesBundleUnavailable, match="does not exist"):
            _scanner(repo, rule_sets=[], rules_paths=["policy"]).rule_files()

    def test_selecting_nothing_is_refused(self, repo, rules_root):
        with pytest.raises(
            RulesBundleUnavailable, match="no cfn-guard rules are selected"
        ):
            _scanner(repo, rule_sets=[]).rule_files()

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a FIFO")
    def test_a_named_rules_file_that_is_not_a_regular_file_is_missing(
        self, repo, rules_root, ash_temp_path
    ):
        """A FIFO would hang cfn-guard; the scanner is MISSING with the reason
        instead of raising out of the dependency check."""
        fifo = ash_temp_path / "operator" / "rules.guard"
        fifo.parent.mkdir()
        os.mkfifo(fifo)
        scanner = _scanner(repo, rule_sets=[], rules_paths=[str(fifo)])
        with pytest.raises(RulesBundleUnavailable, match="not a regular file"):
            scanner.rule_files()
        # The binary is found whatever the host has, so the check reaches the rules.
        with _cfn_guard_on_path():
            assert scanner.validate_plugin_dependencies() is False
        assert "cannot be used" in scanner.dependency_unavailable_reason

    def test_an_operator_directory_with_no_rules_selects_nothing(
        self, repo, rules_root, ash_temp_path
    ):
        """cfn-guard given such a directory exits 0 with no results (measured),
        which would read as a clean scan."""
        empty = ash_temp_path / "operator-rules"
        empty.mkdir()
        (empty / "README.md").write_text("no rules here\n")
        with pytest.raises(
            RulesBundleUnavailable, match="no cfn-guard rules are selected"
        ):
            _scanner(repo, rule_sets=[], rules_paths=[str(empty)]).rule_files()

    @pytest.mark.parametrize("name", ["wa-Security-Pillar.guard", "../x", "a/b", "-r"])
    def test_rule_set_names_must_be_bare_names(self, name):
        with pytest.raises(ValidationError):
            CfnGuardScannerConfigOptions(rule_sets=[name])


class TestDependencies:
    def test_missing_binary_is_missing_with_a_reason(self, repo, rules_root):
        _fake_bundle(rules_root)
        scanner = _scanner(repo)
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner.find_executable",
            return_value=None,
        ):
            assert scanner.validate_plugin_dependencies() is False
        assert "cfn-guard is not on PATH" in scanner.dependency_unavailable_reason
        assert scanner.scan(target=repo, target_type="source") is False

    def test_missing_rules_are_missing_with_a_reason(self, repo, rules_root):
        scanner = _scanner(repo)
        with patch(
            "automated_security_helper.plugin_modules.ash_builtin.scanners."
            "cfn_guard_scanner.find_executable",
            return_value="/usr/local/bin/cfn-guard",
        ):
            assert scanner.validate_plugin_dependencies() is False
        assert "rules are not installed" in scanner.dependency_unavailable_reason
        # Recorded once, as the ERROR log's line (the plugin's name prefixed);
        # a separate append of the bare reason recorded every reason twice.
        recorded = [
            line
            for line in scanner.errors
            if scanner.dependency_unavailable_reason in line
        ]
        assert len(recorded) == 1

    def test_install_commands_install_the_binary_then_the_rules(self, repo):
        commands = _scanner(repo).custom_install_commands
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                steps = commands[target_platform][arch]
                assert len(steps) == 2
                assert "install_pinned_tool" in " ".join(steps[0].args)
                assert "cfn-guard" in steps[0].args
                assert "install_rules_bundle" in " ".join(steps[1].args)
                assert steps[1].args[-1] == "aws-guard-rules-registry"


def test_the_documented_mapping_is_high_error():
    """Every cfn-guard finding is HIGH (by design), in every reader."""
    assert (VIOLATION_SEVERITY, VIOLATION_LEVEL) == ("HIGH", "error")


class TestBuiltin:
    def test_scanner_is_on_by_default(self):
        assert CfnGuardScannerConfig().enabled is True


class TestScan:
    def _run(self, scanner, fake):
        with (
            patch.object(
                CfnGuardScanner, "validate_plugin_dependencies", return_value=True
            ),
            patch.object(CfnGuardScanner, "_run_subprocess", side_effect=fake),
        ):
            return scanner.scan(
                target=Path(scanner.context.source_dir), target_type="source"
            )

    def test_each_template_is_validated_once_with_the_selected_rules(
        self, repo, rules_root
    ):
        directory = _fake_bundle(rules_root)
        calls = []

        def fake(command, **kwargs):
            calls.append(command)
            data = next(a for a in command if a.startswith("--data="))
            insecure = data.endswith("/templates/insecure.yaml")
            source = CAPTURED_INSECURE if insecure else CAPTURED_COMPLIANT
            return {
                "returncode": 19 if insecure else 0,
                "stdout": source.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        report = self._run(scanner, fake)
        assert len(calls) == 2
        for command in calls:
            assert command[:2] == ["cfn-guard", "validate"]
            assert (
                f"--rules={(directory / 'wa-Security-Pillar.guard').as_posix()}"
                in command
            )
            assert "--output-format=sarif" in command
            assert "--structured" in command and "--show-summary=none" in command
            data = next(a for a in command if a.startswith("--data="))
            assert Path(data.split("=", 1)[1]).is_absolute()
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
        assert _observed(report.runs[0].results) == EXPECTED_INSECURE

    def test_the_recorded_invocation_carries_no_host_path(self, repo, rules_root):
        _fake_bundle(rules_root)
        (repo / "policy").mkdir()
        (repo / "policy" / "mine.guard").write_text("rule mine { }\n")

        def fake(command, **kwargs):
            return {
                "returncode": 0,
                "stdout": CAPTURED_COMPLIANT.read_text(),
                "stderr": "",
            }

        report = self._run(_scanner(repo, rules_paths=["policy"]), fake)
        recorded = report.runs[0].invocations[0].arguments
        assert (
            "--rules=aws-guard-rules-registry-1.0.2/wa-Security-Pillar.guard"
            in recorded
        )
        assert "--rules=policy/mine.guard" in recorded
        assert not any(str(rules_root) in a or str(repo) in a for a in recorded)

    def test_cfn_guard_is_given_a_copy_of_what_was_checked(
        self, repo, rules_root, ash_temp_path
    ):
        """The operator's rules reach cfn-guard as copies outside the scanned
        tree, so a link swapped in after the check is never followed, and a
        link that left the directory is not passed at all."""
        _fake_bundle(rules_root)
        not_a_rule = ash_temp_path / "elsewhere" / "notes.txt"
        not_a_rule.parent.mkdir()
        not_a_rule.write_text("this line is not a rule\n")
        mine = ash_temp_path / "operator-rules"
        mine.mkdir()
        (mine / "mine.guard").write_text("rule mine { }\n")
        _symlink_or_skip(mine / "leak.guard", not_a_rule)
        given = {}

        def fake(command, **kwargs):
            for arg in command:
                if arg.startswith("--rules="):
                    path = Path(arg.split("=", 1)[1])
                    given[path] = (path.is_symlink(), path.read_bytes())
            return {
                "returncode": 0,
                "stdout": CAPTURED_COMPLIANT.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo, rules_paths=[str(mine)])
        self._run(scanner, fake)
        operator_given = {
            p: seen
            for p, seen in given.items()
            if "aws-guard-rules-registry" not in str(p)
        }
        assert list(operator_given.values()) == [(False, b"rule mine { }\n")], given
        for path in operator_given:
            assert not path.resolve().is_relative_to(repo.resolve()), path
            assert path.parent.name.startswith(TOOL_CONFIG_DIR_PREFIX), path

    def test_a_copy_holds_the_bytes_that_were_read(
        self, repo, rules_root, ash_temp_path
    ):
        """Bytes that are not UTF-8 reach cfn-guard as they were (surrogateescape
        on the way in and out); only a CRLF line ending becomes LF."""
        mine = ash_temp_path / "operator" / "mine.guard"
        mine.parent.mkdir()
        mine.write_bytes(b"rule mine { }\r\n# caf\xe9 \xff\n")
        given = []

        def fake(command, **kwargs):
            given.extend(
                Path(a.split("=", 1)[1]).read_bytes()
                for a in command
                if a.startswith("--rules=")
            )
            return {
                "returncode": 0,
                "stdout": CAPTURED_COMPLIANT.read_text(),
                "stderr": "",
            }

        self._run(_scanner(repo, rule_sets=[], rules_paths=[str(mine)]), fake)
        assert given == [b"rule mine { }\n# caf\xe9 \xff\n"] * 2

    def test_a_copy_that_cannot_be_written_fails_the_scan(
        self, repo, rules_root, ash_temp_path, monkeypatch
    ):
        """cfn-guard is not run without the operator's rules it was to evaluate."""
        import errno

        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            cfn_guard_scanner as module,
        )

        def full_disk(*args, **kwargs):
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(module, "write_tool_config", full_disk)
        mine = ash_temp_path / "operator" / "mine.guard"
        mine.parent.mkdir()
        mine.write_text("rule mine { }\n")
        calls = []
        with pytest.raises(ScannerError, match="No space left on device"):
            self._run(
                _scanner(repo, rule_sets=[], rules_paths=[str(mine)]),
                lambda command, **kwargs: calls.append(command),
            )
        assert calls == []

    def test_one_failing_template_does_not_cost_the_others(self, repo, rules_root):
        _fake_bundle(rules_root)

        def fake(command, **kwargs):
            data = next(a for a in command if a.startswith("--data="))
            if data.endswith("/templates/compliant.yaml"):
                return {"returncode": 255, "stdout": "", "stderr": "Parser Error"}
            return {
                "returncode": 19,
                "stdout": CAPTURED_INSECURE.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        report = self._run(scanner, fake)
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 1
        # Recorded once: the ERROR log puts the line in self.errors, and at an
        # earlier tip an append beside it recorded the template twice in the
        # invocation's exitCodeDescription.
        recorded = [
            e
            for e in scanner.errors
            if "templates/compliant.yaml: cfn-guard exited 255" in e
        ]
        assert len(recorded) == 1, scanner.errors
        assert _observed(report.runs[0].results) == EXPECTED_INSECURE

    def test_a_failing_templates_stderr_is_redacted_with_the_scanners_values(
        self, repo, rules_root
    ):
        """At the base the excerpt was cut unredacted, so the head of a value that
        straddled the cut reached ``self.errors``."""
        _fake_bundle(rules_root)
        value = "probe-value-that-must-not-print"

        def fake(command, **kwargs):
            return {
                "returncode": 255,
                "stdout": "",
                "stderr": "a" * 110 + value + "b" * 600,
            }

        scanner = _scanner(repo)
        with patch.object(CfnGuardScanner, "_values_to_redact", return_value=(value,)):
            self._run(scanner, fake)
        joined = "\n".join(scanner.errors)
        assert "cfn-guard exited 255" in joined
        assert "probe-value" not in joined and "not-print" not in joined

    def test_errors_are_reset_for_each_scan_call(self, repo, rules_root):
        """At the base the converted target's invocation record (built from
        self.errors) repeated the source target's lines."""
        _fake_bundle(rules_root)

        def fake(command, **kwargs):
            return {"returncode": 255, "stdout": "", "stderr": "Parser Error"}

        scanner = _scanner(repo)
        self._run(scanner, fake)
        assert any("cfn-guard exited 255" in e for e in scanner.errors)
        stale = list(scanner.errors)

        def clean(command, **kwargs):
            return {
                "returncode": 19,
                "stdout": CAPTURED_INSECURE.read_text(),
                "stderr": "",
            }

        self._run(scanner, clean)
        assert not any(e in scanner.errors for e in stale), scanner.errors

    def test_errors_are_reset_before_the_empty_target_return(self, repo, rules_root):
        """At the previous tip the reset sat below the empty-target, pre-scan and
        dependency returns, so a source scan's lines were still in self.errors
        when the converted target was empty, the shape the reset was added for."""
        _fake_bundle(rules_root)
        empty = repo.parent / "converted-empty"
        empty.mkdir()
        scanner = _scanner(repo)
        scanner.errors = ["the source target's line"]
        with patch.object(
            CfnGuardScanner, "validate_plugin_dependencies", return_value=True
        ):
            scanner.scan(target=empty, target_type="converted")
        assert "the source target's line" not in scanner.errors, scanner.errors

    def test_a_dependency_recorded_unavailable_before_the_scan_keeps_its_line(
        self, repo, rules_root
    ):
        """The reset at the top keeps the one line that explains why the scan
        below does not start; a stale line from another target is still dropped."""
        _fake_bundle(rules_root)
        scanner = _scanner(repo)
        scanner.dependency_unavailable_reason = "cfn-guard was recorded missing"
        scanner.errors = ["the source target's line", "cfn-guard was recorded missing"]
        with patch.object(
            CfnGuardScanner, "validate_plugin_dependencies", return_value=False
        ):
            scanner.scan(target=repo, target_type="source")
        assert "the source target's line" not in scanner.errors, scanner.errors
        assert "cfn-guard was recorded missing" in scanner.errors, scanner.errors

    def test_after_a_timeout_the_remaining_templates_are_not_started(
        self, repo, rules_root
    ):
        """The executor discards the scan after a recorded timeout, so each further
        template would spend a fresh full scan_timeout for nothing; at the base
        every remaining template was still started."""
        _fake_bundle(rules_root)
        calls = []

        def timing_out(command, **kwargs):
            calls.append(list(command))
            return {"returncode": None, "stdout": "", "stderr": "", "timed_out": True}

        scanner = _scanner(repo)
        self._run(scanner, timing_out)
        assert len(calls) == 1, "every template after the timeout was still started"
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 2
        assert any("timed out" in e for e in scanner.errors)
        # One line per template that was not started: the ERROR log already puts
        # the line in self.errors, so an append beside it recorded each twice in
        # the invocation's exitCodeDescription.
        not_started = [e for e in scanner.errors if "not started" in e]
        assert len(not_started) == 1, scanner.errors

    def test_every_template_the_tool_never_evaluated_is_recorded_by_name(
        self, repo, rules_root
    ):
        """The one that timed out and the one not started after it are both
        targets the tool never evaluated, and the run's error record names each
        such target from this list. At the previous tip only a candidate ASH could
        not read was recorded on it; a template whose own invocation failed, or
        was never started, was counted as failed and named in the scanner's line
        but was absent from the run's record, where cfn-nag names its own."""
        _fake_bundle(rules_root)

        def timing_out(command, **kwargs):
            return {"returncode": None, "stdout": "", "stderr": "", "timed_out": True}

        scanner = _scanner(repo)
        self._run(scanner, timing_out)
        assert scanner.targets_failed == 2
        assert sorted(scanner.unevaluated_targets) == [
            "templates/compliant.yaml",
            "templates/insecure.yaml",
        ], scanner.unevaluated_targets

    def test_an_unreadable_candidate_is_a_target_that_was_not_evaluated(
        self, repo, rules_root
    ):
        """A non-UTF-8 candidate: with the tool absent the check reads MISSING; at
        the base, with the tool present, it was a WARNING and nothing more."""
        _fake_bundle(rules_root)
        (repo / "templates" / "latin.yaml").write_bytes(b"Resources:\n  caf\xe9: {}\n")

        def fake(command, **kwargs):
            return {
                "returncode": 19,
                "stdout": CAPTURED_INSECURE.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        self._run(scanner, fake)
        assert scanner.targets_attempted == 3
        assert scanner.targets_failed == 1
        assert any("could not be read" in e for e in scanner.errors), scanner.errors

    def test_a_utf16_template_without_a_byte_order_mark_is_a_failed_target(
        self, repo, rules_root
    ):
        """Written without a mark, a UTF-16 template decodes as UTF-8 without an
        error and reaches the parsers NUL-interleaved. At the previous tip it was
        named as a template that could not be parsed, a WARNING counted as nothing;
        it is a template ASH could not decode, so a failed target named in the
        error record, as its marked twin is."""
        _fake_bundle(rules_root)
        (repo / "templates" / "stack.json").write_bytes(
            '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16-le")
        )

        def fake(command, **kwargs):
            return {
                "returncode": 19,
                "stdout": CAPTURED_INSECURE.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        self._run(scanner, fake)
        assert scanner.targets_attempted == 3
        assert scanner.targets_failed == 1
        named = [
            e for e in scanner.errors if "did not evaluate" in e and "stack.json" in e
        ]
        assert len(named) == 1, scanner.errors
        assert "UTF-16 text without a byte-order mark" in named[0]
        assert not any("Skipped" in e and "stack.json" in e for e in scanner.errors)

    def test_a_non_utf8_candidate_with_no_template_in_it_is_skipped(
        self, repo, rules_root
    ):
        """At the previous tip this file was a failed target with no structure read,
        so one Latin-1 locale file in a repository reported ERROR from every
        CloudFormation scanner. Its text, decoded as well as it can be, is not a
        template, so it is skipped and named, as cfn-nag skips it."""
        _fake_bundle(rules_root)
        (repo / "templates" / "latin.yaml").write_bytes(b"greeting: caf\xe9\n")

        def fake(command, **kwargs):
            return {
                "returncode": 19,
                "stdout": CAPTURED_INSECURE.read_text(),
                "stderr": "",
            }

        scanner = _scanner(repo)
        self._run(scanner, fake)
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 0
        skipped = [e for e in scanner.errors if "Skipped" in e and "latin.yaml" in e]
        assert len(skipped) == 1 and "not UTF-8" in skipped[0], scanner.errors

    def test_rules_removed_between_validation_and_scan_raise(self, repo, rules_root):
        scanner = _scanner(repo)
        with (
            patch.object(
                CfnGuardScanner, "validate_plugin_dependencies", return_value=True
            ),
            pytest.raises(Exception, match="rules are not installed"),
        ):
            scanner.scan(target=repo, target_type="source")


def test_each_target_starts_from_a_clean_exit_code(repo, rules_root, monkeypatch):
    """ScannerExecutor runs one instance over the source, then the converted target.

    The base class keeps the worst exit code across subprocess calls, and the
    invocation records it. A clean converted target after a source that failed a
    rule (exit 19) must record its own 0. Only the process call is replaced, so
    ``_run_subprocess`` and that accumulation run for real.
    """
    _fake_bundle(rules_root)
    converted = repo / ".ash" / "ash_output" / "converted" / "archive.zip"
    converted.mkdir(parents=True)
    shutil.copy(repo / "templates" / "compliant.yaml", converted / "t.yaml")

    def tool(command, **_):
        data = next(a for a in command if a.startswith("--data="))
        insecure = data.endswith("/templates/insecure.yaml")
        return {
            "returncode": 19 if insecure else 0,
            "stdout": (
                CAPTURED_INSECURE if insecure else CAPTURED_COMPLIANT
            ).read_text(),
            "stderr": "",
        }

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        tool,
    )
    scanner = _scanner(repo)
    with patch.object(
        CfnGuardScanner, "validate_plugin_dependencies", return_value=True
    ):
        source = scanner.scan(target=repo, target_type="source")
        assert source.runs[0].invocations[0].exitCode == 19
        assert scanner.exit_code == 19

        report = scanner.scan(target=converted.parent, target_type="converted")

    assert scanner.targets_attempted == 1 and scanner.targets_failed == 0
    assert report.runs[0].results == []
    assert scanner.exit_code == 0
    assert report.runs[0].invocations[0].exitCode == 0
