"""cfn-lint: one template's fault costs that template; the operator's options hold.

Pinned here against ``CfnLintScanner`` with only ``_run_subprocess`` faked, as
``test_cfn_lint_scanner.py`` does:

* a batch cfn-lint exits on for one template's fault (a region its Metadata names
  that this cfn-lint does not know exits 32) is re-run one template at a time, so
  only that template fails and the others' findings are kept;
* after one invocation times out, the remaining batches are not started: the
  executor discards the scan after a recorded timeout, and each batch would have
  spent a fresh full scan_timeout;
* with ``honor_inline_ignores`` on, ``--merge-configs`` is passed, so an operator's
  ``ignore_checks`` no longer replaces the template's own list;
* an operator's ``.cfnlintrc`` ASH cannot read stops the scan instead of being
  handed to cfn-lint unchecked;
* ``self.errors`` is reset per ``scan()`` call;
* the last dependency fallback that finds a binary on PATH runs that binary.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_lint_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"

SARIF_WITH_ONE_FINDING = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "cfn-lint",
                    "version": "1.57.2",
                    "rules": [{"id": "W2001", "shortDescription": {"text": "unused"}}],
                }
            },
            "results": [],
        }
    ],
}


def _scanner(repo: Path, *, operator: bool = True, **options) -> CfnLintScanner:
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=[],
    )
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions(**options)
        ),
    )


def _repo(ash_temp_path: Path, *names: str) -> Path:
    repo = ash_temp_path / "repo"
    repo.mkdir()
    for name in names:
        (repo / name).write_text(TEMPLATE, encoding="utf-8")
    return repo


def _finding_at(uri: str) -> dict:
    return {
        "ruleId": "W2001",
        "level": "note",
        "message": {"text": f"W2001 at {uri}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


class RegionFaultCfnLint:
    """Exits 32 for any invocation that names ``faulty``; otherwise writes SARIF."""

    def __init__(self, *faulty: str):
        self.faulty = faulty
        self.calls: list = []

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        files = command[command.index("--") + 1 :]
        if any(f.endswith(name) for f in files for name in self.faulty):
            return {
                "stdout": "",
                "stderr": "Regions ['mars-north-1'] are unsupported.",
                "returncode": 32,
            }
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
        )
        document = json.loads(json.dumps(SARIF_WITH_ONE_FINDING))
        document["runs"][0]["results"] = [_finding_at(f) for f in files]
        Path(output).write_text(json.dumps(document), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 4}


def _run(scanner: CfnLintScanner, fake, repo: Path):
    with (
        patch.object(CfnLintScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(CfnLintScanner, "_run_subprocess", side_effect=fake),
    ):
        return scanner.scan(target=repo, target_type="source")


def test_one_template_can_fail_the_run_is_false_for_timeouts_and_unstarted():
    # Read through the module so a base without the helper fails this test alone
    # instead of failing the whole file's collection.
    can_fail = cfn_lint_scanner._one_template_can_fail_the_run
    assert can_fail({"returncode": 32}) is True
    assert can_fail({"timed_out": True}) is False
    assert can_fail({"error": "no such file"}) is False
    assert can_fail({}) is False


def test_a_batch_failed_by_one_template_is_rerun_one_template_at_a_time(
    ash_temp_path,
):
    """At the base both templates read as not evaluated and no finding survived."""
    repo = _repo(ash_temp_path, "good.yaml", "unknown-region.yaml")
    fake = RegionFaultCfnLint("unknown-region.yaml")
    scanner = _scanner(repo)

    report = _run(scanner, fake, repo)

    batches = [call[call.index("--") + 1 :] for call in fake.calls]
    assert [len(b) for b in batches] == [2, 1, 1], batches
    assert scanner.targets_attempted == 2
    assert scanner.targets_failed == 1
    assert [r.ruleId for r in report.runs[0].results] == ["W2001"]
    assert any("unknown-region.yaml" in e and "exited 32" in e for e in scanner.errors)


def test_a_timeout_stops_the_remaining_invocations(ash_temp_path):
    """Each template runs alone under honor_inline_ignores; the first times out."""
    repo = _repo(ash_temp_path, "a.yaml", "b.yaml", "c.yaml")
    calls: list = []

    def timing_out(command, **kwargs):
        calls.append(list(command))
        return {"stdout": "", "stderr": "", "returncode": None, "timed_out": True}

    scanner = _scanner(repo, honor_inline_ignores=True)
    _run(scanner, timing_out, repo)

    assert len(calls) == 1, "every batch after the timeout was still started"
    assert scanner.targets_attempted == 3
    assert scanner.targets_failed == 3
    # Each not-started template is recorded once, by the ERROR log line (the base
    # class appends ERROR logs to self.errors), which names it; after a timeout
    # the remaining templates are folded one at a time, so one line each. At an
    # earlier tip a second append beside the log recorded each twice, and this
    # test read the templates from that second form.
    not_started = [e for e in scanner.errors if "not started" in e]
    named = sorted(
        e.split("did not evaluate ", 1)[1].split(":", 1)[0] for e in not_started
    )
    assert named == ["b.yaml", "c.yaml"], scanner.errors


def test_a_failed_invocation_names_a_few_templates_and_records_each(ash_temp_path):
    """One invocation lints a batch of templates, and when it fails as a whole one
    line named every template in it. A batch holds up to 24,000 characters of
    paths, hundreds of templates, so that line ran on for hundreds of names in the
    error record. It now names the first eight and counts the rest; no name is
    lost, since each template is recorded on its own as a target the tool never
    evaluated, which the run's error record names one by one. At the previous tip
    a template whose invocation failed was not recorded that way at all."""
    names = [f"t{index:02d}.yaml" for index in range(12)]
    repo = _repo(ash_temp_path, *names)
    calls: list = []

    def timing_out(command, **kwargs):
        calls.append(list(command))
        return {"stdout": "", "stderr": "", "returncode": None, "timed_out": True}

    scanner = _scanner(repo)
    _run(scanner, timing_out, repo)

    assert len(calls) == 1, "the twelve templates did not run as one batch"
    assert scanner.targets_attempted == 12
    assert scanner.targets_failed == 12
    assert sorted(scanner.unevaluated_targets) == names
    lines = [e for e in scanner.errors if "did not evaluate" in e]
    assert len(lines) == 1, scanner.errors
    assert "t00.yaml, t01.yaml" in lines[0]
    assert "t07.yaml and 4 more" in lines[0], lines[0]
    assert "t08.yaml" not in lines[0]


def test_honored_template_ignores_merge_with_the_operators_ignore_checks(
    ash_temp_path,
):
    repo = _repo(ash_temp_path, "a.yaml")
    fake = RegionFaultCfnLint("no-such-template")
    _run(_scanner(repo, honor_inline_ignores=True, ignore_checks=["W2001"]), fake, repo)
    args = fake.calls[0]
    assert "--merge-configs" in args, args
    assert args[args.index("--ignore-checks") + 1] == "W2001"

    default = RegionFaultCfnLint("no-such-template")
    _run(_scanner(repo), default, repo)
    assert "--merge-configs" not in default.calls[0], default.calls[0]


@pytest.mark.parametrize(
    "content, kind",
    [
        pytest.param(b"ignore_checks: [\n", "unparseable YAML", id="yaml"),
        pytest.param(b"ignore_checks: [caf\xe9]\n", "not UTF-8", id="utf8"),
        pytest.param(None, "a file ASH may not read", id="oserror"),
    ],
)
def test_an_operators_cfnlintrc_ash_cannot_read_stops_the_scan(
    ash_temp_path, tmp_path, monkeypatch, content, kind
):
    """Through scan(): cfn-lint is never started with a config file ASH could not
    check (a merge_configs in it would apply unseen). The three ways a read fails
    (YAMLError, UnicodeDecodeError, OSError) all end the scan; at the base the
    UnicodeDecodeError escaped as the generic scanner failure.

    The OSError arm refuses the read of this one path: a directory at the path is
    refused before any read (the next test), and a mode-000 file reads fine for
    root, which the venue may run as.
    """
    repo = _repo(ash_temp_path, "a.yaml")
    operator_rc = tmp_path / "operator" / ".cfnlintrc"
    operator_rc.parent.mkdir()
    if content is None:
        operator_rc.write_bytes(b"ignore_checks: []\n")
        real_read_text = Path.read_text

        def refused(self, *args, **kwargs):
            if self == operator_rc:
                raise PermissionError(13, "Permission denied", str(self))
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", refused)
    else:
        operator_rc.write_bytes(content)
    scanner = _scanner(repo, config_file=str(operator_rc))
    fake = RegionFaultCfnLint("no-such-template")
    with pytest.raises(ScannerError, match="could not read"):
        _run(scanner, fake, repo)
    assert fake.calls == [], f"cfn-lint was started with {kind}"


def test_an_operators_cfnlintrc_that_is_a_directory_is_refused_as_not_a_file(
    ash_temp_path, tmp_path
):
    """A directory at the configured path is refused before any read, and the
    refusal says what was found: at the base it said the path did not exist."""
    repo = _repo(ash_temp_path, "a.yaml")
    operator_rc = tmp_path / "operator" / ".cfnlintrc"
    operator_rc.mkdir(parents=True)
    scanner = _scanner(repo, config_file=str(operator_rc))
    fake = RegionFaultCfnLint("no-such-template")
    with pytest.raises(ScannerError, match="is not a file") as excinfo:
        _run(scanner, fake, repo)
    assert "does not exist" not in str(excinfo.value)
    assert fake.calls == [], "cfn-lint was started with a directory as its config"


def test_errors_are_reset_for_each_scan_call(ash_temp_path):
    """A line recorded by an earlier scan() call is not carried into the next.

    The second scan has a template and a clean cfn-lint run, so the only lines it
    may record are its own; the stale one must be gone.
    """
    repo = _repo(ash_temp_path, "a.yaml")
    scanner = _scanner(repo)
    scanner.errors = ["the source target's line"]
    _run(scanner, RegionFaultCfnLint("no-such-template"), repo)
    assert "the source target's line" not in scanner.errors, scanner.errors


def test_an_already_missing_dependency_sends_no_version_probe(ash_temp_path):
    """At the base the deferred version probe ran before the MISSING gate."""
    repo = ash_temp_path / "repo"
    repo.mkdir()
    scanner = _scanner(repo)
    scanner.dependency_unavailable_reason = "cfn-lint was recorded missing earlier"
    with (
        patch.object(CfnLintScanner, "resolve_deferred_tool_version") as probe,
        patch.object(CfnLintScanner, "_validate_uv_tool_availability") as uv_check,
    ):
        assert scanner.validate_plugin_dependencies() is False
    probe.assert_not_called()
    uv_check.assert_not_called()


def test_the_last_dependency_fallback_runs_the_binary_it_found(ash_temp_path):
    repo = ash_temp_path / "repo"
    repo.mkdir()
    scanner = _scanner(repo)
    with (
        patch.object(
            CfnLintScanner, "resolve_deferred_tool_version", return_value=None
        ),
        patch.object(
            CfnLintScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(
            CfnLintScanner,
            "_get_tool_installation_info",
            return_value={"available": False},
        ),
        patch.object(CfnLintScanner, "_install_uv_tool", return_value=False),
        patch.object(
            cfn_lint_scanner, "get_uv_tool_command", return_value=["/usr/bin/cfn-lint"]
        ),
    ):
        assert scanner.validate_plugin_dependencies() is True
    assert scanner.dependencies_satisfied is True
    assert scanner.use_uv_tool is False, (
        "the scan would go through uv, whose install failed"
    )


def test_a_failing_batchs_stderr_is_redacted_before_it_is_cut():
    """The value straddles the excerpt's cut (the first quarter of 500 characters
    ends inside it), so a redaction of the excerpt would see neither half of it;
    redacting the whole text first leaves nothing of it in the message."""
    value = "probe-value-that-must-not-print"
    stderr = "a" * 110 + value + "b" * 600
    failure = CfnLintScanner._batch_failure(
        {"returncode": 1, "stderr": stderr}, Path("batch.sarif"), values=(value,)
    )
    assert "cfn-lint exited 1" in failure
    assert value not in failure
    assert "probe-value" not in failure and "not-print" not in failure


def test_unreadable_redaction_values_withhold_cfn_lints_stderr():
    failure = CfnLintScanner._batch_failure(
        {"returncode": 1, "stderr": "secret-looking text"},
        Path("batch.sarif"),
        values=None,
    )
    assert "secret-looking" not in failure
    assert "withheld" in failure


def test_the_redaction_values_are_required():
    """A default of "redact nothing" let a caller that forgot the values print the
    stderr unredacted; the parameter is keyword-only with no default."""
    with pytest.raises(TypeError):
        CfnLintScanner._batch_failure({"returncode": 1}, Path("batch.sarif"))  # type: ignore[call-arg]


def test_the_scan_passes_its_redaction_values_to_the_failure_message(ash_temp_path):
    """At the base the excerpt was cut unredacted, so the head of a value that
    straddled the cut reached ``self.errors``."""
    repo = _repo(ash_temp_path, "one.yaml")
    value = "probe-value-that-must-not-print"

    def fake(command, **kwargs):
        return {
            "stdout": "",
            "stderr": "a" * 110 + value + "b" * 600,
            "returncode": 1,
        }

    scanner = _scanner(repo)
    with patch.object(CfnLintScanner, "_values_to_redact", return_value=(value,)):
        _run(scanner, fake, repo)
    joined = "\n".join(scanner.errors)
    assert "cfn-lint exited 1" in joined
    assert "probe-value" not in joined and "not-print" not in joined


class RunWideFaultCfnLint:
    """Exits 32 with the same message for every invocation: the run's fault."""

    def __init__(self):
        self.calls: list = []

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        return {
            "stdout": "",
            "stderr": "Regions ['mars-north-1'] are unsupported.",
            "returncode": 32,
        }


def test_a_run_wide_failure_is_not_repeated_once_per_template(ash_temp_path):
    """At the base a batch of eight that failed for the run's own reason was re-run
    one template at a time: nine cfn-lint start-ups to report one failure eight
    times. The first template alone fails alike and the failure names no template,
    so one probe lint of a synthetic template decides: it fails alike, so the
    seven remaining are recorded with that failure and not re-run. Three
    invocations: the batch, the first template, the probe."""
    names = [f"{letter}.yaml" for letter in "abcdefgh"]
    repo = _repo(ash_temp_path, *names)
    fake = RunWideFaultCfnLint()
    scanner = _scanner(repo)

    _run(scanner, fake, repo)

    batches = [call[call.index("--") + 1 :] for call in fake.calls]
    assert len(batches) == 3, batches
    assert len(batches[0]) == 8
    assert len(batches[1]) == 1 and batches[1][0].endswith("a.yaml")
    assert len(batches[2]) == 1 and batches[2][0].endswith(".probe.yaml")
    # Compared as paths: the argument is POSIX-form, the repo path is the host's.
    assert repo / ".ash" in Path(batches[2][0]).parents, (
        "the probe left the results dir"
    )
    assert scanner.targets_attempted == 8
    assert scanner.targets_failed == 8
    assert any("read as a failure of the run" in e for e in scanner.errors)


def test_a_small_batch_with_alike_failures_at_both_ends_still_runs_the_middle(
    ash_temp_path,
):
    """Two templates with the SAME per-template fault at both ends of a small batch
    fail alike when run alone. At an earlier tip that equality alone folded the
    template between them as failed without running it, and its finding was never
    produced. The probe template (no Metadata) lints clean, so the failure is not
    the run's and every remaining template runs on its own: the batch, the first
    alone, the probe, then the two remaining."""
    repo = _repo(ash_temp_path, "aaa-faulty.yaml", "mmm.yaml", "zzz-faulty.yaml")
    fake = RegionFaultCfnLint("aaa-faulty.yaml", "zzz-faulty.yaml")
    scanner = _scanner(repo)

    report = _run(scanner, fake, repo)

    batches = [call[call.index("--") + 1 :] for call in fake.calls]
    assert len(batches) == 5, batches
    assert batches[2][0].endswith(".probe.yaml"), batches
    assert scanner.targets_attempted == 3
    assert scanner.targets_failed == 2
    assert not any("read as a failure of the run" in e for e in scanner.errors)
    uris = [
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    ]
    assert [u.rsplit("/", 1)[-1] for u in uris] == ["mmm.yaml"]


def test_a_large_batch_with_the_same_fault_at_both_ends_keeps_the_middles_findings(
    ash_temp_path,
):
    """Eight templates, the first and the last naming the same unknown region: at
    the previous tip the first and last re-runs failed alike, the failure text
    names no template, six sat between them, so all six were recorded as failed
    without being linted and their findings were lost. The probe decides instead:
    it lints clean, so the six run on their own and every finding is kept."""
    middles = [f"{letter}.yaml" for letter in "bcdefg"]
    repo = _repo(ash_temp_path, "aaa-faulty.yaml", *middles, "zzz-faulty.yaml")
    fake = RegionFaultCfnLint("aaa-faulty.yaml", "zzz-faulty.yaml")
    scanner = _scanner(repo)

    report = _run(scanner, fake, repo)

    batches = [call[call.index("--") + 1 :] for call in fake.calls]
    # The batch, the first alone, the probe, then the seven remaining one by one.
    assert len(batches) == 10, batches
    assert scanner.targets_attempted == 8
    assert scanner.targets_failed == 2
    assert not any("read as a failure of the run" in e for e in scanner.errors)
    uris = sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    )
    assert [u.rsplit("/", 1)[-1] for u in uris] == middles


def test_a_faulty_first_template_does_not_hide_the_others(ash_temp_path):
    """The first template alone fails as the batch did and the probe template
    lints clean, so the failure is one template's and the rest are linted on
    their own: the batch, the first alone, the probe, then the two remaining."""
    repo = _repo(ash_temp_path, "aaa-faulty.yaml", "mmm.yaml", "zzz.yaml")
    fake = RegionFaultCfnLint("aaa-faulty.yaml")
    scanner = _scanner(repo)

    report = _run(scanner, fake, repo)

    batches = [call[call.index("--") + 1 :] for call in fake.calls]
    assert len(batches) == 5, batches
    assert scanner.targets_failed == 1
    assert not any("read as a failure of the run" in e for e in scanner.errors)
    uris = sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    )
    assert [u.rsplit("/", 1)[-1] for u in uris] == ["mmm.yaml", "zzz.yaml"]


def test_an_unreadable_candidate_is_a_target_that_was_not_evaluated(ash_temp_path):
    """A non-UTF-8 candidate: with the tool absent the check reads MISSING (only
    MISSING cannot hide a template); at the base, with the tool present, it was a
    WARNING and the run looked like one with no templates. Now it is counted."""
    repo = ash_temp_path / "repo"
    repo.mkdir()
    (repo / "latin.yaml").write_bytes(b"Resources:\n  caf\xe9: {}\n")
    fake = RegionFaultCfnLint("no-such-template")
    scanner = _scanner(repo)

    _run(scanner, fake, repo)

    assert fake.calls == []
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    assert any("could not be read" in e for e in scanner.errors), scanner.errors


def test_a_utf16_template_without_a_byte_order_mark_is_a_failed_target(
    ash_temp_path,
):
    """Written without a mark, a UTF-16 template decodes as UTF-8 without an error
    (NUL is valid UTF-8) and reaches the parsers NUL-interleaved. At the previous
    tip it was named as a template that could not be parsed, a WARNING counted as
    nothing; it is a template ASH could not decode, so a failed target named in the
    error record, as its marked twin is."""
    repo = ash_temp_path / "repo"
    repo.mkdir()
    (repo / "stack.json").write_bytes(
        '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}'.encode("utf-16-le")
    )
    fake = RegionFaultCfnLint("no-such-template")
    scanner = _scanner(repo)

    _run(scanner, fake, repo)

    assert fake.calls == []
    assert scanner.targets_attempted == 1
    assert scanner.targets_failed == 1
    named = [e for e in scanner.errors if "did not evaluate" in e and "stack.json" in e]
    assert len(named) == 1, scanner.errors
    assert "UTF-16 text without a byte-order mark" in named[0]
    assert not any("Skipped" in e and "stack.json" in e for e in scanner.errors)


def test_a_non_utf8_candidate_with_no_template_in_it_is_skipped(ash_temp_path):
    """At the previous tip this file was a failed target with no structure read, so
    one Latin-1 locale file in a repository reported ERROR from every CloudFormation
    scanner. Its text, decoded as well as it can be, is not a template, so it is
    skipped and named, as cfn-nag skips it, and the run has nothing to scan."""
    repo = ash_temp_path / "repo"
    repo.mkdir()
    (repo / "latin.yaml").write_bytes(b"greeting: caf\xe9\n")
    fake = RegionFaultCfnLint("no-such-template")
    scanner = _scanner(repo)

    _run(scanner, fake, repo)

    assert fake.calls == []
    assert scanner.targets_attempted == 0
    assert scanner.targets_failed == 0
    skipped = [e for e in scanner.errors if "Skipped" in e and "latin.yaml" in e]
    assert len(skipped) == 1 and "not UTF-8" in skipped[0], scanner.errors
