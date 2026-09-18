# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The GitLab SAST schema version is one fact, stated once, and CI must use it.

Why this exists
---------------
``gitlab_sast_reporter`` emits ``"version": "15.2.2"`` in every report, which is a
claim that the document conforms to that schema. The CI step that checks the claim --
"Validate GitLab SAST Report Schema Compliance" in
``.github/actions/run-scan-test/action.yml`` -- fetched the schema from the upstream
repository's ``master`` instead, so it validated against whatever GitLab had merged
most recently rather than against the claim.

Measured 2026-09-17: ``master`` was schema 15.2.5, 36,352 bytes, while v15.2.2 is
35,322 bytes, and their digests differ. The drift happened to be loosening -- 15.2.5
adds CVSS 4.0 vectors and raises ``code_flows.items.maxItems`` from 10 to 30, and this
reporter emits neither field -- so nothing had failed yet. A tightening change would
have reddened the gate with no commit to this repository, which is the failure this
guards.

These tests pin the two halves that have to agree: the constant is what the report
carries, and the workflow resolves the schema URL from the constant rather than from a
branch name.

Known limitations
-----------------
* The workflow assertions are text checks over YAML, not an execution of the step. They
  can tell that the URL is built from the constant and is not a floating ref; they
  cannot tell that the fetch succeeds. That is what the CI step itself is for.
* Nothing here reaches the network, so a bump to ``GITLAB_SAST_SCHEMA_VERSION`` whose
  tag does not exist upstream is not caught here -- it fails in the step, where the
  added ``curl -f`` makes a 404 an error instead of a schema file full of HTML.
"""

import json
import re
from pathlib import Path

from automated_security_helper.plugin_modules.ash_builtin.reporters.gitlab_sast_reporter import (
    GITLAB_SAST_SCHEMA_VERSION,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
SCAN_TEST_ACTION = REPO_ROOT / ".github/actions/run-scan-test/action.yml"
REPORTER_SOURCE = (
    REPO_ROOT
    / "automated_security_helper/plugin_modules/ash_builtin/reporters/gitlab_sast_reporter.py"
)


class TestTheConstantIsTheOnlyStatementOfTheVersion:
    def test_it_looks_like_a_schema_version(self):
        assert re.fullmatch(r"\d+\.\d+\.\d+", GITLAB_SAST_SCHEMA_VERSION), (
            f"{GITLAB_SAST_SCHEMA_VERSION!r} is not an x.y.z version. The report's "
            f"`version` field is constrained to that shape by the schema itself, so a "
            f"malformed value here produces a report that fails validation."
        )

    def test_the_reporter_does_not_carry_a_second_hardcoded_version(self):
        """A literal reintroduced beside the constant is how the two drift apart.

        Scoped to strings that look like a schema version, so the analyzer and scanner
        versions -- both `get_ash_version()` calls -- are untouched.
        """
        source = REPORTER_SOURCE.read_text()
        # The constant's own definition line is the one legitimate occurrence.
        without_definition = re.sub(
            r"^GITLAB_SAST_SCHEMA_VERSION\s*=.*$", "", source, flags=re.MULTILINE
        )
        # Comments explain the measurement and legitimately name versions.
        code_only = "\n".join(
            line
            for line in without_definition.splitlines()
            if not line.strip().startswith("#")
        )
        literals = re.findall(r'"(\d+\.\d+\.\d+)"', code_only)
        assert not literals, (
            f"hardcoded schema-version literal(s) {literals} in the reporter. Use "
            f"GITLAB_SAST_SCHEMA_VERSION so the report and the CI gate cannot disagree."
        )


class TestTheEmittedReportCarriesTheConstant:
    def test_the_report_dict_uses_the_constant(self):
        """Reads the source rather than building a report.

        Constructing one needs a populated model and a plugin context, which is
        covered by test_gitlab_sast_suppressions.py; the property here is narrower --
        that the `version` key is wired to the constant and not to a literal.
        """
        source = REPORTER_SOURCE.read_text()
        assert '"version": GITLAB_SAST_SCHEMA_VERSION' in source, (
            "the report dict's top-level `version` is not GITLAB_SAST_SCHEMA_VERSION. "
            "If the key moved, update this test rather than reverting to a literal."
        )


class TestTheCiGateResolvesTheSchemaFromTheConstant:
    def test_the_schema_is_not_fetched_from_a_floating_ref(self):
        """The regression: `/-/raw/master/` made an external branch the contract."""
        text = SCAN_TEST_ACTION.read_text()
        offenders = [
            line.strip()
            for line in text.splitlines()
            if "security-report-schemas" in line
            and re.search(r"/-/raw/(master|main|HEAD)/", line)
        ]
        assert not offenders, (
            "the GitLab SAST schema is fetched from a floating ref: "
            + "; ".join(offenders)
            + ". Pin it to the version the reporter declares, or the gate's contract "
            "can change without a commit here."
        )

    def test_the_schema_url_is_built_from_the_reporter_constant(self):
        text = SCAN_TEST_ACTION.read_text()
        assert "GITLAB_SAST_SCHEMA_VERSION" in text, (
            "the schema-compliance step does not read GITLAB_SAST_SCHEMA_VERSION. "
            "Hardcoding the version in the workflow puts the same fact in two files."
        )
        assert "raw/v${SCHEMA_VERSION}/dist/sast-report-format.json" in text, (
            "the schema URL does not interpolate the version read from the reporter. "
            "Upstream tags carry a 'v' prefix; a bare version is a 404."
        )

    @staticmethod
    def _command_lines(text: str) -> "list[str]":
        """Shell lines only.

        The comments in this step quote the old unretried, unpinned forms in order to
        explain what changed, so matching raw text finds the prose and reports the
        defect as still present. Both of these tests failed that way on first run.
        """
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def test_the_validator_is_version_pinned(self):
        """An unpinned `npm install -g ajv-cli` lets a validator release fail the gate."""
        installs = [
            line
            for line in self._command_lines(SCAN_TEST_ACTION.read_text())
            if re.search(r"npm install\s+-g\s+ajv-cli", line)
        ]
        assert installs, "the ajv-cli install disappeared; the gate needs a validator"
        for line in installs:
            assert re.search(r"ajv-cli@\d", line), (
                f"ajv-cli is installed unpinned: {line!r}. Pin at least the major, or a "
                f"breaking validator release fails the gate on unchanged reports."
            )

    def test_both_network_operations_are_retried(self):
        """The npm fetch is what ECONNRESET took down on run 35177045049."""
        text = SCAN_TEST_ACTION.read_text()
        # Anchored on the step DECLARATION, not on its name. An earlier comment in this
        # file names the step in prose, and slicing from there put the window 160 lines
        # short of the commands -- so the first version of this test reported the npm
        # install missing when it was present.
        start = text.index("- name: Validate GitLab SAST Report Schema Compliance")
        step = "\n".join(self._command_lines(text[start : start + 5000]))
        for command in (
            "npm install -g ajv-cli",
            "curl -sSfL -o gitlab-sast-schema.json",
        ):
            index = step.find(command)
            assert index != -1, f"{command!r} not found in the schema-compliance step"
            # `retry` must be the thing invoking it, on the same line or the line before
            # (the curl is continued across lines).
            preceding = step[max(0, index - 120) : index]
            assert "retry " in preceding, (
                f"{command!r} is not wrapped in the step's retry helper, so a transient "
                f"network failure fails the job before any report is validated"
            )


class TestTheCommittedReportFixtureAgrees:
    """If a gl-sast fixture is committed, its version must match the constant.

    A fixture pinned to an older schema would make the suite assert conformance to a
    contract the reporter no longer claims.
    """

    def test_any_committed_gl_sast_fixture_declares_the_same_version(self):
        fixtures = sorted(
            p
            for p in (REPO_ROOT / "tests").rglob("*gl-sast-report*.json")
            if p.is_file()
        )
        if not fixtures:
            # Nothing to check. Stated rather than skipped so the absence is visible in
            # the run instead of reading as a pass.
            print("no committed gl-sast-report fixtures found")
            return
        for fixture in fixtures:
            payload = json.loads(fixture.read_text())
            if "version" not in payload:
                continue
            assert payload["version"] == GITLAB_SAST_SCHEMA_VERSION, (
                f"{fixture.relative_to(REPO_ROOT)} declares schema "
                f"{payload['version']} but the reporter emits "
                f"{GITLAB_SAST_SCHEMA_VERSION}"
            )
