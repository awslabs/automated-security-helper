# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unknown key in a suppression or ignore-path entry refuses the config.

Dropped as an unknown key (pydantic's default ``extra="ignore"``), a misspelled
``rule_id`` -- ``ruleId``, ``rule-id``, ``rule`` -- would leave the entry with no
rule at all, and a suppression with no rule suppresses every rule in its path.
The same goes for every other key: a ``line_star`` would widen a suppression to
the whole file, an ``expiraton`` would make it permanent.

Every entry built on ``IgnorePathWithReason`` refuses a key it does not
declare, with "did you mean" when one is close: global suppressions and ignore
paths, a workspace policy's, and the scanner options of the same type (bandit
``excluded_paths``, checkov ``skip_path``, syft ``exclude``). A config file
with one exits 3; a workspace policy with one exits 4.

A results file is a record of a past scan, not a config to apply, so one that
holds such a key still loads: the key is kept, a warning names it, and an entry
that carries one never applies.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    WorkspaceDefinitionError,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScannerConfigOptions,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    should_suppress_finding,
)
from automated_security_helper.utils.unknown_keys import TOLERATE_STORED_CONFIG

AshConfig.model_rebuild()


def _finding(rule_id="B602", path="app.py"):
    return FlatVulnerability(
        id="f1",
        title="t",
        description="d",
        severity="HIGH",
        scanner="bandit",
        scanner_type="SAST",
        rule_id=rule_id,
        file_path=path,
        line_start=10,
        line_end=10,
    )


class TestMisspelledRuleId:
    """A misspelled rule_id refuses the config instead of leaving a suppression
    with no rule."""

    @pytest.mark.parametrize("key", ["ruleId", "rule-id", "RULE_ID", "rule_ids"])
    def test_refused_with_a_suggestion(self, key):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression(**{key: "B101", "path": "app.py", "reason": "r"})
        message = str(excinfo.value)
        assert key in message
        assert "did you mean 'rule_id'" in message

    def test_never_suppresses_every_rule_in_the_path(self):
        """An entry with a misspelled rule_id never matches a B602 finding.

        A config file refuses it. A results file keeps it, and the kept entry
        never applies.
        """
        data = {"ruleId": "B101", "path": "app.py", "reason": "asserts only"}
        with pytest.raises(ValidationError):
            AshSuppression(**data)
        notes: list = []
        kept = AshSuppression.model_validate(
            data, context={TOLERATE_STORED_CONFIG: notes}
        )
        assert kept.rule_id is None and kept.model_extra == {"ruleId": "B101"}
        assert notes, "the kept key was not reported"
        suppressed, _ = should_suppress_finding(_finding("B602"), [kept])
        assert not suppressed, (
            "a suppression written for B101 suppressed an unrelated B602 finding "
            "because its misspelled rule_id was dropped"
        )


class TestEveryEntryKind:
    @pytest.mark.parametrize(
        "data,key,suggestion",
        [
            ({"pathh": "vendor/**", "reason": "r"}, "pathh", "path"),
            ({"path": "vendor/**", "reasons": "r"}, "reasons", "reason"),
            (
                {"path": "vendor/**", "reason": "r", "expiraton": "2099-01-01"},
                "expiraton",
                "expiration",
            ),
        ],
    )
    def test_ignore_path_entry(self, data, key, suggestion):
        with pytest.raises(ValidationError) as excinfo:
            IgnorePathWithReason(**data)
        assert key in str(excinfo.value)
        assert f"did you mean '{suggestion}'" in str(excinfo.value)

    def test_no_suggestion_when_nothing_is_close(self):
        with pytest.raises(ValidationError) as excinfo:
            IgnorePathWithReason(path="vendor/**", reason="r", colour="blue")
        message = str(excinfo.value)
        assert "colour" in message
        assert "did you mean" not in message

    @pytest.mark.parametrize("key", ["line_star", "package-name", "symbl"])
    def test_suppression_fields(self, key):
        with pytest.raises(ValidationError) as excinfo:
            AshSuppression(rule_id="B101", path="a.py", reason="r", **{key: "x"})
        assert key in str(excinfo.value)

    def test_scanner_option_entries(self):
        with pytest.raises(ValidationError) as excinfo:
            BanditScannerConfigOptions(
                excluded_paths=[{"path": "vendor", "reason": "r", "reasn": "x"}]
            )
        assert "reasn" in str(excinfo.value)

    def test_declared_keys_load(self):
        AshSuppression(
            rule_id="B101",
            path="a.py",
            reason="r",
            line_start=1,
            line_end=2,
            expiration="2099-01-01",
            package_name="p",
            package_version="1",
            package_path="x",
            symbol="A.b",
        )
        IgnorePathWithReason(path="vendor/**", reason="r", expiration="2099-01-01")


class TestConfigFiles:
    @staticmethod
    def _source(tmp_path, body):
        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(body, encoding="utf-8")
        return source

    def test_config_with_a_misspelled_rule_id_exits_3(self, tmp_path):
        source = self._source(
            tmp_path,
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - ruleId: B101\n"
            "      path: 'tests/**'\n"
            "      reason: asserts in tests\n",
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        message = str(excinfo.value)
        assert "ruleId" in message and "did you mean 'rule_id'" in message
        # The location as format_model_error prints it ("Invalid value at
        # 'global_settings.suppressions[0]'").
        assert "global_settings.suppressions[0]" in message, (
            "the error should say which entry"
        )

    def test_config_with_a_bad_ignore_path_key_exits_3(self, tmp_path):
        source = self._source(
            tmp_path,
            "project_name: demo\n"
            "global_settings:\n"
            "  ignore_paths:\n"
            "    - path: 'vendor/**'\n"
            "      reason: vendored\n"
            "      expires: '2099-01-01'\n",
        )
        with pytest.raises(ASHConfigValidationError) as excinfo:
            resolve_config(source_dir=source)
        assert "expires" in str(excinfo.value)
        assert "did you mean 'expiration'" in str(excinfo.value)

    def test_workspace_policy_with_one_is_refused(self, tmp_path):
        from automated_security_helper.workspace.resolver import resolve_workspace

        (tmp_path / "api").mkdir()
        workspace = tmp_path / "dev.code-workspace"
        workspace.write_text(json.dumps({"folders": [{"path": "api"}]}))
        (tmp_path / ".ash").mkdir()
        (tmp_path / ".ash" / "ash-workspace.yaml").write_text(
            "workspace:\n"
            "  suppressions:\n"
            "    - ruleId: B101\n"
            "      path: 'api/tests/**'\n"
            "      reason: asserts\n",
            encoding="utf-8",
        )
        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            resolve_workspace(workspace)
        assert "ruleId" in str(excinfo.value)


class TestStoredResults:
    """A results file that holds such a key still loads, and the entry is inert."""

    FIXTURE = (
        Path(__file__).resolve().parents[2]
        / "test_data"
        / "outputs"
        / "written_before_expiration_checks"
        / "ash_aggregated_results.json"
    )

    def _stored(self):
        data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        data["ash_config"]["global_settings"]["suppressions"] = [
            {"ruleId": "B101", "path": "app.py", "reason": "written by a later version"}
        ]
        data["ash_config"]["global_settings"]["ignore_paths"].append(
            {"path": "build/**", "reason": "generated", "origin": "policy"}
        )
        return json.dumps(data)

    def _load(self):
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
            model = AshAggregatedResults.model_validate_json(self._stored())
        return model, [str(c.args[0]) for c in log.warning.call_args_list]

    def test_a_results_file_from_an_earlier_release_loads(self):
        with patch("automated_security_helper.models.asharp_model.ASH_LOGGER"):
            model = AshAggregatedResults.model_validate_json(
                self.FIXTURE.read_text(encoding="utf-8")
            )
        assert model.ash_config.project_name.startswith("results-written-before")

    def test_loads_keeps_the_keys_and_warns(self):
        """Each kept key warns, naming the entry that holds it but not the key.

        A stored key is the results file's data, like a stored value: it is
        shown as ``<key>``, as a non-schema key on an error's location is.
        """
        model, warnings = self._load()
        (suppression,) = model.ash_config.global_settings.suppressions
        assert suppression.model_extra == {"ruleId": "B101"}
        ignore_paths = model.ash_config.global_settings.ignore_paths
        assert ignore_paths[-1].model_extra == {"origin": "policy"}
        unknown = [w for w in warnings if "unknown key" in w]
        assert len(unknown) == 2, warnings
        assert any(
            "unknown key <key> in 'global_settings.suppressions[0]'" in w
            for w in unknown
        ), warnings
        assert any(
            "unknown key <key> in 'global_settings.ignore_paths[1]'" in w
            for w in unknown
        ), warnings
        for warning in warnings:
            assert "ruleId" not in warning, warning
            assert "origin" not in warning, warning

    def test_a_stored_key_never_reaches_the_log(self):
        """A canary key, and one holding ESC and a workflow command, are kept
        as written and appear in no logger call."""
        canary = "wJalrXUtnFEMIK7MDENG-key-canary"
        for key in (canary, canary + "\x1b[31m\n::error title=x::" + canary):
            data = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
            data["ash_config"]["global_settings"]["suppressions"] = [
                {"rule_id": "B101", "path": "app.py", "reason": "r", key: "v"}
            ]
            data["ash_config"]["scanners"]["bandit"]["options"][key] = "v"
            with patch(
                "automated_security_helper.models.asharp_model.ASH_LOGGER"
            ) as log:
                model = AshAggregatedResults.model_validate(data)
            assert model.ash_config.global_settings.suppressions[0].model_extra == {
                key: "v"
            }
            assert model.ash_config.scanners.bandit.options.model_extra == {key: "v"}
            logged = " ".join(
                str(arg)
                for call in log.method_calls
                for arg in (*call.args, *call.kwargs.values())
            )
            assert canary not in logged, logged
            assert "\x1b" not in logged and "\n::" not in logged, repr(logged)
            assert "'global_settings.suppressions[0]'" in logged, logged
            assert "'scanners.bandit.options'" in logged, logged

    def test_a_key_the_walk_cannot_locate_still_warns(self, monkeypatch):
        """Should the kept keys found in the loaded config not match the count
        the load recorded, each still warns, without a location or the key."""
        from automated_security_helper.models import asharp_model

        monkeypatch.setattr(asharp_model, "_kept_unknown_keys", lambda config: [])
        _, warnings = self._load()
        unknown = [w for w in warnings if "unknown key" in w]
        assert len(unknown) == 2, warnings
        for warning in warnings:
            assert "ruleId" not in warning, warning
            assert "origin" not in warning, warning

    def test_an_entry_with_an_unknown_key_never_applies(self):
        model, _ = self._load()
        (suppression,) = model.ash_config.global_settings.suppressions
        suppressed, _ = should_suppress_finding(_finding("B602"), [suppression])
        assert not suppressed
        assert not suppression.matches(_finding("B101"))
        build = model.ash_config.global_settings.ignore_paths[-1]
        assert build not in active_ignore_paths([build])

    def test_a_location_shows_a_mapping_key_as_key(self):
        """A stored warning's location names schema fields only. No kept key or
        date in today's schema sits under a mapping key, so this is checked on
        the formatter both readers use."""
        from automated_security_helper.config.config_validator import (
            _schema_names,
            location_text,
        )

        loc = ("scanners", "wJalrXUtnFEMIK7MDENG-plugin", "options", 0, "path")
        assert location_text(loc, _schema_names()) == "scanners.<key>.options[0].path"
        # A live config's error is the operator's own file: every part is named.
        assert location_text(loc) == (
            "scanners.wJalrXUtnFEMIK7MDENG-plugin.options[0].path"
        )

    def test_a_config_file_with_the_same_keys_is_refused(self):
        data = json.loads(self._stored())["ash_config"]
        with pytest.raises(ValidationError):
            AshConfig.model_validate(data)
